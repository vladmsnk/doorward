package pdp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/persistence/sql"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

const (
	payments  = "https://payments.example.internal"
	ledger    = "https://ledger.example.internal/mcp"
	pepToken  = "pep-token-0123456789abcdef"
	aliceCnsn = "cns_01JBXR4Q8M2P4R6T8V0X2Z4B6D"
)

// The example consent was given at 09:29:45 on 30 October 2026; the box's
// clock stands an hour later.
var now = time.Date(2026, 10, 30, 10, 30, 0, 0, time.UTC)

type box struct {
	t        testing.TB
	st       *sql.Persister
	v        *schema.Validator
	signer   *jwk.Signer
	srv      *httptest.Server
	journal  *syncBuffer
	follower *journal.Follower
	pdp      *pdp.PDP
}

// exported drains the journal follower and returns the file so far.
func (b *box) exported() string {
	b.t.Helper()
	if err := b.follower.Drain(context.Background()); err != nil {
		b.t.Fatal(err)
	}
	return b.journal.String()
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newBox(t testing.TB, opts ...func(*pdp.PDP)) *box {
	t.Helper()
	dsn := os.Getenv("DOORWARD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("DOORWARD_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	st, err := sql.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.Pool().Exec(ctx, "TRUNCATE documents, consents, grants, decisions, approvals, counters, signing_keys, secrets"); err != nil {
		t.Fatal(err)
	}
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"manifest-payments-api.yaml", "manifest-ledger-mcp.yaml", "mandate-invoices.yaml", "mandate-reconcile.yaml",
		"agent-invoice-assistant.yaml", "agent-reconciler.yaml"} {
		data, err := os.ReadFile(filepath.Join("../../examples/v0/config", f))
		if err != nil {
			t.Fatal(err)
		}
		src, err := schema.Read(f, data, "")
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Metadata struct{ Name string } `json:"metadata"`
		}
		_ = json.Unmarshal(src[0].JSON, &meta)
		if _, err := st.Documents().Put(ctx, string(src[0].Kind), meta.Metadata.Name, src[0].JSON, "test"); err != nil {
			t.Fatal(err)
		}
	}
	consent := load[v0.Consent](t, v, "consent/alice-invoice-assistant.json", schema.Consent)
	if err := st.Consents().Create(ctx, consent); err != nil {
		t.Fatal(err)
	}
	mk, _ := sealer.Generate()
	sl, _ := sealer.Parse(mk)
	km := jwk.NewKeyRing(st.Keys(), sl)
	signer, err := km.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	b := &box{t: t, st: st, v: v, signer: signer, journal: &syncBuffer{}}
	b.follower = journal.New(st.Decisions(), b.journal, 0, 10*time.Millisecond, nil)
	fctx, fcancel := context.WithCancel(ctx)
	go b.follower.Run(fctx)
	t.Cleanup(fcancel)
	cfg := &configuration.Cache{Store: st, Validator: v}
	p := &pdp.PDP{
		Store:    st,
		Config:   cfg,
		Verifier: &grant.Verifier{Keys: km, Status: grant.StoreStatus{Store: st, Config: pdp.StatusConfig(cfg), Now: clock}, Validator: v, Now: clock},
		ID:       "doorward-test", Version: "test",
		Journal: b.follower, Now: clock,
	}
	for _, o := range opts {
		o(p)
	}
	b.pdp = p
	b.srv = httptest.NewServer(p.Handler([]pdp.Client{{Token: pepToken, PEP: v0.PEP{ID: "gateway-1", Kind: v0.PEPGateway}}}))
	t.Cleanup(b.srv.Close)
	return b
}

func load[T schema.Document](t testing.TB, v *schema.Validator, rel string, kind schema.Kind) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../examples/v0", rel))
	if err != nil {
		t.Fatal(err)
	}
	src, err := schema.Read(rel, data, kind)
	if err != nil {
		t.Fatal(err)
	}
	out, err := schema.Decode[T](v, src[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// mint issues and records a grant from an example, valid from the box's
// clock; bound, when set, makes it single-use for that call.
func (b *box) mint(rel, id string, bound *v0.ApprovedAction, edits ...func(*v0.Grant)) string {
	b.t.Helper()
	g := load[v0.Grant](b.t, b.v, rel, schema.Grant)
	for _, e := range edits {
		e(&g)
	}
	g.ID, g.IssuedAt, g.Expiry = id, now.Add(-time.Minute).Unix(), now.Add(14*time.Minute).Unix()
	rec := grant.Record{Grant: g, Agent: g.Actor.Subject}
	if bound != nil {
		h, err := bound.Hash()
		if err != nil {
			b.t.Fatal(err)
		}
		rec.SingleUse, rec.ActionHash = true, h
	}
	if err := b.st.Grants().Create(context.Background(), rec); err != nil {
		b.t.Fatal(err)
	}
	tok, err := grant.Sign(b.signer, g)
	if err != nil {
		b.t.Fatal(err)
	}
	return tok
}

type answer struct {
	status int
	resp   pdp.Response
	raw    string
}

func (b *box) ask(token, auth, resource, action string, args map[string]any, header map[string]string) answer {
	b.t.Helper()
	req := map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "invoice-assistant"},
		"action":   map[string]any{"name": action},
		"resource": map[string]any{"type": "tool_call", "id": resource, "properties": map[string]any{"arguments": args}},
	}
	if token != "" {
		req["context"] = map[string]any{"token": token}
	}
	body, _ := json.Marshal(req)
	return b.post(body, auth, header)
}

func (b *box) post(body []byte, auth string, header map[string]string) answer {
	b.t.Helper()
	r, _ := http.NewRequest(http.MethodPost, b.srv.URL+pdp.EvaluationPath, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(res.Body)
	var a answer
	a.status, a.raw = res.StatusCode, buf.String()
	_ = json.Unmarshal(buf.Bytes(), &a.resp)
	return a
}

func (b *box) record(id string) v0.Decision {
	b.t.Helper()
	d, err := b.st.Decisions().Get(context.Background(), id)
	if err != nil {
		b.t.Fatal(err)
	}
	return d
}

func checks(d v0.Decision) string {
	var s []string
	for _, c := range d.Checks {
		s = append(s, string(c.Name)+":"+string(c.Result))
	}
	return strings.Join(s, " ")
}

func pay(amount float64) map[string]any {
	return map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": amount, "currency": "EUR"}
}

func TestEvaluate(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice := b.mint("grant/pay-invoice.json", "grt_alice_standing_0000001", nil)

	// A read: allowed, one call drawn, the record complete.
	a := b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "inv_7Q2M9X4K"},
		map[string]string{"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
	if a.status != 200 || !a.resp.Decision || a.resp.Context.Outcome != v0.OutcomeAllow {
		t.Fatalf("read: %d %s", a.status, a.raw)
	}
	d := b.record(a.resp.Context.ID)
	if got := checks(d); got != "request:pass signature:pass status:pass pop:skip audience:pass time:pass subset:pass sensitivity:pass policy:skip limits:pass" {
		t.Errorf("read checks: %s", got)
	}
	if d.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || d.Principal.User != "alice@example.com" || d.Grant.Consent != aliceCnsn {
		t.Errorf("read record: %+v %+v %+v", d.TraceID, d.Principal, d.Grant)
	}
	if d.Request.Context["grant"] != "grt_alice_standing_0000001" || d.Request.Context["token"] != nil {
		t.Errorf("the record must name the grant and never hold the token: %v", d.Request.Context)
	}
	mandateDoc, _ := b.st.Documents().Current(ctx, v0.KindMandate, "invoices")
	if d.Versions == nil || d.Versions.Mandate != mandateDoc.Digest || d.Versions.Manifest == "" {
		t.Errorf("versions: %+v", d.Versions)
	}
	if len(d.Limits) != 1 || d.Limits[0] != (v0.LimitUse{Name: "calls", Consumed: 1, Remaining: 49}) {
		t.Errorf("read limits: %+v", d.Limits)
	}

	// Over the grant: denied at subset, the rest skipped, nothing drawn.
	a = b.ask(alice, pepToken, payments, "pay_invoice", pay(7500), nil)
	if a.resp.Decision || a.resp.Context.Outcome != v0.OutcomeDeny || a.resp.Context.Reasons[0].Message != "7500 is above the grant's max of 5000" {
		t.Fatalf("7,500 EUR: %s", a.raw)
	}
	if got := checks(b.record(a.resp.Context.ID)); got != "request:pass signature:pass status:pass pop:skip audience:pass time:pass subset:fail sensitivity:skip policy:skip limits:skip" {
		t.Errorf("deny checks: %s", got)
	}

	// Critical on the standing grant: held, with an approval request that
	// a retry of the same call reuses.
	a = b.ask(alice, pepToken, payments, "pay_invoice", pay(1200), nil)
	if a.resp.Decision || a.resp.Context.Outcome != v0.OutcomeApprovalRequired || a.resp.Context.Approval == nil {
		t.Fatalf("1,200 EUR: %s", a.raw)
	}
	held := a.resp.Context.Approval.Request
	ap, err := b.st.Approvals().Get(ctx, held)
	if err != nil || ap.Status != v0.ApprovalPending || ap.Route.Kind != v0.ApproverUser || ap.Required != 1 ||
		ap.ActionHash != a.resp.Context.ActionHash || ap.PolicyVersion != mandateDoc.Digest {
		t.Fatalf("approval request: %+v %v", ap, err)
	}
	if again := b.ask(alice, pepToken, payments, "pay_invoice", map[string]any{"currency": "EUR", "amount": 1200.0, "invoice_id": "inv_7Q2M9X4K"}, nil); again.resp.Context.Approval == nil || again.resp.Context.Approval.Request != held {
		t.Errorf("the retry opened another request: %s", again.raw)
	}

	// Once approved, the single-use grant runs that call once.
	once := b.mint("grant/pay-invoice.json", "grt_alice_single_use_00001",
		&v0.ApprovedAction{Name: "pay_invoice", Location: payments, Arguments: pay(1200)})
	a = b.ask(once, pepToken, payments, "pay_invoice", pay(1200), nil)
	if !a.resp.Decision || len(a.resp.Context.Limits) != 2 || a.resp.Context.Limits[0] != (v0.LimitUse{Name: "payout-month", Consumed: 1200, Remaining: 3800}) {
		t.Fatalf("the approved call: %s", a.raw)
	}
	a = b.ask(once, pepToken, payments, "pay_invoice", pay(1200), nil)
	if a.resp.Decision || a.resp.Context.Reasons[0].Code != v0.ReasonGrantRevoked || !strings.Contains(a.resp.Context.Reasons[0].Message, "was used at") {
		t.Errorf("the approved call again: %s", a.raw)
	}

	// The reconciler acts for itself: its owner answers for it.
	rec := b.mint("grant/reconcile.json", "grt_reconciler_000000000001", nil)
	a = b.ask(rec, pepToken, ledger, "post_entry", map[string]any{"account_id": "acc_EU_448120", "amount": 240.5, "memo": "m"}, nil)
	if !a.resp.Decision {
		t.Fatalf("reconciler: %s", a.raw)
	}
	if p := b.record(a.resp.Context.ID).Principal; p.Owner != "finance-platform" || p.User != "" {
		t.Errorf("reconciler principal: %+v", p)
	}

	// No grant, and a request the box cannot decide on: recorded refusals.
	a = b.ask("", pepToken, payments, "get_invoice", nil, nil)
	if a.resp.Decision || a.resp.Context.Reasons[0].Code != v0.ReasonGrantMissing {
		t.Errorf("no grant: %s", a.raw)
	}
	a = b.ask(alice, pepToken, "payments", "get_invoice", nil, nil)
	if a.resp.Decision || a.resp.Context.Reasons[0].Code != v0.ReasonRequestMalformed || checks(b.record(a.resp.Context.ID))[:12] != "request:fail" {
		t.Errorf("malformed: %s", a.raw)
	}

	// Who may ask, and what is not a request at all: no record.
	if a := b.ask(alice, "", payments, "get_invoice", nil, nil); a.status != 401 {
		t.Errorf("no PEP token: %d", a.status)
	}
	if a := b.ask(alice, "wrong-token-0123456789", payments, "get_invoice", nil, nil); a.status != 401 {
		t.Errorf("wrong PEP token: %d", a.status)
	}
	for _, body := range []string{`{"subject":{"type":"agent","id":"x"}}`, `{"subject":{"type":"a","id":"x"},"action":{"name":"a"},"resource":{"type":"tool_call","id":"https://x"},"extra":1}`, `{"a":1,"a":2}`} {
		if a := b.post([]byte(body), pepToken, nil); a.status != 400 {
			t.Errorf("%s: %d %s", body, a.status, a.raw)
		}
	}

	// Every record is valid under the contract, and the journal, read back
	// from the store and from the export, is one unbroken chain.
	head, err := b.st.Decisions().Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	all, err := b.st.Decisions().Range(ctx, 0, head.Chain.Seq+1)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range all {
		doc, _ := json.Marshal(d)
		if _, err := schema.Decode[v0.Decision](b.v, doc); err != nil {
			t.Errorf("record %s is not valid: %v", d.ID, err)
		}
	}
	if broken, err := v0.Verify(all); broken != -1 || err != nil {
		t.Errorf("stored chain broken at %d: %v", broken, err)
	}
	var exported []v0.Decision
	for _, line := range strings.Split(strings.TrimSpace(b.exported()), "\n") {
		var d v0.Decision
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			t.Fatal(err)
		}
		exported = append(exported, d)
	}
	if len(exported) != len(all) {
		t.Errorf("exported %d records, stored %d", len(exported), len(all))
	}
	if broken, err := v0.Verify(exported); broken != -1 || err != nil {
		t.Errorf("exported chain broken at %d: %v", broken, err)
	}

	// A verifier that shares no code with doorward agrees: the chain is
	// RFC 8785, not an accident of Go's JSON encoder. One changed value
	// anywhere breaks it.
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Log("python3 not found; skipping the independent verifier")
		return
	}
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	file := b.exported()
	if err := os.WriteFile(journal, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, "../../scripts/verify-journal.py", journal).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "chain intact") {
		t.Fatalf("independent verifier: %v\n%s", err, out)
	}
	tampered := strings.Replace(file, `"remaining":3800`, `"remaining":9800`, 1)
	if tampered == file {
		t.Fatal("nothing to tamper with")
	}
	if err := os.WriteFile(journal, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(python, "../../scripts/verify-journal.py", journal).CombinedOutput(); err == nil || !strings.Contains(string(out), "hash does not match") {
		t.Errorf("independent verifier accepted a tampered journal: %v\n%s", err, out)
	}
}

// 60 parallel reads against a grant allowed 50 calls: exactly 50 allowed,
// 10 refused for the budget, 60 records in one chain.
func TestEvaluateUnderLoad(t *testing.T) {
	b := newBox(t)
	alice := b.mint("grant/pay-invoice.json", "grt_alice_load_00000000001", nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	outcomes := map[string]int{}
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "inv_1"}, nil)
			key := string(a.resp.Context.Outcome)
			if len(a.resp.Context.Reasons) > 0 {
				key += ":" + string(a.resp.Context.Reasons[0].Code)
			}
			mu.Lock()
			outcomes[key]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if outcomes["allow"] != 50 || outcomes["deny:limit_exceeded"] != 10 {
		t.Errorf("outcomes: %v", outcomes)
	}
	all, _ := b.st.Decisions().Range(context.Background(), 0, 1000)
	if broken, err := v0.Verify(all); len(all) != 60 || broken != -1 || err != nil {
		t.Errorf("%d records, chain broken at %d: %v", len(all), broken, err)
	}
}

// Each evaluation is one span that continues the caller's trace, and the
// record carries the same trace ID.
func TestEvaluationSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	b := newBox(t, func(p *pdp.PDP) { p.Tracer = tp.Tracer("test") })
	alice := b.mint("grant/pay-invoice.json", "grt_alice_traced_000000001", nil)
	a := b.ask(alice, pepToken, payments, "pay_invoice", pay(7500),
		map[string]string{"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"})
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("%d spans", len(spans))
	}
	sp := spans[0]
	if sp.Name != "doorward.evaluation" || sp.SpanContext.TraceID().String() != "0af7651916cd43dd8448eb211c80319c" || sp.Parent.SpanID().String() != "b7ad6b7169203331" {
		t.Errorf("span %s in trace %s under %s", sp.Name, sp.SpanContext.TraceID(), sp.Parent.SpanID())
	}
	attrs := map[string]string{}
	for _, kv := range sp.Attributes {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	if attrs["doorward.outcome"] != "deny" || attrs["doorward.reason"] != "constraint_violated" || attrs["doorward.agent"] != "invoice-assistant" || attrs["doorward.decision.id"] != a.resp.Context.ID {
		t.Errorf("attributes: %v", attrs)
	}
	if d := b.record(a.resp.Context.ID); d.TraceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("record trace_id %s", d.TraceID)
	}
	// Without a caller's trace, the span starts one, and the record names it.
	a = b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "i"}, nil)
	if got := exp.GetSpans()[1].SpanContext.TraceID().String(); b.record(a.resp.Context.ID).TraceID != got {
		t.Errorf("record trace_id %s, span trace %s", b.record(a.resp.Context.ID).TraceID, got)
	}
}

// BenchmarkEvaluate measures one allowed decision end to end: HTTP, the
// grant's checks, the call's checks, a budget drawn and the record appended
// to the chain, against PostgreSQL.
func BenchmarkEvaluate(b *testing.B) {
	bx := newBox(b)
	tok := bx.mint("grant/pay-invoice.json", "grt_alice_bench_0000000001", nil, func(g *v0.Grant) {
		g.Limits = []v0.Limit{{Name: "calls", Kind: v0.LimitCount, Max: 1e9}}
	})
	args := map[string]any{"invoice_id": "inv_7Q2M9X4K"}
	b.ResetTimer()
	for b.Loop() {
		if a := bx.ask(tok, pepToken, payments, "get_invoice", args, nil); !a.resp.Decision {
			b.Fatal(a.raw)
		}
	}
}

// BenchmarkEvaluateParallel measures throughput with several points of
// enforcement asking at once; appends to the chain are serialized.
func BenchmarkEvaluateParallel(b *testing.B) {
	bx := newBox(b)
	tok := bx.mint("grant/pay-invoice.json", "grt_alice_bench_0000000002", nil, func(g *v0.Grant) {
		g.Limits = []v0.Limit{{Name: "calls", Kind: v0.LimitCount, Max: 1e9}}
	})
	args := map[string]any{"invoice_id": "inv_7Q2M9X4K"}
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if a := bx.ask(tok, pepToken, payments, "get_invoice", args, nil); !a.resp.Decision {
				b.Error(a.raw)
				return
			}
		}
	})
}

// putDoc stores a new version of a configuration document, changed by edit.
// It writes to the store directly: the Admin API's rules are tested on
// their own.
func (b *box) putDoc(kind, name string, edit func(spec map[string]any)) {
	b.t.Helper()
	ctx := context.Background()
	cur, err := b.st.Documents().Current(ctx, kind, name)
	if err != nil {
		b.t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(cur.Doc, &doc); err != nil {
		b.t.Fatal(err)
	}
	edit(doc["spec"].(map[string]any))
	data, _ := json.Marshal(doc)
	if _, err := b.st.Documents().Put(ctx, kind, name, data, "test"); err != nil {
		b.t.Fatal(err)
	}
}

// B6: observe mode lets the mandate's own rules be tried without stopping
// calls, and enforces everything else.
func TestObserveMode(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	b.putDoc(v0.KindMandate, "invoices", func(spec map[string]any) { spec["enforcement"] = "observe" })
	alice := b.mint("grant/pay-invoice.json", "grt_alice_observed_0000001", nil, func(g *v0.Grant) {
		for i := range g.Limits {
			if g.Limits[i].Name == "calls" {
				g.Limits[i].Max = 2
			}
		}
	})
	observedReason := func(a answer) v0.ReasonCode {
		if a.resp.Context.Observed == nil {
			return ""
		}
		return a.resp.Context.Observed.Reasons[0].Code
	}

	// An operation the grant does not name runs, and the record says
	// enforcement would have refused it.
	a := b.ask(alice, pepToken, payments, "refund_payment", map[string]any{"payment_id": "pmt_1", "amount": 10.0}, nil)
	if !a.resp.Decision || a.resp.Context.Enforcement != v0.EnforcementObserve || observedReason(a) != v0.ReasonActionNotGranted {
		t.Fatalf("observed refund: %s", a.raw)
	}
	if got := checks(b.record(a.resp.Context.ID)); got != "request:pass signature:pass status:pass pop:skip audience:pass time:pass subset:fail sensitivity:pass policy:skip limits:pass" {
		t.Errorf("observed refund checks: %s", got)
	}

	// Over the budget: the call runs, the full budget stays at its max.
	b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "i"}, nil)
	a = b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "i"}, nil)
	if !a.resp.Decision || observedReason(a) != v0.ReasonLimitExceeded {
		t.Fatalf("observed over budget: %s", a.raw)
	}
	if v, _ := b.st.Counters().Consumed(ctx, "grant:grt_alice_observed_0000001:calls"); v != "2" {
		t.Errorf("the calls budget holds %s, want its max of 2", v)
	}

	// Critical calls still wait for a person, observed or not; an amount
	// over the grant is noted as well.
	a = b.ask(alice, pepToken, payments, "pay_invoice", pay(1200), nil)
	if a.resp.Context.Outcome != v0.OutcomeApprovalRequired || a.resp.Context.Observed != nil {
		t.Errorf("observed 1,200 EUR: %s", a.raw)
	}
	a = b.ask(alice, pepToken, payments, "pay_invoice", pay(7500), nil)
	if a.resp.Context.Outcome != v0.OutcomeApprovalRequired || observedReason(a) != v0.ReasonConstraintViolated {
		t.Errorf("observed 7,500 EUR: %s", a.raw)
	}

	// What observe mode never lets through: an operation the manifest does
	// not declare, a call without a valid grant, a tier above the agent's
	// ceiling.
	a = b.ask(alice, pepToken, payments, "delete_everything", nil, nil)
	if a.resp.Decision || a.resp.Context.Reasons[0].Code != v0.ReasonActionNotGranted || a.resp.Context.Observed != nil {
		t.Errorf("undeclared operation: %s", a.raw)
	}
	if a := b.ask("", pepToken, payments, "get_invoice", nil, nil); a.resp.Decision {
		t.Errorf("no grant: %s", a.raw)
	}
	b.putDoc(v0.KindAgent, "invoice-assistant", func(spec map[string]any) { spec["max_sensitivity"] = "read" })
	a = b.ask(alice, pepToken, payments, "refund_payment", map[string]any{"payment_id": "pmt_1", "amount": 10.0}, nil)
	if a.resp.Decision || a.resp.Context.Reasons[0].Code != v0.ReasonSensitivityExceeded {
		t.Errorf("above the agent's ceiling: %s", a.raw)
	}

	// Observe mode on the agent: the reconciler writes off more than its
	// grant allows, and it runs.
	b.putDoc(v0.KindAgent, "reconciler", func(spec map[string]any) { spec["enforcement"] = "observe" })
	rec := b.mint("grant/reconcile.json", "grt_reconciler_observed_01", nil)
	a = b.ask(rec, pepToken, ledger, "post_entry", map[string]any{"account_id": "acc_1", "amount": 5000.0, "memo": "m"}, nil)
	if !a.resp.Decision || observedReason(a) != v0.ReasonConstraintViolated {
		t.Errorf("observed reconciler: %s", a.raw)
	}

	// Every record is valid under the contract.
	all, err := b.st.Decisions().Range(ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range all {
		doc, _ := json.Marshal(d)
		if _, err := schema.Decode[v0.Decision](b.v, doc); err != nil {
			t.Errorf("record %s (%s): %v", d.ID, d.Outcome, err)
		}
	}
	if broken, err := v0.Verify(all); broken != -1 || err != nil {
		t.Errorf("chain broken at %d: %v", broken, err)
	}
}

// Q1: while the journal is held, decisions are refused within the deadline
// with 503, and nothing is drawn or recorded. Once it is free, they flow.
func TestDecisionDeadline(t *testing.T) {
	b := newBox(t, func(p *pdp.PDP) { p.Timeout = 300 * time.Millisecond })
	ctx := context.Background()
	alice := b.mint("grant/pay-invoice.json", "grt_alice_deadline_000001", nil)
	conn, err := b.st.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", sql.ChainLock); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a := b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "i"}, nil)
	took := time.Since(start)
	if a.status != 503 || a.resp.Decision || !strings.Contains(a.resp.Context.Error, "ran out of time") {
		t.Fatalf("held journal: %d %s", a.status, a.raw)
	}
	if took > 2*time.Second {
		t.Errorf("answer took %s on a 300ms deadline", took)
	}
	_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", sql.ChainLock)
	conn.Release()
	if v, _ := b.st.Counters().Consumed(ctx, "grant:grt_alice_deadline_000001:calls"); v != "0" {
		t.Errorf("the refused call drew %s", v)
	}
	if _, err := b.st.Decisions().Head(ctx); !errors.Is(err, x.ErrNotFound) {
		t.Errorf("the refused call was recorded: %v", err)
	}
	if a := b.ask(alice, pepToken, payments, "get_invoice", map[string]any{"invoice_id": "i"}, nil); !a.resp.Decision {
		t.Errorf("after release: %s", a.raw)
	}
}

// Q2: the journal file is a complete, ordered copy of the chain. It
// contains records another instance committed, and a follower started on
// an existing file continues where it ended.
func TestJournalFollowsEveryInstance(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice := b.mint("grant/pay-invoice.json", "grt_alice_follow_000000001", nil)
	read := map[string]any{"invoice_id": "i"}
	b.ask(alice, pepToken, payments, "get_invoice", read, nil)

	// A second instance on the same store, with no follower of its own.
	other := &pdp.PDP{Store: b.st, Config: b.pdp.Config, Verifier: b.pdp.Verifier, ID: "doorward-other", Version: "test", Now: b.pdp.Now}
	srv := httptest.NewServer(other.Handler([]pdp.Client{{Token: pepToken, PEP: v0.PEP{ID: "gateway-2", Kind: v0.PEPGateway}}}))
	defer srv.Close()
	for i := 0; i < 3; i++ {
		body, _ := json.Marshal(map[string]any{
			"subject": map[string]any{"type": "agent", "id": "invoice-assistant"}, "action": map[string]any{"name": "get_invoice"},
			"resource": map[string]any{"type": "tool_call", "id": payments, "properties": map[string]any{"arguments": read}},
			"context":  map[string]any{"token": alice}})
		r, _ := http.NewRequest(http.MethodPost, srv.URL+pdp.EvaluationPath, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+pepToken)
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
	}
	b.ask(alice, pepToken, payments, "get_invoice", read, nil)

	lines := strings.Split(strings.TrimSpace(b.exported()), "\n")
	if len(lines) != 5 {
		t.Fatalf("the file has %d records, the chain 5", len(lines))
	}
	var seqs []uint64
	peps := map[string]int{}
	for _, l := range lines {
		var d v0.Decision
		if err := json.Unmarshal([]byte(l), &d); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, d.Chain.Seq)
		peps[d.PEP.ID]++
	}
	if fmt.Sprint(seqs) != "[0 1 2 3 4]" || peps["gateway-2"] != 3 {
		t.Errorf("seqs %v, by gateway %v", seqs, peps)
	}

	// Resume: a new follower over the same file writes only what follows.
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:3], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	from, err := journal.Resume(f)
	if err != nil || from != 3 {
		t.Fatalf("Resume: %d %v", from, err)
	}
	resumed := journal.New(b.st.Decisions(), f, from, time.Hour, nil)
	if err := resumed.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if got := strings.Split(strings.TrimSpace(string(data)), "\n"); len(got) != 5 || got[4] != lines[4] {
		t.Errorf("resumed file has %d lines; last matches: %v", len(got), len(got) == 5 && got[4] == lines[4])
	}
	// An empty file starts from 0; a file with junk is refused.
	empty, _ := os.CreateTemp(t.TempDir(), "e")
	if from, err := journal.Resume(empty); err != nil || from != 0 {
		t.Errorf("empty: %d %v", from, err)
	}
	junk, _ := os.CreateTemp(t.TempDir(), "j")
	_, _ = junk.WriteString("not json\n")
	if _, err := journal.Resume(junk); err == nil {
		t.Error("junk accepted")
	}
}

// Q3: fifty first attempts of one held call, at once, open one approval
// request, and every answer names it.
func TestOneApprovalPerCallUnderContention(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice := b.mint("grant/pay-invoice.json", "grt_alice_contend_00000001", nil)
	args := map[string]any{"invoice_id": "inv_contended", "amount": 1500.0, "currency": "EUR"}
	var wg sync.WaitGroup
	var mu sync.Mutex
	requests := map[string]int{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := b.ask(alice, pepToken, payments, "pay_invoice", args, nil)
			mu.Lock()
			defer mu.Unlock()
			if a.resp.Context.Outcome != v0.OutcomeApprovalRequired || a.resp.Context.Approval == nil {
				requests["not held: "+a.raw]++
				return
			}
			requests[a.resp.Context.Approval.Request]++
		}()
	}
	wg.Wait()
	if len(requests) != 1 {
		t.Errorf("answers name %d different requests: %v", len(requests), requests)
	}
	pending, err := b.st.Approvals().Pending(ctx)
	if err != nil || len(pending) != 1 {
		t.Errorf("%d pending requests, want 1 (%v)", len(pending), err)
	}
}

// Q5: configuration is read once per change. A document this version
// cannot read fails closed for the calls that depend on it, and no other.
func TestConfigurationSnapshot(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice := b.mint("grant/pay-invoice.json", "grt_alice_snapshot_000001", nil)
	rec := b.mint("grant/reconcile.json", "grt_reconciler_snapshot_01", nil)
	read := map[string]any{"invoice_id": "i"}

	v1, _ := b.st.ConfigVersion(ctx)
	snap, err := b.pdp.Config.Current(ctx)
	if err != nil || snap.Version != v1 {
		t.Fatalf("snapshot %v %v, version %d", snap, err, v1)
	}
	if again, _ := b.pdp.Config.Current(ctx); again != snap {
		t.Error("the snapshot was reloaded although nothing changed")
	}
	// A change bumps the version and takes effect on the next call.
	b.putDoc(v0.KindMandate, "invoices", func(spec map[string]any) { spec["enforcement"] = "observe" })
	if v2, _ := b.st.ConfigVersion(ctx); v2 != v1+1 {
		t.Errorf("version %d after one write, want %d", v2, v1+1)
	}
	if a := b.ask(alice, pepToken, payments, "refund_payment", map[string]any{"payment_id": "p", "amount": 1.0}, nil); !a.resp.Decision {
		t.Errorf("the change did not take effect: %s", a.raw)
	}
	if again, _ := b.pdp.Config.Current(ctx); again == snap {
		t.Error("the snapshot was not reloaded after a change")
	}

	// A mandate from a newer doorward, with a field this version does not
	// know, written straight to the store: calls under it are refused, the
	// reconciler's are not.
	cur, _ := b.st.Documents().Current(ctx, v0.KindMandate, "invoices")
	newer := strings.Replace(string(cur.Doc), `"principal":"user"`, `"principal":"user","future_field":true`, 1)
	if newer == string(cur.Doc) {
		t.Fatal("the mandate changed shape")
	}
	if _, err := b.st.Documents().Put(ctx, v0.KindMandate, "invoices", []byte(newer), "a newer doorward"); err != nil {
		t.Fatal(err)
	}
	// The refusal is recorded, with internal_error as its reason.
	if a := b.ask(alice, pepToken, payments, "get_invoice", read, nil); a.resp.Decision || a.resp.Context.Outcome != v0.OutcomeDeny || a.resp.Context.Reasons[0].Code != v0.ReasonInternalError {
		t.Errorf("a call under an unreadable mandate: %d %s", a.status, a.raw)
	}
	if a := b.ask(rec, pepToken, ledger, "list_unmatched", map[string]any{"day": "2026-11-01"}, nil); !a.resp.Decision {
		t.Errorf("the reconciler, under another mandate: %s", a.raw)
	}
	// Repairing the document restores service.
	if _, err := b.st.Documents().Put(ctx, v0.KindMandate, "invoices", cur.Doc, "test"); err != nil {
		t.Fatal(err)
	}
	if a := b.ask(alice, pepToken, payments, "get_invoice", read, nil); !a.resp.Decision {
		t.Errorf("after the repair: %s", a.raw)
	}
}
