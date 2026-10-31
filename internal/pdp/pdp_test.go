package pdp_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/keys"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/internal/store/postgres"
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
	t       testing.TB
	st      *postgres.Store
	v       *schema.Validator
	signer  *keys.Signer
	srv     *httptest.Server
	journal *syncBuffer
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
	st, err := postgres.Open(ctx, dsn)
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
	km := keys.New(st.Keys(), sl)
	signer, err := km.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	b := &box{t: t, st: st, v: v, signer: signer, journal: &syncBuffer{}}
	p := &pdp.PDP{
		Store:    st,
		Verifier: &grant.Verifier{Keys: km, Status: grant.StoreStatus{Store: st, Now: clock}, Validator: v, Now: clock},
		ID:       "doorward-test", Version: "test",
		Journal: b.journal, Now: clock,
	}
	for _, o := range opts {
		o(p)
	}
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
	rec := store.GrantRecord{Grant: g, Agent: g.Actor.Subject}
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
	for _, line := range strings.Split(strings.TrimSpace(b.journal.String()), "\n") {
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
	if err := os.WriteFile(journal, []byte(b.journal.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, "../../scripts/verify-journal.py", journal).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "chain intact") {
		t.Fatalf("independent verifier: %v\n%s", err, out)
	}
	tampered := strings.Replace(b.journal.String(), `"remaining":3800`, `"remaining":9800`, 1)
	if tampered == b.journal.String() {
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
