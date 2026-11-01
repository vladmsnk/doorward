package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/admin"
	"github.com/vladmsnk/doorward/internal/config"
	"github.com/vladmsnk/doorward/internal/demoledger"
	"github.com/vladmsnk/doorward/internal/gateway"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/keys"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/internal/store/postgres"
	"github.com/vladmsnk/doorward/schema"
)

const (
	ledgerAud = "https://ledger.example.internal/mcp"
	apiKey    = "lk_live_example"
	keyRef    = "ledger-mcp-api-key"
	endpoint  = gateway.Prefix + "ledger-mcp"
)

// The box's clock: an hour after the example consent.
var now = time.Date(2026, 10, 30, 10, 30, 0, 0, time.UTC)

// box is a gateway in front of the demo ledger, with a store, a decision
// point and a signer to mint grants with.
type box struct {
	t      testing.TB
	st     *postgres.Store
	v      *schema.Validator
	signer *keys.Signer
	gw     *gateway.Gateway
	srv    *httptest.Server

	// The ledger answers as plain JSON, or as event streams when sse is set.
	ledger, ledgerSSE *demoledger.Server
	sse               atomic.Bool
}

func newBox(t testing.TB) *box {
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
	b := &box{t: t, st: st, v: v}
	b.ledger = &demoledger.Server{APIKey: apiKey}
	b.ledgerSSE = &demoledger.Server{APIKey: apiKey, SSE: true}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.sse.Load() {
			b.ledgerSSE.ServeHTTP(w, r)
			return
		}
		b.ledger.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)

	// The example configuration, with the ledger manifest pointed at the
	// demo server.
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
		doc := src[0].JSON
		if f == "manifest-ledger-mcp.yaml" {
			doc = retarget(t, doc, upstream.URL+"/mcp")
		}
		var meta struct {
			Metadata struct{ Name string } `json:"metadata"`
		}
		_ = json.Unmarshal(doc, &meta)
		if _, err := st.Documents().Put(ctx, string(src[0].Kind), meta.Metadata.Name, doc, "test"); err != nil {
			t.Fatal(err)
		}
	}

	mk, _ := sealer.Generate()
	sl, _ := sealer.Parse(mk)
	sealed, err := sl.Seal([]byte(apiKey), admin.SecretPurpose(keyRef))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Secrets().Put(ctx, keyRef, sealed, "test"); err != nil {
		t.Fatal(err)
	}
	km := keys.New(st.Keys(), sl)
	b.signer, err = km.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	cfg := &config.Cache{Store: st, Validator: v}
	p := &pdp.PDP{
		Store:    st,
		Config:   cfg,
		Verifier: &grant.Verifier{Keys: km, Status: grant.StoreStatus{Store: st, Config: pdp.StatusConfig(cfg), Now: clock}, Validator: v, Now: clock},
		ID:       "doorward-test", Version: "test",
		Now: clock,
	}
	b.gw = &gateway.Gateway{
		Config: cfg, PDP: p, Verifier: p.Verifier, Secrets: st.Secrets(), Sealer: sl,
		ID:  "gateway-test",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	b.srv = httptest.NewServer(b.gw.Handler())
	t.Cleanup(b.srv.Close)
	return b
}

// retarget points a manifest's upstream at url.
func retarget(t testing.TB, doc []byte, url string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	m["spec"].(map[string]any)["upstream"].(map[string]any)["url"] = url
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// mint issues and records the reconciler's grant from the example, valid
// from the box's clock.
func (b *box) mint(id string, edits ...func(*v0.Grant)) string {
	b.t.Helper()
	data, err := os.ReadFile("../../examples/v0/grant/reconcile.json")
	if err != nil {
		b.t.Fatal(err)
	}
	g, err := schema.Decode[v0.Grant](b.v, data)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, e := range edits {
		e(&g)
	}
	g.ID, g.IssuedAt, g.Expiry = id, now.Add(-time.Minute).Unix(), now.Add(14*time.Minute).Unix()
	if err := b.st.Grants().Create(context.Background(), store.GrantRecord{Grant: g, Agent: g.Actor.Subject}); err != nil {
		b.t.Fatal(err)
	}
	tok, err := grant.Sign(b.signer, g)
	if err != nil {
		b.t.Fatal(err)
	}
	return tok
}

// reply is one answer from the gateway, with the JSON-RPC message in it
// parsed from plain JSON or from the event stream.
type reply struct {
	status int
	header http.Header
	body   string
	msg    map[string]any
}

func (r reply) result() map[string]any {
	res, _ := r.msg["result"].(map[string]any)
	return res
}

// toolError returns the text and the doorward _meta of a tool execution
// error, and whether the result is one.
func (r reply) toolError() (string, map[string]any, bool) {
	res := r.result()
	isErr, _ := res["isError"].(bool)
	content, _ := res["content"].([]any)
	text := ""
	if len(content) > 0 {
		c, _ := content[0].(map[string]any)
		text, _ = c["text"].(string)
	}
	meta, _ := res["_meta"].(map[string]any)
	dec, _ := meta[gateway.MetaKey].(map[string]any)
	return text, dec, isErr
}

func (r reply) tools() []string {
	raw, _ := r.result()["tools"].([]any)
	var names []string
	for _, t := range raw {
		m, _ := t.(map[string]any)
		names = append(names, m["name"].(string))
	}
	return names
}

func (b *box) send(method, path, token string, body []byte, header map[string]string) reply {
	b.t.Helper()
	req, err := http.NewRequest(method, b.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	r := reply{status: res.StatusCode, header: res.Header, body: string(raw)}
	switch {
	case strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream"):
		for _, ev := range strings.Split(string(raw), "\n\n") {
			for _, line := range strings.Split(ev, "\n") {
				if data, ok := strings.CutPrefix(line, "data:"); ok && strings.TrimSpace(data) != "" {
					_ = json.Unmarshal([]byte(strings.TrimSpace(data)), &r.msg)
				}
			}
		}
	default:
		_ = json.Unmarshal(raw, &r.msg)
	}
	return r
}

// rpc posts one JSON-RPC message to the ledger's endpoint. A nil id makes
// it a notification.
func (b *box) rpc(token string, id any, method string, params any, header map[string]string) reply {
	b.t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != nil {
		msg["id"] = id
	}
	if params != nil {
		msg["params"] = params
	}
	body, _ := json.Marshal(msg)
	return b.send(http.MethodPost, endpoint, token, body, header)
}

func (b *box) tool(token, name string, args map[string]any) reply {
	b.t.Helper()
	return b.rpc(token, 7, "tools/call", map[string]any{"name": name, "arguments": args}, nil)
}

func (b *box) head() v0.Decision {
	b.t.Helper()
	d, err := b.st.Decisions().Head(context.Background())
	if err != nil {
		b.t.Fatal(err)
	}
	return d
}

func entry(amount float64) map[string]any {
	return map[string]any{"account_id": "acc_EU_448120", "amount": amount, "memo": "pmt_8K2"}
}

func TestGateway(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	rec := b.mint("grt_reconciler_000000000001")

	// Without a grant: a challenge that names the mandate to ask for.
	r := b.rpc("", 1, "tools/list", nil, nil)
	if r.status != 401 || !strings.Contains(r.header.Get("WWW-Authenticate"), `Bearer realm="doorward"`) || !strings.Contains(r.header.Get("WWW-Authenticate"), `scope="reconcile"`) {
		t.Fatalf("no grant: %d %q %s", r.status, r.header.Get("WWW-Authenticate"), r.body)
	}
	if r := b.rpc("not.a.grant", 1, "tools/list", nil, nil); r.status != 401 || !strings.Contains(r.header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("bad grant: %d %q", r.status, r.header.Get("WWW-Authenticate"))
	}

	// The handshake passes through, session header and all; the ledger
	// sees its API key, never the grant.
	r = b.rpc(rec, 1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "0"}}, nil)
	if r.status != 200 || r.result()["protocolVersion"] != "2025-11-25" || r.header.Get("MCP-Session-Id") == "" {
		t.Fatalf("initialize: %d %v %s", r.status, r.header, r.body)
	}
	if r := b.rpc(rec, nil, "notifications/initialized", nil, nil); r.status != 202 {
		t.Errorf("initialized notification: %d %s", r.status, r.body)
	}

	// The tool list is the grant's: export_everything, which no manifest
	// declares, is not there.
	r = b.rpc(rec, 2, "tools/list", nil, nil)
	if got := strings.Join(r.tools(), " "); r.status != 200 || got != "list_unmatched post_entry write_off" {
		t.Fatalf("tools/list: %d %q %s", r.status, got, r.body)
	}
	b.sse.Store(true)
	r = b.rpc(rec, 3, "tools/list", nil, nil)
	if got := strings.Join(r.tools(), " "); !strings.HasPrefix(r.header.Get("Content-Type"), "text/event-stream") || got != "list_unmatched post_entry write_off" {
		t.Fatalf("tools/list over SSE: %d %q %q\n%s", r.status, r.header.Get("Content-Type"), got, r.body)
	}
	if !strings.HasPrefix(r.body, "id: ") || !strings.Contains(r.body, "\ndata: \n\n") || !strings.Contains(r.body, "event: message\n") {
		t.Errorf("the stream's other fields must pass unchanged:\n%s", r.body)
	}
	b.sse.Store(false)

	// A call inside the grant is made, with the ledger's own credential.
	r = b.tool(rec, "post_entry", entry(240.5))
	if text, _, isErr := r.toolError(); r.status != 200 || isErr || !strings.HasPrefix(text, "posted ent_") {
		t.Fatalf("post_entry 240.5: %d %s", r.status, r.body)
	}
	if entries := b.ledger.Entries(); len(entries) != 1 || entries[0].Amount != 240.5 {
		t.Errorf("ledger entries: %+v", entries)
	}
	d := b.head()
	if d.Outcome != v0.OutcomeAllow || d.PEP != (v0.PEP{ID: "gateway-test", Kind: v0.PEPGateway}) || d.Principal.Agent != "reconciler" || d.Request.Action.Name != "post_entry" {
		t.Errorf("record of the allowed call: %+v", d)
	}
	for _, seen := range b.ledger.Requests() {
		if seen.Credential != "api key" {
			t.Errorf("the ledger saw %q on %s", seen.Credential, seen.Method)
		}
	}

	// Over the grant: a tool execution error with the reason, so the model
	// can correct itself; the ledger never hears of it.
	before := len(b.ledger.Requests())
	r = b.tool(rec, "post_entry", entry(5000))
	text, meta, isErr := r.toolError()
	if r.status != 200 || !isErr || !strings.Contains(text, "5000 is above the grant's max of 1000") || meta["outcome"] != "deny" {
		t.Fatalf("post_entry 5000: %d %s", r.status, r.body)
	}
	if id, _ := meta["decision"].(string); id == "" || b.head().ID != id || b.head().Outcome != v0.OutcomeDeny {
		t.Errorf("the refusal is recorded as %v; head is %+v", meta["decision"], b.head())
	}
	if len(b.ledger.Requests()) != before {
		t.Error("a refused call reached the ledger")
	}

	// Critical: held, with the approval request to point a person at.
	r = b.tool(rec, "write_off", map[string]any{"payment_id": "pmt_8K2", "amount": 100.0, "reason": "duplicate"})
	text, meta, isErr = r.toolError()
	if r.status != 200 || !isErr || !strings.Contains(text, "holds this call for approval") || meta["outcome"] != "approval_required" {
		t.Fatalf("write_off: %d %s", r.status, r.body)
	}
	apID, _ := meta["approval"].(string)
	ap, err := b.st.Approvals().Get(ctx, apID)
	if err != nil || ap.Status != v0.ApprovalPending || ap.Required != 2 || ap.Route.Kind != v0.ApproverGroup {
		t.Fatalf("approval request %q: %+v %v", apID, ap, err)
	}
	if !strings.Contains(text, apID) {
		t.Errorf("the text must name the request: %s", text)
	}
	if len(b.ledger.Requests()) != before {
		t.Error("a held call reached the ledger")
	}

	// A tool the grant lacks but a mandate allows: 403 insufficient_scope,
	// naming the mandate, and the list shows only what the grant has.
	narrow := b.mint("grt_reconciler_narrow_00001", func(g *v0.Grant) {
		g.AuthorizationDetails, g.Audience, g.Limits = g.AuthorizationDetails[:1], []string{ledgerAud}, nil
	})
	r = b.tool(narrow, "post_entry", entry(10))
	if r.status != 403 || !strings.Contains(r.header.Get("WWW-Authenticate"), `error="insufficient_scope"`) || !strings.Contains(r.header.Get("WWW-Authenticate"), `scope="reconcile"`) {
		t.Errorf("ungranted tool: %d %q %s", r.status, r.header.Get("WWW-Authenticate"), r.body)
	}
	if r := b.rpc(narrow, 4, "tools/list", nil, nil); strings.Join(r.tools(), " ") != "list_unmatched" {
		t.Errorf("narrow tools/list: %s", r.body)
	}

	// A tool the ledger has but no grant or mandate allows: refused in the
	// protocol, with no scope to ask for.
	r = b.tool(rec, "export_everything", map[string]any{})
	if text, _, isErr := r.toolError(); r.status != 200 || !isErr || !strings.Contains(text, "does not allow export_everything") {
		t.Errorf("undeclared tool: %d %s", r.status, r.body)
	}

	// Malformed calls and batches are protocol errors; a listening stream
	// is the ledger's to refuse.
	if r := b.rpc(rec, 5, "tools/call", map[string]any{"arguments": map[string]any{}}, nil); r.status != 200 || r.msg["error"] == nil {
		t.Errorf("tools/call without a name: %d %s", r.status, r.body)
	}
	if r := b.send(http.MethodPost, endpoint, rec, []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`), nil); r.status != 400 || !strings.Contains(r.body, "-32600") {
		t.Errorf("batch: %d %s", r.status, r.body)
	}
	if r := b.send(http.MethodGet, endpoint, rec, nil, nil); r.status != 405 || !strings.Contains(r.body, "keeps no sessions") {
		t.Errorf("GET: %d %s", r.status, r.body)
	}

	// Origins: the gateway's own host and the configured ones; no other.
	host := strings.TrimPrefix(b.srv.URL, "http://")
	if r := b.rpc(rec, 6, "ping", nil, map[string]string{"Origin": "http://" + host}); r.status != 200 {
		t.Errorf("own origin: %d %s", r.status, r.body)
	}
	if r := b.rpc(rec, 6, "ping", nil, map[string]string{"Origin": "https://evil.example"}); r.status != 403 {
		t.Errorf("foreign origin: %d %s", r.status, r.body)
	}
	b.gw.Origins = []string{"https://inspector.example"}
	if r := b.rpc(rec, 6, "ping", nil, map[string]string{"Origin": "https://inspector.example"}); r.status != 200 {
		t.Errorf("allowed origin: %d %s", r.status, r.body)
	}

	// Only MCP manifests have an address here.
	if r := b.send(http.MethodPost, gateway.Prefix+"payments-api", rec, []byte(`{}`), nil); r.status != 404 {
		t.Errorf("HTTP manifest: %d", r.status)
	}
	if r := b.send(http.MethodPost, gateway.Prefix+"nothing", rec, []byte(`{}`), nil); r.status != 404 {
		t.Errorf("unknown manifest: %d", r.status)
	}

	// Every decision the gateway asked for is on the chain.
	head := b.head()
	all, err := b.st.Decisions().Range(ctx, 0, head.Chain.Seq+1)
	if err != nil {
		t.Fatal(err)
	}
	if broken, err := v0.Verify(all); broken != -1 || err != nil {
		t.Errorf("chain broken at %d: %v", broken, err)
	}
	for _, d := range all {
		if d.PEP.ID != "gateway-test" || d.Request.Context["token"] != nil {
			t.Errorf("record %s: pep %+v, context %v", d.ID, d.PEP, d.Request.Context)
		}
	}
}
