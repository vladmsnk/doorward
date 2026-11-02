package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/demoledger"
	"github.com/vladmsnk/doorward/internal/driver"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/gateway"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/mcp"
	"github.com/vladmsnk/doorward/internal/persistence/sql"
	"github.com/vladmsnk/doorward/internal/testhelpers"
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
	st     *sql.Persister
	v      *schema.Validator
	signer *jwk.Signer
	reg    *driver.RegistryDefault
	srv    *httptest.Server

	// The ledger answers as plain JSON, or as event streams when sse is set.
	ledger, ledgerSSE *demoledger.Server
	sse               atomic.Bool
}

func newBox(t testing.TB) *box {
	t.Helper()
	ctx := context.Background()
	clock := func() time.Time { return now }
	reg := testhelpers.NewRegistry(t, func(c *config.DefaultProvider) {
		c.PDPID, c.GatewayID = "doorward-test", "gateway-test"
	}, func(r *driver.RegistryDefault) { r.WithClock(clock) })
	st := reg.Persister().(*sql.Persister)
	v := reg.Validator()
	b := &box{t: t, st: st, v: v, reg: reg}
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
	testhelpers.PutExampleConfig(t, st.Documents(), func(file string, doc []byte) []byte {
		if file == "manifest-ledger-mcp.yaml" {
			return retarget(t, doc, upstream.URL+"/mcp")
		}
		return doc
	})

	sealed, err := reg.Sealer().Seal([]byte(apiKey), configuration.SecretPurpose(keyRef))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Secrets().Put(ctx, keyRef, sealed, "test"); err != nil {
		t.Fatal(err)
	}
	b.signer = reg.KeyRing().Signer()
	mux := http.NewServeMux()
	reg.GatewayHandler().SetPublicRoutes(mux)
	b.srv = httptest.NewServer(mux)
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
	if err := b.st.Grants().Create(context.Background(), grant.Record{Grant: g, Agent: g.Actor.Subject}); err != nil {
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
		if v == "" {
			req.Header.Del(k) // leave it out
			continue
		}
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
	b.reg.Config().GatewayOrigins = "https://inspector.example"
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

func TestGatewayHardening(t *testing.T) {
	b := newBox(t)
	rec := b.mint("grt_reconciler_000000000001")
	raw := func(s string) reply { return b.send(http.MethodPost, endpoint, rec, []byte(s), nil) }
	count := func() int { return len(b.ledger.Requests()) }

	// A message that this gateway and a case-sensitive server would read as
	// two different calls is refused, not forwarded: here a second "Method"
	// alongside "method", and a second "Arguments" alongside "arguments".
	n := count()
	r := raw(`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"write_off","arguments":{"payment_id":"p","amount":50000,"reason":"x"}}}`)
	if r.status != 400 || r.msg["error"] == nil {
		t.Fatalf("ambiguous method: %d %s", r.status, r.body)
	}
	r = raw(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"post_entry","arguments":{"account_id":"a","amount":50000},"Arguments":{"account_id":"a","amount":1}}}`)
	if r.status != 400 || r.msg["error"] == nil {
		t.Fatalf("ambiguous arguments: %d %s", r.status, r.body)
	}
	if count() != n {
		t.Error("an ambiguous message reached the server")
	}

	// Methods the manifest cannot describe are refused in the protocol, not
	// proxied undecided.
	n = count()
	for _, m := range []string{"resources/read", "resources/list", "prompts/list", "logging/setLevel", "sampling/createMessage"} {
		r := b.rpc(rec, 3, m, map[string]any{"uri": "ledger://export/all"}, nil)
		errObj, _ := r.msg["error"].(map[string]any)
		if errObj == nil || errObj["code"].(float64) != -32601 {
			t.Errorf("%s: want a -32601 error, got %d %s", m, r.status, r.body)
		}
	}
	if count() != n {
		t.Error("a method the manifest does not describe reached the server")
	}

	// The client's own headers do not reach the server: the grant, cookies
	// and anything a server might read as an identity are dropped.
	r = b.rpc(rec, 4, "tools/call",
		map[string]any{"name": "post_entry", "arguments": map[string]any{"account_id": "acc_EU_448120", "amount": 240.5}},
		map[string]string{"X-Forwarded-User": "cfo@example.com", "Cookie": "session=abc", "X-Real-Ip": "10.0.0.9"})
	if _, _, isErr := r.toolError(); isErr {
		t.Fatalf("post_entry with extra headers: %s", r.body)
	}
	for _, seen := range b.ledger.Requests() {
		if len(seen.Extra) != 0 {
			t.Errorf("the server saw client headers it should not: %v", seen.Extra)
		}
		if seen.Credential != "api key" {
			t.Errorf("the server saw credential %q, not the upstream key", seen.Credential)
		}
	}
}

// A manifest imported from the ledger's own tool list serves as the
// hand-written one does: the granted tools are listed, a write runs and a
// critical call is held.
func TestGatewayServesAnImportedManifest(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	snap, err := b.reg.ConfigurationCache().Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	man, ok := snap.ManifestByName("ledger-mcp")
	if !ok {
		t.Fatal("no ledger manifest")
	}
	listing, err := mcp.ListTools(ctx, man.Spec.Upstream.URL, http.Header{"Authorization": {"Bearer " + apiKey}})
	if err != nil {
		t.Fatal(err)
	}
	base := man.Manifest
	base.Spec.Operations = nil
	d := configuration.DraftManifest(base, listing.Tools, nil)
	doc, err := json.Marshal(d.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.v.Check(schema.Manifest, doc); err != nil {
		t.Fatal(err)
	}
	stored, err := b.st.Documents().Put(ctx, v0.KindManifest, "ledger-mcp", doc, "test")
	if err != nil {
		t.Fatal(err)
	}

	rec := b.mint("grt_reconciler_000000000009")
	// export_everything is declared now, as write, but not granted.
	r := b.rpc(rec, 2, "tools/list", nil, nil)
	if got := strings.Join(r.tools(), " "); r.status != 200 || got != "list_unmatched post_entry write_off" {
		t.Fatalf("tools/list: %d %q %s", r.status, got, r.body)
	}
	if text, _, isErr := b.tool(rec, "post_entry", entry(240.5)).toolError(); isErr || !strings.HasPrefix(text, "posted ent_") {
		t.Errorf("post_entry: %s", text)
	}
	r = b.tool(rec, "write_off", map[string]any{"payment_id": "pmt_8K2", "amount": 100.0, "reason": "duplicate"})
	if _, meta, isErr := r.toolError(); !isErr || meta["outcome"] != "approval_required" {
		t.Errorf("write_off: %s", r.body)
	}
	if v := b.head().Versions; v == nil || v.Manifest != stored.Digest {
		t.Errorf("the record names manifest %+v, not the imported %s", v, stored.Digest)
	}
}

// put stores a document directly, as an example configuration is stored.
func (b *box) put(kind string, doc map[string]any) string {
	b.t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		b.t.Fatal(err)
	}
	k, err := schema.ParseKind(kind)
	if err != nil {
		b.t.Fatal(err)
	}
	if err := b.v.Check(k, data); err != nil {
		b.t.Fatalf("%s: %v", data, err)
	}
	d, err := b.st.Documents().Put(context.Background(), kind, doc["metadata"].(map[string]any)["name"].(string), data, "test")
	if err != nil {
		b.t.Fatal(err)
	}
	return d.Digest
}

// userGrant mints a grant for a user, through agent, under mandate, with
// the consent it rests on, for list_unmatched alone.
func (b *box) userGrant(id, agent, mandate, digest string) string {
	b.t.Helper()
	user := v0.SubjectID{Format: v0.SubjectIDFormat, Issuer: "https://login.example.com", Sub: "u_alice"}
	c := v0.Consent{
		ID: "cns_" + id, User: user, Agent: agent, Mandate: mandate, MandateVersion: digest, Status: v0.ConsentActive,
		GrantedAt: v0.Timestamp{Time: now.Add(-time.Hour)}, ExpiresAt: v0.Timestamp{Time: now.Add(24 * time.Hour)},
	}
	if err := b.st.Consents().Create(context.Background(), c); err != nil {
		b.t.Fatal(err)
	}
	return b.mint("grt_"+id, func(g *v0.Grant) {
		g.Subject, g.SubjectID, g.ClientID, g.Consent = "alice@example.com", &user, "client-"+agent, c.ID
		g.Actor, g.Mandate, g.Limits, g.Audience = v0.Actor{Subject: agent}, mandate, nil, []string{ledgerAud}
		g.AuthorizationDetails = []v0.AuthorizationDetail{{Type: v0.AuthorizationDetailType, Locations: []string{ledgerAud}, Actions: []string{"list_unmatched"}}}
	})
}

// A refused tool names, in the 403, only the mandates the caller could
// obtain: ones its agent may request, for its kind of principal, within
// its ceiling. Otherwise the refusal is a plain tool error, not an
// invitation to a step-up that can only fail.
func TestGatewayStepUpNamesOnlyMandatesTheAgentCanGet(t *testing.T) {
	b := newBox(t)
	ledger := func(actions ...string) []map[string]any {
		return []map[string]any{{"locations": []string{ledgerAud}, "actions": actions}}
	}
	mandate := func(name string, open bool, actions ...string) string {
		spec := map[string]any{"principal": "user", "ttl": "10m",
			"consent": map[string]any{"text": "Read the ledger.", "max_duration": "24h"}, "permissions": ledger(actions...)}
		if open {
			spec["open"] = true
		}
		return b.put(v0.KindMandate, map[string]any{"apiVersion": v0.APIVersion, "kind": v0.KindMandate, "metadata": map[string]any{"name": name}, "spec": spec})
	}
	agent := func(name string, status v0.AgentStatus, ceiling v0.Sensitivity, mandates []string, actions ...string) {
		doc := map[string]any{"apiVersion": v0.APIVersion, "kind": v0.KindAgent, "metadata": map[string]any{"name": name},
			"spec": map[string]any{"status": status, "max_sensitivity": ceiling, "max_ttl": "1h",
				"identities":  []map[string]any{{"type": "oauth_client", "client_id": "client-" + name, "redirect_uris": []string{"http://127.0.0.1:1/cb"}}},
				"permissions": ledger(actions...)}}
		spec := doc["spec"].(map[string]any)
		if mandates != nil {
			spec["mandates"] = mandates
		}
		if status == v0.AgentUnverified {
			spec["publisher"] = map[string]any{"name": "Peek"}
		} else {
			spec["owner"] = map[string]any{"team": "finance-platform"}
		}
		b.put(v0.KindAgent, doc)
	}
	glance := mandate("ledger-glance", true, "list_unmatched")
	mandate("ledger-books", false, "list_unmatched", "post_entry")
	agent("peek-1a2b", v0.AgentUnverified, v0.SensitivityRead, nil, "list_unmatched", "post_entry")
	agent("books-helper", v0.AgentVerified, v0.SensitivityWrite, []string{"ledger-books"}, "list_unmatched", "post_entry", "write_off")

	refused := func(name string, r reply) {
		t.Helper()
		if text, _, isErr := r.toolError(); r.status != 200 || !isErr || !strings.Contains(text, "action_not_granted") {
			t.Errorf("%s: want a plain refusal, got %d %q %s", name, r.status, r.header.Get("WWW-Authenticate"), r.body)
		}
	}
	// Unverified: it may ask only for open mandates, and none allows the
	// write, so neither ledger-books nor the service mandate reconcile is
	// named.
	peek := b.userGrant("peek_000000001", "peek-1a2b", "ledger-glance", glance)
	refused("unverified agent", b.tool(peek, "post_entry", entry(10)))

	// Verified: the mandate it lists is named, and the service mandate
	// that also allows the tool is not.
	helper := b.userGrant("helper_0000001", "books-helper", "ledger-glance", glance)
	r := b.tool(helper, "post_entry", entry(10))
	if r.status != 403 || !strings.Contains(r.header.Get("WWW-Authenticate"), `scope="ledger-books"`) {
		t.Errorf("verified agent: %d %q %s", r.status, r.header.Get("WWW-Authenticate"), r.body)
	}
	// Above its ceiling: write_off is critical, the agent stops at write.
	refused("above the ceiling", b.tool(helper, "write_off", map[string]any{"payment_id": "p", "amount": 1.0, "reason": "x"}))
}

// modern posts one 2026-07-28 request: the version in the body's _meta and
// in the header, the method and name mirrored in headers. header, applied
// last, changes or ("") removes any of them.
func (b *box) modern(token string, method string, params map[string]any, header map[string]string) reply {
	b.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
	h := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
	if name, ok := params["name"].(string); ok {
		h["Mcp-Name"] = name
	}
	for k, v := range header {
		h[k] = v
	}
	return b.rpc(token, 9, method, params, h)
}

func rpcErrorCode(r reply) float64 {
	e, _ := r.msg["error"].(map[string]any)
	code, _ := e["code"].(float64)
	return code
}

func rpcErrorMessage(r reply) string {
	e, _ := r.msg["error"].(map[string]any)
	msg, _ := e["message"].(string)
	return msg
}

// A 2026-07-28 client: no handshake, its version and the mirrored headers
// on every request. The gateway decides as before, keeps its answers in
// the revision's shape, and refuses headers that say something other than
// the body.
func TestGatewayModernRevision(t *testing.T) {
	b := newBox(t)
	rec := b.mint("grt_reconciler_modern_0001")
	call := func(name string, args map[string]any) map[string]any {
		return map[string]any{"name": name, "arguments": args}
	}

	r := b.modern(rec, "server/discover", nil, nil)
	if versions, _ := r.result()["supportedVersions"].([]any); r.status != 200 || len(versions) == 0 || versions[0] != "2026-07-28" {
		t.Fatalf("server/discover: %d %s", r.status, r.body)
	}

	// The list is the grant's, so it is private, whatever the server said.
	r = b.modern(rec, "tools/list", nil, nil)
	if got := strings.Join(r.tools(), " "); r.status != 200 || got != "list_unmatched post_entry write_off" ||
		r.result()["cacheScope"] != "private" || r.result()["ttlMs"] != 300000.0 || r.result()["resultType"] != "complete" {
		t.Fatalf("tools/list: %d %s", r.status, r.body)
	}

	if text, _, isErr := b.modern(rec, "tools/call", call("post_entry", entry(240.5)), nil).toolError(); isErr || !strings.HasPrefix(text, "posted ent_") {
		t.Fatalf("post_entry: %s", text)
	}
	if seen := b.ledger.Requests(); seen[len(seen)-1].Version != "2026-07-28" {
		t.Errorf("the ledger saw version %q", seen[len(seen)-1].Version)
	}
	// The gateway's own answers carry the revision's resultType.
	r = b.modern(rec, "tools/call", call("post_entry", entry(5000)), nil)
	if _, meta, isErr := r.toolError(); !isErr || meta["outcome"] != "deny" || r.result()["resultType"] != "complete" {
		t.Errorf("refusal: %s", r.body)
	}
	// A name in base64, as a client must send one that is not plain ASCII.
	r = b.modern(rec, "tools/call", call("post_entry", entry(1)), map[string]string{"Mcp-Name": "=?base64?cG9zdF9lbnRyeQ==?="})
	if _, _, isErr := r.toolError(); r.status != 200 || isErr {
		t.Errorf("encoded name: %d %s", r.status, r.body)
	}

	before := len(b.ledger.Requests())
	for _, tc := range []struct {
		name   string
		method string
		params map[string]any
		header map[string]string
		want   string
	}{
		{"another tool in the header", "tools/call", call("write_off", map[string]any{"payment_id": "p", "amount": 1.0, "reason": "x"}),
			map[string]string{"Mcp-Name": "list_unmatched"}, `Mcp-Name header value "list_unmatched" does not match body value "write_off"`},
		{"another method in the header", "tools/call", call("post_entry", entry(1)), map[string]string{"Mcp-Method": "tools/list"}, "Mcp-Method header value"},
		{"no name header", "tools/call", call("post_entry", entry(1)), map[string]string{"Mcp-Name": ""}, "the Mcp-Name header is missing"},
		{"no method header", "tools/list", nil, map[string]string{"Mcp-Method": ""}, "the Mcp-Method header is missing"},
		{"another version in the header", "tools/list", nil, map[string]string{"MCP-Protocol-Version": "2025-11-25"}, "MCP-Protocol-Version header value"},
		{"no version header", "tools/list", nil, map[string]string{"MCP-Protocol-Version": ""}, "the MCP-Protocol-Version header is missing"},
	} {
		r := b.modern(rec, tc.method, tc.params, tc.header)
		if r.status != 400 || rpcErrorCode(r) != -32020 || !strings.Contains(rpcErrorMessage(r), tc.want) {
			t.Errorf("%s: %d %s", tc.name, r.status, r.body)
		}
	}
	// An older client's headers, when it sends them, must agree too: the
	// gateway forwards them.
	r = b.rpc(rec, 9, "tools/call", call("write_off", map[string]any{"payment_id": "p", "amount": 1.0, "reason": "x"}), map[string]string{"Mcp-Name": "list_unmatched"})
	if r.status != 400 || rpcErrorCode(r) != -32020 {
		t.Errorf("older client, mismatched header: %d %s", r.status, r.body)
	}
	if len(b.ledger.Requests()) != before {
		t.Error("a request whose headers disagree with its body reached the ledger")
	}

	// What the manifest cannot describe: 404, as the revision answers an
	// unknown method. The subscription stream is the server's.
	if r := b.modern(rec, "resources/list", nil, nil); r.status != 404 || rpcErrorCode(r) != -32601 {
		t.Errorf("resources/list: %d %s", r.status, r.body)
	}
	b.modern(rec, "subscriptions/listen", map[string]any{"notifications": map[string]any{"toolsListChanged": true}}, nil)
	if seen := b.ledger.Requests(); seen[len(seen)-1].Method != "subscriptions/listen" {
		t.Errorf("subscriptions/listen did not reach the server: %+v", seen[len(seen)-1])
	}
}
