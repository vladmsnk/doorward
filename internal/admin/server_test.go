package admin_test

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
	"sync"
	"testing"

	"github.com/vladmsnk/agentbox/internal/admin"
	"github.com/vladmsnk/agentbox/internal/keys"
	"github.com/vladmsnk/agentbox/internal/sealer"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

const token = "test-admin-token-0123456789"

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	dsn := os.Getenv("AGENTBOX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTBOX_TEST_POSTGRES_DSN not set")
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
	master, _ := sealer.Generate()
	sl, _ := sealer.Parse(master)
	km := keys.New(st.Keys(), sl)
	if _, err := km.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	api := &admin.Server{Store: st, Validator: v, Token: token, Sealer: sl, Keys: km, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

type result struct {
	status   int
	body     string
	resp     admin.Response
	problems []string
}

func call(t *testing.T, srv *httptest.Server, method, path string, body []byte, contentType string, withToken bool) result {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if withToken {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	out := result{status: res.StatusCode, body: string(raw)}
	if res.StatusCode == http.StatusOK && method != http.MethodGet {
		_ = json.Unmarshal(raw, &out.resp)
	}
	var e admin.ErrorResponse
	if res.StatusCode >= 400 && json.Unmarshal(raw, &e) == nil {
		out.problems = e.Problems
	}
	return out
}

func example(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../examples/v0/config", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func putYAML(t *testing.T, srv *httptest.Server, path, file string) result {
	t.Helper()
	return call(t, srv, http.MethodPut, path, example(t, file), "application/yaml", true)
}

func mustOK(t *testing.T, r result) result {
	t.Helper()
	if r.status != http.StatusOK {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
	return r
}

// loadExamples puts every example in dependency order.
func loadExamples(t *testing.T, srv *httptest.Server) {
	t.Helper()
	// The ledger manifest's upstream names a secret, which has to exist first.
	if r := call(t, srv, http.MethodPut, "/admin/v0/secrets/ledger-mcp-api-key", []byte(`{"value":"lk_live_example"}`), "application/json", true); r.status != 204 {
		t.Fatalf("put secret: %d %s", r.status, r.body)
	}
	for _, f := range []string{"manifest-payments-api.yaml", "manifest-ledger-mcp.yaml"} {
		mustOK(t, putYAML(t, srv, "/admin/v0/manifests/"+strings.TrimSuffix(strings.TrimPrefix(f, "manifest-"), ".yaml"), f))
	}
	for _, f := range []string{"mandate-invoices.yaml", "mandate-invoices-readonly.yaml", "mandate-reconcile.yaml"} {
		mustOK(t, putYAML(t, srv, "/admin/v0/mandates/"+strings.TrimSuffix(strings.TrimPrefix(f, "mandate-"), ".yaml"), f))
	}
	for name, f := range map[string]string{"invoice-assistant": "agent-invoice-assistant.yaml", "reconciler": "agent-reconciler.yaml", "desk-helper-7f3a": "agent-desk-helper.yaml"} {
		mustOK(t, putYAML(t, srv, "/admin/v0/agents/"+name, f))
	}
}

func TestExamplesLoadAndRead(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)

	r := call(t, srv, http.MethodGet, "/admin/v0/mandates", nil, "", true)
	var list []admin.Response
	if err := json.Unmarshal([]byte(r.body), &list); err != nil || len(list) != 3 {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	r = call(t, srv, http.MethodGet, "/admin/v0/agents/desk-helper-7f3a", nil, "", true)
	if r.status != 200 || !strings.Contains(r.body, `"status":"unverified"`) || !strings.Contains(r.body, `"version":1`) {
		t.Fatalf("get: %d %s", r.status, r.body)
	}
	if r := call(t, srv, http.MethodGet, "/admin/v0/agents/nobody", nil, "", true); r.status != 404 {
		t.Errorf("missing agent: %d", r.status)
	}
	if r := call(t, srv, http.MethodGet, "/admin/v0/policies", nil, "", true); r.status != 404 {
		t.Errorf("unknown collection: %d", r.status)
	}
}

func TestEveryWriteIsAVersion(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)
	v2 := mustOK(t, putYAML(t, srv, "/admin/v0/mandates/invoices", "mandate-invoices.yaml")).resp
	if v2.Version != 2 {
		t.Fatalf("second put: version %d", v2.Version)
	}
	r := call(t, srv, http.MethodGet, "/admin/v0/mandates/invoices/versions", nil, "", true)
	var hist []admin.Response
	_ = json.Unmarshal([]byte(r.body), &hist)
	if len(hist) != 2 || hist[0].Digest != hist[1].Digest || hist[0].CreatedBy != "admin-token" {
		t.Fatalf("history: %s", r.body)
	}
	if r := call(t, srv, http.MethodGet, "/admin/v0/mandates/invoices/versions/1", nil, "", true); r.status != 200 {
		t.Errorf("version 1: %d", r.status)
	}
	if r := call(t, srv, http.MethodGet, "/admin/v0/mandates/invoices/versions/9", nil, "", true); r.status != 404 {
		t.Errorf("version 9: %d", r.status)
	}
}

func TestRefusals(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)
	invoices := string(example(t, "mandate-invoices.yaml"))

	cases := []struct {
		name   string
		path   string
		body   string
		status int
		want   string
	}{
		{"no token", "/admin/v0/mandates/invoices", invoices, 401, "administrator token"},
		{"name mismatch", "/admin/v0/mandates/other", invoices, 400, `metadata.name is \"invoices\"`},
		{"wrong kind for the collection", "/admin/v0/agents/invoices", invoices, 400, "expected a Agent"},
		{"schema violation", "/admin/v0/mandates/invoices", strings.Replace(invoices, "ttl: 15m", "ttl: soon", 1), 400, "pattern"},
		{"mandate wider than the agent", "/admin/v0/mandates/invoices",
			strings.Replace(invoices, "/amount: { min: 0.01, max: 5000 }", "/amount: { min: 0.01, max: 50000 }", 1), 400, "at or below 10000"},
		{"mandate longer than the agent allows", "/admin/v0/mandates/invoices", strings.Replace(invoices, "ttl: 15m", "ttl: 2h", 1), 400, "max_ttl 30m"},
		{"operation no manifest declares", "/admin/v0/mandates/invoices", strings.Replace(invoices, "list_payments", "delete_invoice", 1), 400, "does not declare"},
		{"audience no manifest declares", "/admin/v0/mandates/invoices",
			strings.ReplaceAll(invoices, "https://payments.example.internal", "https://nowhere.example.internal"), 400, "no manifest declares"},
		{"constraint on an argument no operation has", "/admin/v0/mandates/invoices", strings.Replace(invoices, "/amount: { min: 0.01, max: 5000 }", "/total: { min: 0.01, max: 5000 }", 1), 400, "none of its operations"},
		{"monthly limit above the agent's cap", "/admin/v0/mandates/invoices", strings.Replace(invoices, "max: 5000\n    - name: calls", "max: 25000\n    - name: calls", 1), 400, "caps it at 20000"},
		{"contradictory bounds", "/admin/v0/mandates/invoices",
			strings.Replace(invoices, "/amount: { min: 0.01, max: 5000 }", "/amount: { min: 6000, max: 5000 }", 1), 400, "min 6000 is above max 5000"},
		{"second manifest on one audience", "/admin/v0/manifests/payments-copy",
			strings.Replace(string(example(t, "manifest-payments-api.yaml")), "name: payments-api", "name: payments-copy", 1), 400, "already belongs to manifest payments-api"},
		{"agent listing a missing mandate", "/admin/v0/agents/invoice-assistant",
			strings.Replace(string(example(t, "agent-invoice-assistant.yaml")), "mandates: [invoices]", "mandates: [invoices, refunds]", 1), 400, "refunds, which does not exist"},
		{"agent claiming another's identity", "/admin/v0/agents/reconciler",
			strings.Replace(string(example(t, "agent-reconciler.yaml")), "subject: system:serviceaccount:finance:reconciler", "subject: system:serviceaccount:finance:reconciler\n    - type: oauth_client\n      client_id: acme-invoice-assistant", 1), 400, "already claimed by agent invoice-assistant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := call(t, srv, http.MethodPut, tc.path, []byte(tc.body), "application/yaml", tc.name != "no token")
			if r.status != tc.status {
				t.Fatalf("status %d, want %d: %s", r.status, tc.status, r.body)
			}
			if !strings.Contains(r.body, tc.want) {
				t.Errorf("response lacks %q: %s", tc.want, r.body)
			}
		})
	}

	// None of the refused writes left a trace.
	r := call(t, srv, http.MethodGet, "/admin/v0/mandates/invoices/versions", nil, "", true)
	if strings.Count(r.body, `"version"`) != 1 {
		t.Errorf("refused writes created versions: %s", r.body)
	}
}

func TestAgentLifecycle(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)

	r := call(t, srv, http.MethodPost, "/admin/v0/agents/desk-helper-7f3a/verify", []byte(`{"owner":{"team":"support-tools"}}`), "application/json", true)
	mustOK(t, r)
	if r.resp.Version != 2 || !strings.Contains(string(r.resp.Document), `"status":"verified"`) || !strings.Contains(string(r.resp.Document), `"team":"support-tools"`) {
		t.Fatalf("verify: %s", r.body)
	}
	if r := call(t, srv, http.MethodPost, "/admin/v0/agents/desk-helper-7f3a/verify", []byte(`{}`), "application/json", true); r.status != 400 {
		t.Errorf("verify without owner: %d", r.status)
	}
	r = call(t, srv, http.MethodPost, "/admin/v0/agents/desk-helper-7f3a/suspend", nil, "", true)
	mustOK(t, r)
	if r.resp.Version != 3 || !strings.Contains(string(r.resp.Document), `"status":"suspended"`) {
		t.Fatalf("suspend: %s", r.body)
	}
	if r := call(t, srv, http.MethodPost, "/admin/v0/agents/desk-helper-7f3a/disable", nil, "", true); r.status != 400 {
		t.Errorf("disable on an agent: %d", r.status)
	}
}

func TestSecretsAndKeys(t *testing.T) {
	srv := newServer(t)

	// A manifest cannot name a secret that is not there.
	r := putYAML(t, srv, "/admin/v0/manifests/ledger-mcp", "manifest-ledger-mcp.yaml")
	if r.status != 400 || !strings.Contains(r.body, "secret ledger-mcp-api-key, which has not been stored") {
		t.Fatalf("manifest before secret: %d %s", r.status, r.body)
	}
	loadExamples(t, srv)

	// Secrets are listed without their values, and cannot be deleted while used.
	r = call(t, srv, http.MethodGet, "/admin/v0/secrets", nil, "", true)
	if r.status != 200 || !strings.Contains(r.body, `"name":"ledger-mcp-api-key"`) || strings.Contains(r.body, "lk_live") {
		t.Fatalf("list secrets: %d %s", r.status, r.body)
	}
	if r := call(t, srv, http.MethodDelete, "/admin/v0/secrets/ledger-mcp-api-key", nil, "", true); r.status != 409 {
		t.Errorf("delete secret in use: %d %s", r.status, r.body)
	}
	if r := call(t, srv, http.MethodPut, "/admin/v0/secrets/Bad Name", []byte(`{"value":"x"}`), "application/json", true); r.status != 400 {
		t.Errorf("bad secret name: %d", r.status)
	}
	if r := call(t, srv, http.MethodPut, "/admin/v0/secrets/empty", []byte(`{"value":""}`), "application/json", true); r.status != 400 {
		t.Errorf("empty secret: %d", r.status)
	}
	if r := call(t, srv, http.MethodPut, "/admin/v0/secrets/unused", []byte(`{"value":"x"}`), "application/json", true); r.status != 204 {
		t.Errorf("put unused secret: %d", r.status)
	}
	if r := call(t, srv, http.MethodDelete, "/admin/v0/secrets/unused", nil, "", true); r.status != 204 {
		t.Errorf("delete unused secret: %d", r.status)
	}

	// Keys: one active key at start; rotation adds one; the active key cannot be retired.
	r = call(t, srv, http.MethodGet, "/admin/v0/keys", nil, "", true)
	var ks []admin.KeyResponse
	if err := json.Unmarshal([]byte(r.body), &ks); err != nil || len(ks) != 1 || !ks[0].Active {
		t.Fatalf("keys: %d %s", r.status, r.body)
	}
	first := ks[0].KID
	if r := call(t, srv, http.MethodPost, "/admin/v0/keys/rotate", nil, "", true); r.status != 200 {
		t.Fatalf("rotate: %d %s", r.status, r.body)
	}
	r = call(t, srv, http.MethodGet, "/admin/v0/keys", nil, "", true)
	_ = json.Unmarshal([]byte(r.body), &ks)
	// Newest first: the new key is active, the first one no longer is.
	if len(ks) != 2 || !ks[0].Active || ks[0].KID == first || ks[1].Active || ks[1].KID != first {
		t.Fatalf("after rotate: %s", r.body)
	}
	var active string
	for _, k := range ks {
		if k.Active {
			active = k.KID
		}
	}
	if r := call(t, srv, http.MethodPost, "/admin/v0/keys/"+active+"/retire", nil, "", true); r.status != 409 {
		t.Errorf("retire active key: %d %s", r.status, r.body)
	}
	if r := call(t, srv, http.MethodPost, "/admin/v0/keys/"+first+"/retire", nil, "", true); r.status != 204 {
		t.Errorf("retire old key: %d %s", r.status, r.body)
	}
	if r := call(t, srv, http.MethodPost, "/admin/v0/keys/nope/retire", nil, "", true); r.status != 404 {
		t.Errorf("retire unknown key: %d", r.status)
	}
}

func TestDisableAndEnable(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)

	// A manifest that mandates rest on cannot be disabled under them.
	if r := call(t, srv, http.MethodPost, "/admin/v0/manifests/payments-api/disable", nil, "", true); r.status != 409 || !strings.Contains(r.body, "invoices") {
		t.Fatalf("disable manifest in use: %d %s", r.status, r.body)
	}
	// A mandate can be disabled; the change is a version.
	r := mustOK(t, call(t, srv, http.MethodPost, "/admin/v0/mandates/reconcile/disable", nil, "", true))
	if !r.resp.Disabled || r.resp.Version != 2 {
		t.Fatalf("disable mandate: %s", r.body)
	}
	// An agent may keep listing a disabled mandate: disabling it is how its
	// grants are stopped at once. While it is disabled, the agent narrows
	// below it.
	narrow := strings.Replace(string(example(t, "agent-reconciler.yaml")), "/amount: { max: 5000 }", "/amount: { max: 500 }", 1)
	mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/agents/reconciler", []byte(narrow), "application/yaml", true))
	// P4: enabling it again is checked against the configuration as it is
	// now, and refused: the mandate allows 1000, the agent 500.
	if r := call(t, srv, http.MethodPost, "/admin/v0/mandates/reconcile/enable", nil, "", true); r.status != 400 || !strings.Contains(r.body, "must stay at or below 500") {
		t.Fatalf("enable a mandate that no longer fits: %d %s", r.status, r.body)
	}
	mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/agents/reconciler", example(t, "agent-reconciler.yaml"), "application/yaml", true))
	r = mustOK(t, call(t, srv, http.MethodPost, "/admin/v0/mandates/reconcile/enable", nil, "", true))
	if r.resp.Disabled || r.resp.Version != 3 {
		t.Fatalf("enable mandate: %s", r.body)
	}
	// Enabling twice adds nothing.
	r = mustOK(t, call(t, srv, http.MethodPost, "/admin/v0/mandates/reconcile/enable", nil, "", true))
	if r.resp.Version != 3 {
		t.Errorf("enable twice: version %d", r.resp.Version)
	}
}

// P4: a manifest change is checked against the mandates and agents that
// rely on it. Before, only the manifest's audience and secret were checked.
func TestManifestChangesAreChecked(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)
	payments := string(example(t, "manifest-payments-api.yaml"))

	// Dropping an operation a mandate names.
	start := strings.Index(payments, "    # Critical: never runs on a standing grant")
	if start < 0 {
		t.Fatal("the example manifest changed shape")
	}
	withoutPay := payments[:start]
	if r := call(t, srv, http.MethodPut, "/admin/v0/manifests/payments-api", []byte(withoutPay), "application/yaml", true); r.status != 400 ||
		!strings.Contains(r.body, "mandate invoices names operation pay_invoice, which manifest payments-api does not declare") {
		t.Errorf("manifest dropping pay_invoice: %d %s", r.status, r.body)
	}
	// Raising an operation above an agent's ceiling: get_invoice becomes
	// write, but the unverified desk helper, which may ask for the open
	// read-only mandate, goes no higher than read.
	raised := strings.Replace(payments, "description: Read one invoice.\n      sensitivity: read", "description: Read one invoice.\n      sensitivity: write", 1)
	if raised == payments {
		t.Fatal("the example manifest changed shape")
	}
	if r := call(t, srv, http.MethodPut, "/admin/v0/manifests/payments-api", []byte(raised), "application/yaml", true); r.status != 400 ||
		!strings.Contains(r.body, "a write operation, but agent desk-helper-7f3a may go no higher than read") {
		t.Errorf("manifest raising get_invoice: %d %s", r.status, r.body)
	}
	// Neither left a version behind.
	r := call(t, srv, http.MethodGet, "/admin/v0/manifests/payments-api/versions", nil, "", true)
	if strings.Count(r.body, `"version"`) != 1 {
		t.Errorf("refused manifest writes created versions: %s", r.body)
	}
}

// P4: two changes that are each fine, but not together, cannot both pass.
// The mandate rises to 8000 while the agent's ceiling falls to 6000; one of
// the two must be refused, whichever comes second.
func TestConflictingChangesAreSerialized(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)
	mandate := string(example(t, "mandate-invoices.yaml"))
	agent := string(example(t, "agent-invoice-assistant.yaml"))
	wideMandate := strings.Replace(mandate, "/amount: { min: 0.01, max: 5000 }", "/amount: { min: 0.01, max: 8000 }", 1)
	lowAgent := strings.Replace(agent, "/amount: { max: 10000 }", "/amount: { max: 6000 }", 1)
	if wideMandate == mandate || lowAgent == agent {
		t.Fatal("the examples changed shape")
	}
	for round := 0; round < 20; round++ {
		mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/mandates/invoices", []byte(mandate), "application/yaml", true))
		mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/agents/invoice-assistant", []byte(agent), "application/yaml", true))
		var wg sync.WaitGroup
		codes := make([]int, 2)
		for i, put := range []struct{ path, body string }{
			{"/admin/v0/mandates/invoices", wideMandate},
			{"/admin/v0/agents/invoice-assistant", lowAgent},
		} {
			wg.Add(1)
			go func(i int, path, body string) {
				defer wg.Done()
				codes[i] = call(t, srv, http.MethodPut, path, []byte(body), "application/yaml", true).status
			}(i, put.path, put.body)
		}
		wg.Wait()
		ok := 0
		for _, c := range codes {
			if c == http.StatusOK {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d of the two conflicting changes passed (statuses %v)", round, ok, codes)
		}
	}
}
