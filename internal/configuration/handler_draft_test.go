package configuration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/demoledger"
	"github.com/vladmsnk/doorward/schema"
)

func draft(t *testing.T, srv *httptest.Server, name, body string) (result, configuration.DraftResponse) {
	t.Helper()
	r := call(t, srv, http.MethodPost, "/admin/v0/manifests/"+name+"/draft", []byte(body), "application/json", true)
	var d configuration.DraftResponse
	if r.status == http.StatusOK {
		if err := json.Unmarshal([]byte(r.body), &d); err != nil {
			t.Fatal(err)
		}
	}
	return r, d
}

// TestDraftThroughTheAdminAPI drafts the stored ledger manifest again from
// the demo ledger, with the stored secret, and applies the draft and a
// starter mandate for it through the Admin API's own rules.
func TestDraftThroughTheAdminAPI(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)
	ledger := &demoledger.Server{APIKey: "lk_live_example", SSE: true}
	upstream := httptest.NewServer(ledger)
	defer upstream.Close()

	// The ledger manifest, pointed at the demo server.
	src, err := schema.Read("m.yaml", example(t, "manifest-ledger-mcp.yaml"), schema.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var stored v0.Manifest
	if err := json.Unmarshal(src[0].JSON, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Spec.Upstream.URL = upstream.URL + "/mcp"
	doc, _ := json.Marshal(stored)
	mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/manifests/ledger-mcp", doc, "application/json", true))

	r, d := draft(t, srv, "ledger-mcp", "")
	if r.status != http.StatusOK {
		t.Fatalf("draft: %d %s", r.status, r.body)
	}
	if d.Server.Name != "demo-ledger" || d.Version != 2 || d.Digest == "" {
		t.Errorf("draft of %+v, version %d", d.Server, d.Version)
	}
	want := []configuration.Change{{Operation: "export_everything", Kind: "added", Detail: "write"}}
	if !reflect.DeepEqual(d.Changes, want) || len(d.Notes) != 1 || d.Notes[0].Tool != "export_everything" {
		t.Errorf("changes %+v, notes %+v", d.Changes, d.Notes)
	}
	for _, seen := range ledger.Requests() {
		if seen.Credential != "api key" {
			t.Errorf("the ledger saw %q on %s: the stored secret was not used", seen.Credential, seen.Method)
		}
	}

	// Left out on purpose, export_everything makes no change.
	r, d2 := draft(t, srv, "ledger-mcp", `{"skip":["export_everything"]}`)
	if r.status != http.StatusOK || len(d2.Changes) != 0 || !reflect.DeepEqual(d2.Manifest, stored) {
		t.Errorf("draft without export_everything: %d %s", r.status, r.body)
	}

	// The draft applies as it is, and so does a starter mandate for it.
	doc, _ = json.Marshal(d.Manifest)
	if v := mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/manifests/ledger-mcp", doc, "application/json", true)).resp; v.Version != 3 {
		t.Errorf("applied as version %d", v.Version)
	}
	md, _, err := configuration.StarterMandate("ledger-starter", d.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ = json.Marshal(md)
	mustOK(t, call(t, srv, http.MethodPut, "/admin/v0/mandates/ledger-starter", doc, "application/json", true))

	// A draft stores nothing.
	before := call(t, srv, http.MethodGet, "/admin/v0/manifests/ledger-mcp", nil, "", true).body
	draft(t, srv, "ledger-mcp", "")
	if after := call(t, srv, http.MethodGet, "/admin/v0/manifests/ledger-mcp", nil, "", true).body; after != before {
		t.Error("drafting changed the stored manifest")
	}

	// The server refuses another credential, and says so.
	if r := call(t, srv, http.MethodPut, "/admin/v0/secrets/ledger-mcp-api-key", []byte(`{"value":"lk_wrong"}`), "application/json", true); r.status != http.StatusNoContent {
		t.Fatalf("put secret: %d", r.status)
	}
	if r, _ := draft(t, srv, "ledger-mcp", ""); r.status != http.StatusBadGateway || !strings.Contains(r.body, "401 Unauthorized") || strings.Contains(r.body, "lk_") {
		t.Errorf("wrong credential: %d %s", r.status, r.body)
	}
	upstream.Close()
	if r, _ := draft(t, srv, "ledger-mcp", ""); r.status != http.StatusBadGateway || !strings.Contains(r.body, `"upstream_failed"`) {
		t.Errorf("server gone: %d %s", r.status, r.body)
	}
}

func TestDraftRefusals(t *testing.T) {
	srv := newServer(t)
	loadExamples(t, srv)
	for _, tc := range []struct {
		name, manifest, body string
		status               int
		want                 string
	}{
		{"an HTTP manifest", "payments-api", "", http.StatusBadRequest, "only MCP servers list their tools"},
		{"no such manifest", "nothing", "", http.StatusNotFound, "not_found"},
		{"a bad body", "ledger-mcp", `{"skip":"all"}`, http.StatusBadRequest, "skip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r, _ := draft(t, srv, tc.manifest, tc.body); r.status != tc.status || !strings.Contains(r.body, tc.want) {
				t.Errorf("%d %s", r.status, r.body)
			}
		})
	}
	if r := call(t, srv, http.MethodPost, "/admin/v0/manifests/ledger-mcp/draft", nil, "", false); r.status != http.StatusUnauthorized {
		t.Errorf("without the token: %d", r.status)
	}
}
