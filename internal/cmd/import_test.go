package cmd

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/demoledger"
	"github.com/vladmsnk/doorward/schema"
)

const ledgerKey = "Authorization: Bearer lk_live_example"

func ledger(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(&demoledger.Server{APIKey: "lk_live_example", SSE: true, PageSize: 3})
	t.Cleanup(srv.Close)
	return srv.URL + "/mcp"
}

func read[T schema.Document](t *testing.T, file string) T {
	t.Helper()
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file) // #nosec G304 -- a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	src, err := schema.Read(file, data, schema.KindOf[T]())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := schema.Decode[T](v, src[0].JSON)
	if err != nil {
		t.Fatalf("%s: %v\n%s", file, err, data)
	}
	return doc
}

func TestImportMCP(t *testing.T) {
	url := ledger(t)
	dir := t.TempDir()
	manifest, mandate := filepath.Join(dir, "ledger.yaml"), filepath.Join(dir, "mandate.yaml")
	code, stdout, stderr := runCLI("import", "mcp", "--name", "ledger-mcp", "--audience", "https://doorward.example.com/mcp/ledger-mcp",
		"--secret-ref", "ledger-mcp-api-key", "--header", ledgerKey, "-o", manifest, "--mandate", mandate, url)
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d, stdout %q\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"ledger-mcp from demo-ledger 0.1 (MCP 2025-11-25): 4 tools listed, 4 operations",
		"+ list_unmatched (read)\n+ post_entry (write)\n+ write_off (critical)\n+ export_everything (write)\n",
		"note: post_entry: it does not say whether it is destructive; drafted as write",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if code, _, stderr := runCLI("validate", manifest, mandate); code != 0 {
		t.Fatalf("the draft does not validate:\n%s", stderr)
	}

	m := read[v0.Manifest](t, manifest)
	if m.Spec.Upstream.URL != url || *m.Spec.Upstream.Auth != (v0.UpstreamAuth{Header: "Authorization", Prefix: "Bearer ", SecretRef: "ledger-mcp-api-key"}) {
		t.Errorf("upstream: %+v", m.Spec.Upstream)
	}
	data, _ := os.ReadFile(manifest) // #nosec G304 -- a file the test wrote
	if strings.Contains(string(data), "lk_live_example") {
		t.Error("the server's credential is in the draft")
	}
	if !strings.Contains(string(data), "\n        /amount: {type: number}\n") {
		t.Errorf("params are not one a line:\n%s", data)
	}

	md := read[v0.Mandate](t, mandate)
	if len(md.Spec.Permissions) != 2 || md.Spec.Permissions[0].Actions[0] != "list_unmatched" || md.Spec.Permissions[1].Actions[0] != "write_off" ||
		md.Spec.Approval == nil || md.Spec.Approval.Approvers.Kind != v0.ApproverUser {
		t.Errorf("starter mandate: %+v", md.Spec)
	}
	data, _ = os.ReadFile(mandate) // #nosec G304 -- a file the test wrote
	if !strings.HasPrefix(string(data), "# A starter mandate for manifest ledger-mcp") || !strings.Contains(string(data), "# out: post_entry, export_everything.") {
		t.Errorf("starter mandate's comment:\n%s", data)
	}

	// Importing again against the draft changes nothing, to the byte.
	code, stdout, stderr = runCLI("import", "mcp", "--header", ledgerKey, "--against", manifest)
	if code != 0 || !strings.Contains(stderr, "no changes") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
	before, _ := os.ReadFile(manifest) // #nosec G304 -- a file the test wrote
	if stdout != string(before) {
		t.Errorf("the second draft differs:\n%s\nfrom:\n%s", stdout, before)
	}
}

func TestImportMCPAgainstAManifest(t *testing.T) {
	url := ledger(t)
	example := filepath.Join("..", "..", "examples", "v0", "config", "manifest-ledger-mcp.yaml")
	code, stdout, stderr := runCLI("import", "mcp", "--header", ledgerKey, "--against", example, "--skip", "export_everything", url)
	if code != 0 || !strings.Contains(stderr, "no changes") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "upstream:\n    url: https://ledger-mcp.finance.svc.cluster.local/mcp\n") {
		t.Errorf("the manifest's upstream changed:\n%s", stdout)
	}
	// export_everything, which the manifest leaves out, is a change.
	code, _, stderr = runCLI("import", "mcp", "--header", ledgerKey, "--against", example, url)
	if code != exitChanged || !strings.Contains(stderr, "+ export_everything (write)\n") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
}

func TestImportMCPErrors(t *testing.T) {
	url := ledger(t)
	payments := filepath.Join("..", "..", "examples", "v0", "config", "manifest-payments-api.yaml")
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no credential", []string{"--name", "l", "--audience", "https://a.example/mcp", url}, 1, "give it with --header"},
		{"no server", []string{"--name", "l", "--audience", "https://a.example/mcp", "http://127.0.0.1:1/mcp"}, 1, "initialize:"},
		{"no name", []string{"--audience", "https://a.example/mcp", url}, 2, "usage:"},
		{"bad name", []string{"--name", "Ledger", "--audience", "https://a.example/mcp", url}, 2, "not a name"},
		{"bad audience", []string{"--name", "l", "--audience", "ledger", "--header", ledgerKey, url}, 1, "not a valid manifest"},
		{"bad header", []string{"--header", "Authorization", "--name", "l", "--audience", "https://a.example/mcp", url}, 2, `want "Name: value"`},
		{"two URLs", []string{"--name", "l", "--audience", "https://a.example/mcp", url, url}, 2, "usage:"},
		{"against and name", []string{"--against", payments, "--name", "l"}, 2, "come from the --against manifest"},
		{"against an HTTP manifest", []string{"--against", payments}, 2, "only MCP servers list their tools"},
		{"against nothing", []string{"--against", "missing.yaml"}, 1, "missing.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(append([]string{"import", "mcp"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, want %d; stderr lacks %q:\n%s", code, tc.code, tc.want, stderr)
			}
		})
	}
}
