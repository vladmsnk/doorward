package testhelpers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/schema"
)

// Examples is the directory of the example documents, examples/v0.
var Examples = func() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "examples", "v0")
}()

var validator = sync.OnceValues(schema.NewValidator)

// Example reads the example at examples/v0/rel as a T, the way the box
// reads a document: strictly decoded, and checked against the schema and
// the document's own rules.
func Example[T schema.Document](t testing.TB, rel string) T {
	t.Helper()
	v, err := validator()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(Examples, rel))
	if err != nil {
		t.Fatal(err)
	}
	src, err := schema.Read(rel, data, schema.KindOf[T]())
	if err != nil {
		t.Fatal(err)
	}
	out, err := schema.Decode[T](v, src[0].JSON)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return out
}

// ConfigFiles are the example configuration documents a decision needs:
// both manifests, the mandates and agents of the two stories.
var ConfigFiles = []string{
	"manifest-payments-api.yaml", "manifest-ledger-mcp.yaml", "mandate-invoices.yaml", "mandate-reconcile.yaml",
	"agent-invoice-assistant.yaml", "agent-reconciler.yaml",
}

// PutExampleConfig stores ConfigFiles directly, without the Admin API's
// rules. edit, when set, may change a document before it is stored.
func PutExampleConfig(t testing.TB, docs configuration.Manager, edit func(file string, doc []byte) []byte) {
	t.Helper()
	for _, f := range ConfigFiles {
		data, err := os.ReadFile(filepath.Join(Examples, "config", f))
		if err != nil {
			t.Fatal(err)
		}
		src, err := schema.Read(f, data, "")
		if err != nil {
			t.Fatal(err)
		}
		doc := src[0].JSON
		if edit != nil {
			doc = edit(f, doc)
		}
		var meta struct {
			Metadata struct{ Name string } `json:"metadata"`
		}
		_ = json.Unmarshal(doc, &meta)
		if _, err := docs.Put(context.Background(), string(src[0].Kind), meta.Metadata.Name, doc, "test"); err != nil {
			t.Fatal(err)
		}
	}
}

// Checks lists checks as name:result, space-separated, so a test can
// compare a record's checks with one line.
func Checks(checks []v0.Check) string {
	s := make([]string, len(checks))
	for i, c := range checks {
		s[i] = string(c.Name) + ":" + string(c.Result)
	}
	return strings.Join(s, " ")
}
