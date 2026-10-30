package schema_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/schema"
)

const examples = "../examples/v0"

func newValidator(t *testing.T) *schema.Validator {
	t.Helper()
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// example reads one example file as a single JSON document.
func example(t *testing.T, rel string, kind schema.Kind) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(examples, rel))
	if err != nil {
		t.Fatal(err)
	}
	srcs, err := schema.Read(rel, data, kind)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 {
		t.Fatalf("%s: %d documents, want 1", rel, len(srcs))
	}
	return srcs[0].JSON
}

// F02 "done when": every example passes validation, decodes into its Go type,
// and comes back out of the Go type unchanged and still valid.
func TestExamplesValidateAndRoundTrip(t *testing.T) {
	v := newValidator(t)
	dirs := map[string]schema.Kind{"config": "", "grant": schema.Grant, "decision": schema.Decision}
	seen := map[schema.Kind]int{}

	for dir, kind := range dirs {
		paths, err := filepath.Glob(filepath.Join(examples, dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			srcs, err := schema.Read(p, data, kind)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			for _, src := range srcs {
				t.Run(filepath.Base(src.Name), func(t *testing.T) {
					seen[src.Kind]++
					if err := v.Validate(src.Kind, src.JSON); err != nil {
						t.Fatalf("invalid example:\n%v", err)
					}
					roundTrip(t, v, src)
				})
			}
		}
	}
	for _, k := range schema.Kinds {
		if seen[k] == 0 {
			t.Errorf("no example of kind %s", k)
		}
	}
}

func roundTrip(t *testing.T, v *schema.Validator, src schema.Source) {
	t.Helper()
	var out any
	var err error
	switch src.Kind {
	case schema.Boundary:
		out, err = schema.Decode[v0.Boundary](v, src.JSON)
	case schema.TaskType:
		out, err = schema.Decode[v0.TaskType](v, src.JSON)
	case schema.Manifest:
		out, err = schema.Decode[v0.Manifest](v, src.JSON)
	case schema.Grant:
		out, err = schema.Decode[v0.Grant](v, src.JSON)
	case schema.Decision:
		out, err = schema.Decode[v0.Decision](v, src.JSON)
	}
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	again, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(src.Kind, again); err != nil {
		t.Fatalf("re-encoded document is invalid:\n%v\n%s", err, again)
	}
	var before, after any
	if err := json.Unmarshal(src.JSON, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(again, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("round trip changed the document\nbefore: %s\nafter:  %s", src.JSON, again)
	}
}

// edit is one change to a valid example that must make it invalid.
type edit struct {
	set   string // JSON Pointer to set...
	value any    // ...to this value
	del   string // or JSON Pointer to delete
}

func TestInvalidDocuments(t *testing.T) {
	v := newValidator(t)
	const (
		boundary = "config/boundary-invoice-agent.yaml"
		tasktype = "config/tasktype-pay-invoice.yaml"
		manifest = "config/manifest-payments-api.yaml"
		mcp      = "config/manifest-ledger-mcp.yaml"
		root     = "grant/root-invoice-agent.json"
		child    = "grant/delegated-ledger-agent.json"
		allow    = "decision/1-allow-get-invoice.json"
		deny     = "decision/2-deny-amount-over-grant.json"
		hold     = "decision/3-approval-required-pay-invoice.json"
	)
	cases := []struct {
		name    string
		file    string
		kind    schema.Kind
		edits   []edit
		keyword string // a schema keyword the error must mention
	}{
		// Envelope.
		{"wrong apiVersion", boundary, schema.Boundary, []edit{{set: "/apiVersion", value: "agentbox/v1"}}, "const"},
		{"unknown top-level field", boundary, schema.Boundary, []edit{{set: "/status", value: map[string]any{}}}, "additionalProperties"},
		{"name with upper case", boundary, schema.Boundary, []edit{{set: "/metadata/name", value: "Invoice-Agent"}}, "pattern"},

		// Boundary.
		{"boundary without owner", boundary, schema.Boundary, []edit{{del: "/spec/owner"}}, "required"},
		{"owner contact not an email", boundary, schema.Boundary, []edit{{set: "/spec/owner/contact", value: "on-call"}}, "format"},
		{"max_ttl in words", boundary, schema.Boundary, []edit{{set: "/spec/max_ttl", value: "1 day"}}, "pattern"},
		{"unknown sensitivity tier", boundary, schema.Boundary, []edit{{set: "/spec/max_sensitivity", value: "extreme"}}, "enum"},
		{"empty permissions", boundary, schema.Boundary, []edit{{set: "/spec/permissions", value: []any{}}}, "minItems"},
		{"wildcard action", boundary, schema.Boundary, []edit{{set: "/spec/permissions/0/actions/0", value: "*"}}, "pattern"},
		{"location not a URL", boundary, schema.Boundary, []edit{{set: "/spec/permissions/0/locations/0", value: "payments"}}, "format"},
		{"unknown constraint type", boundary, schema.Boundary, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{"regex": ".*"}}}, "unevaluatedProperties"},
		{"empty constraint", boundary, schema.Boundary, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{}}}, "minProperties"},
		{"constraint key not a pointer", boundary, schema.Boundary, []edit{{set: "/spec/permissions/0/constraints/amount", value: map[string]any{"max": 1}}}, "pattern"},
		{"delegation to anyone", boundary, schema.Boundary, []edit{{del: "/spec/delegation/recipients"}}, "required"},
		{"sum limit without field", boundary, schema.Boundary, []edit{{del: "/spec/limits/0/field"}}, "required"},

		// Task type.
		{"task type without initiators", tasktype, schema.TaskType, []edit{{del: "/spec/initiators"}}, "required"},
		{"empty initiators", tasktype, schema.TaskType, []edit{{set: "/spec/initiators", value: []any{}}}, "minItems"},
		{"unanchored id_pattern", tasktype, schema.TaskType, []edit{{set: "/spec/object/id_pattern", value: "inv_[0-9]+"}}, "pattern"},
		{"id_pattern not a regex", tasktype, schema.TaskType, []edit{{set: "/spec/object/id_pattern", value: "^inv_[0-9+$"}}, "format"},
		{"count limit with a field", tasktype, schema.TaskType, []edit{{set: "/spec/limits/1/field", value: "/amount"}}, "false schema"},
		{"count limit not whole", tasktype, schema.TaskType, []edit{{set: "/spec/limits/1/max", value: 2.5}}, "integer"},
		{"task_object false", tasktype, schema.TaskType, []edit{{set: "/spec/permissions/0/constraints/~1invoice_id/task_object", value: false}}, "const"},

		// Manifest.
		{"http operation without route", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/http"}}, "required"},
		{"http param without location", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/params/~1invoice_id/in"}}, "required"},
		{"operation without tier", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/sensitivity"}}, "required"},
		{"object param", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1invoice_id/type", value: "object"}}, "enum"},
		{"unknown protocol", manifest, schema.Manifest, []edit{{set: "/spec/protocol", value: "grpc"}}, "enum"},
		{"mcp operation with a route", mcp, schema.Manifest, []edit{{set: "/spec/operations/0/http", value: map[string]any{"method": "GET", "path": "/"}}}, "false schema"},
		{"mcp param with a location", mcp, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1account_id/in", value: "body"}}, "false schema"},

		// Grant.
		{"grant without act", root, schema.Grant, []edit{{del: "/act"}}, "required"},
		{"grant without task", root, schema.Grant, []edit{{del: "/task"}}, "required"},
		{"grant without flow", root, schema.Grant, []edit{{del: "/flow"}}, "required"},
		{"aud as a string", root, schema.Grant, []edit{{set: "/aud", value: "https://payments.example.internal"}}, "type"},
		{"empty aud", root, schema.Grant, []edit{{set: "/aud", value: []any{}}}, "minItems"},
		{"exp as a date string", root, schema.Grant, []edit{{set: "/exp", value: "2026-10-30T10:00:00Z"}}, "type"},
		{"short key thumbprint", root, schema.Grant, []edit{{set: "/cnf/jkt", value: "abc"}}, "pattern"},
		{"unknown claim", root, schema.Grant, []edit{{set: "/scope", value: "payments"}}, "additionalProperties"},
		{"unresolved task_object", root, schema.Grant, []edit{{set: "/authorization_details/0/constraints/~1invoice_id", value: map[string]any{"task_object": true}}}, "unevaluatedProperties"},
		{"authorization detail without type", root, schema.Grant, []edit{{del: "/authorization_details/0/type"}}, "required"},
		{"foreign authorization detail type", root, schema.Grant, []edit{{set: "/authorization_details/0/type", value: "payment_initiation"}}, "const"},
		{"root grant with a parent", root, schema.Grant, []edit{{set: "/parent", value: "grt_01JBXR4T7Q2M9X4KZ8D3F6H1ZZ"}}, "not"},
		{"child grant without a parent", child, schema.Grant, []edit{{del: "/parent"}}, "required"},
		{"chain too deep", child, schema.Grant, []edit{{set: "/depth", value: 9}}, "maximum"},
		{"actor name with spaces", child, schema.Grant, []edit{{set: "/act/act/sub", value: "invoice agent"}}, "pattern"},

		// Decision.
		{"unknown outcome", allow, schema.Decision, []edit{{set: "/outcome", value: "maybe"}}, "enum"},
		{"allow without principal", allow, schema.Decision, []edit{{del: "/principal"}}, "required"},
		{"allow without grant", allow, schema.Decision, []edit{{del: "/grant"}}, "required"},
		{"allow without action hash", allow, schema.Decision, []edit{{del: "/action_hash"}}, "required"},
		{"no checks", allow, schema.Decision, []edit{{set: "/checks", value: []any{}}}, "minItems"},
		{"no point of enforcement", allow, schema.Decision, []edit{{del: "/pep"}}, "required"},
		{"no point of decision", allow, schema.Decision, []edit{{del: "/pdp"}}, "required"},
		{"request without subject", allow, schema.Decision, []edit{{del: "/request/subject"}}, "required"},
		{"time not RFC 3339", allow, schema.Decision, []edit{{set: "/time", value: "30.10.2026 09:30"}}, "format"},
		{"time without milliseconds", allow, schema.Decision, []edit{{set: "/time", value: "2026-10-30T09:30:12Z"}}, "pattern"},
		{"time with an offset", allow, schema.Decision, []edit{{set: "/time", value: "2026-10-30T11:30:12.418+02:00"}}, "pattern"},
		{"malformed action hash", allow, schema.Decision, []edit{{set: "/action_hash", value: "md5:abc"}}, "pattern"},
		{"first record with prev", allow, schema.Decision, []edit{{set: "/chain/prev", value: "sha-256:example-hash-not-computed-record-0000000000"}}, "not"},
		{"later record without prev", deny, schema.Decision, []edit{{del: "/chain/prev"}}, "required"},
		{"deny without reasons", deny, schema.Decision, []edit{{del: "/reasons"}}, "required"},
		{"deny with empty reasons", deny, schema.Decision, []edit{{set: "/reasons", value: []any{}}}, "minItems"},
		{"deny spends budget", deny, schema.Decision, []edit{{set: "/limits", value: []any{map[string]any{"name": "calls", "consumed": 1, "remaining": 49}}}}, "false schema"},
		{"unknown reason code", deny, schema.Decision, []edit{{set: "/reasons/0/code", value: "too_expensive"}}, "anyOf"},
		{"hold without approval request", hold, schema.Decision, []edit{{del: "/approval"}}, "required"},
		{"hold spends budget", hold, schema.Decision, []edit{{set: "/limits", value: []any{map[string]any{"name": "calls", "consumed": 1, "remaining": 49}}}}, "false schema"},
		{"unknown check", hold, schema.Decision, []edit{{set: "/checks/0/name", value: "vibes"}}, "enum"},
		{"unknown enforcement point kind", hold, schema.Decision, []edit{{set: "/pep/kind", value: "firewall"}}, "enum"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := applyEdits(t, example(t, tc.file, tc.kind), tc.edits)
			err := v.Validate(tc.kind, doc)
			if err == nil {
				t.Fatalf("document was accepted:\n%s", doc)
			}
			var verr *jsonschema.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("want a schema validation error, got %v", err)
			}
			if msg := verr.Error() + flatten(*verr.DetailedOutput()); !strings.Contains(msg, tc.keyword) {
				t.Errorf("error does not mention %q:\n%s", tc.keyword, msg)
			}
		})
	}
}

// A custom reason code is fine as long as it says it is one.
func TestCustomReasonCode(t *testing.T) {
	v := newValidator(t)
	doc := applyEdits(t, example(t, "decision/2-deny-amount-over-grant.json", schema.Decision),
		[]edit{{set: "/reasons/0/code", value: "x-fraud_score"}})
	if err := v.Validate(schema.Decision, doc); err != nil {
		t.Fatalf("custom code rejected: %v", err)
	}
}

func flatten(u jsonschema.OutputUnit) string {
	var b strings.Builder
	b.WriteString(u.KeywordLocation)
	b.WriteString(" ")
	if u.Error != nil {
		b.WriteString(u.Error.String())
	}
	for _, e := range u.Errors {
		b.WriteString("\n")
		b.WriteString(flatten(e))
	}
	return b.String()
}

func applyEdits(t *testing.T, doc []byte, edits []edit) []byte {
	t.Helper()
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatal(err)
	}
	for _, e := range edits {
		if e.del != "" {
			root = patch(t, root, e.del, nil, true)
		} else {
			root = patch(t, root, e.set, e.value, false)
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// patch sets or deletes the value at a JSON Pointer.
func patch(t *testing.T, node any, pointer string, value any, del bool) any {
	t.Helper()
	parts := strings.Split(pointer, "/")[1:]
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	var walk func(node any, parts []string) any
	walk = func(node any, parts []string) any {
		key := parts[0]
		last := len(parts) == 1
		switch n := node.(type) {
		case map[string]any:
			if last {
				if del {
					if _, ok := n[key]; !ok {
						t.Fatalf("%s: nothing to delete", pointer)
					}
					delete(n, key)
				} else {
					n[key] = value
				}
				return n
			}
			child, ok := n[key]
			if !ok {
				t.Fatalf("%s: no member %q", pointer, key)
			}
			n[key] = walk(child, parts[1:])
			return n
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(n) {
				t.Fatalf("%s: bad index %q", pointer, key)
			}
			if last {
				if del {
					return append(n[:i], n[i+1:]...)
				}
				n[i] = value
				return n
			}
			n[i] = walk(n[i], parts[1:])
			return n
		default:
			t.Fatalf("%s: cannot descend into %T", pointer, node)
			return nil
		}
	}
	return walk(node, parts)
}

func TestDuplicateKeysAreRejected(t *testing.T) {
	v := newValidator(t)

	// The second "sub" would win in encoding/json; neither may win.
	grant := example(t, "grant/root-invoice-agent.json", schema.Grant)
	forged := strings.Replace(string(grant), `"sub":`, `"sub":"mallory@example.com","sub":`, 1)
	if err := v.Validate(schema.Grant, []byte(forged)); err == nil || !strings.Contains(err.Error(), `duplicate key "sub"`) {
		t.Errorf("duplicate sub in a grant: got %v", err)
	}

	nested := `{"a":{"b":[{"c":1,"c":2}]}}`
	if err := schema.CheckDuplicateKeys([]byte(nested)); err == nil || !strings.Contains(err.Error(), `"/a/b/0"`) {
		t.Errorf("nested duplicate: got %v", err)
	}

	yamlDoc := "apiVersion: agentbox/v0\nkind: Boundary\nkind: TaskType\n"
	if _, err := schema.Read("x.yaml", []byte(yamlDoc), ""); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("duplicate YAML key: got %v", err)
	}
}

func TestTrailingDataIsRejected(t *testing.T) {
	if err := schema.CheckDuplicateKeys([]byte(`{"a":1} {"a":2}`)); err == nil {
		t.Error("two JSON values accepted as one document")
	}
}

func TestReadMultiDocumentYAML(t *testing.T) {
	var all []byte
	for _, f := range []string{"boundary-invoice-agent.yaml", "tasktype-pay-invoice.yaml"} {
		data, err := os.ReadFile(filepath.Join(examples, "config", f))
		if err != nil {
			t.Fatal(err)
		}
		all = append(append(all, "---\n"...), data...)
	}
	srcs, err := schema.Read("bundle.yaml", all, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 || srcs[0].Kind != schema.Boundary || srcs[1].Kind != schema.TaskType {
		t.Fatalf("got %+v", srcs)
	}
	if srcs[1].Name != "bundle.yaml#2" {
		t.Errorf("name %q", srcs[1].Name)
	}
}

func TestReadKindResolution(t *testing.T) {
	boundary := []byte(`{"apiVersion":"agentbox/v0","kind":"Boundary"}`)
	grant := []byte(`{"jti":"grt_0000000000"}`)

	if _, err := schema.Read("g.json", grant, ""); err == nil {
		t.Error("grant without --kind accepted")
	}
	if srcs, err := schema.Read("g.json", grant, schema.Grant); err != nil || srcs[0].Kind != schema.Grant {
		t.Errorf("grant with kind: %v %+v", err, srcs)
	}
	if _, err := schema.Read("b.json", boundary, schema.TaskType); err == nil {
		t.Error("Boundary read as TaskType")
	}
	for _, k := range []string{"boundary", "Grant", "Policy"} {
		doc := []byte(`{"kind":"` + k + `"}`)
		if _, err := schema.Read("k.json", doc, ""); err == nil {
			t.Errorf("kind %q accepted as a configuration kind", k)
		}
	}
}

func TestDecodeRejectsAnInvalidDocument(t *testing.T) {
	v := newValidator(t)
	doc := applyEdits(t, example(t, "grant/root-invoice-agent.json", schema.Grant), []edit{{del: "/act"}})
	if _, err := schema.Decode[v0.Grant](v, doc); err == nil {
		t.Fatal("Decode accepted a grant without act")
	}
}

func TestParseKind(t *testing.T) {
	for in, want := range map[string]schema.Kind{"grant": schema.Grant, "TASKTYPE": schema.TaskType, "Decision": schema.Decision} {
		if got, err := schema.ParseKind(in); err != nil || got != want {
			t.Errorf("ParseKind(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := schema.ParseKind("task-type"); err == nil {
		t.Error("ParseKind accepted task-type")
	}
}
