package core_test

import (
	"os"
	"path/filepath"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/core"
	"github.com/vladmsnk/doorward/schema"
)

const (
	payments = "https://payments.example.internal"
	ledger   = "https://ledger.example.internal/mcp"
)

func load[T schema.Document](t *testing.T, rel string) T {
	t.Helper()
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("../../examples/v0", rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src, err := schema.Read(path, data, schema.KindOf[T]())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := schema.Decode[T](v, src[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

type world struct {
	manifests map[string]v0.Manifest
}

func newWorld(t *testing.T) world {
	return world{manifests: map[string]v0.Manifest{
		payments: load[v0.Manifest](t, "config/manifest-payments-api.yaml"),
		ledger:   load[v0.Manifest](t, "config/manifest-ledger-mcp.yaml"),
	}}
}

func (w world) subset(g v0.Grant, call core.Call) (v0.Check, *v0.Reason) {
	return core.Subset(g, core.Operation(w.manifests[call.Resource], call.Action), call)
}

func TestSubsetExamples(t *testing.T) {
	w := newWorld(t)
	alice := load[v0.Grant](t, "grant/pay-invoice.json")
	reconciler := load[v0.Grant](t, "grant/reconcile.json")

	cases := []struct {
		name   string
		grant  v0.Grant
		call   core.Call
		code   v0.ReasonCode // empty: inside the grant
		field  string
		detail string
	}{
		// The calls of the four example decision records.
		{"read an invoice", alice, core.Call{payments, "get_invoice", map[string]any{"invoice_id": "inv_7Q2M9X4K"}}, "", "", ""},
		{"pay 1200 EUR", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": 1200.0, "currency": "EUR"}}, "", "", ""},
		{"pay 7500 EUR", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": 7500.0, "currency": "EUR"}},
			v0.ReasonConstraintViolated, "/amount", "7500 is above the grant's max of 5000"},
		{"post an entry", reconciler, core.Call{ledger, "post_entry", map[string]any{"account_id": "acc_EU_448120", "amount": 240.5, "memo": "payment pmt_8K2"}}, "", "", ""},

		// The currency bound holds too.
		{"pay in GBP", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "i", "amount": 10.0, "currency": "GBP"}},
			v0.ReasonConstraintViolated, "/currency", `"GBP" is not one of the grant's ["EUR","USD"]`},
		{"pay nothing", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "i", "amount": 0.0, "currency": "EUR"}},
			v0.ReasonConstraintViolated, "/amount", "0 is below the grant's min of 0.01"},
		{"pay without an amount", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "i", "currency": "EUR"}},
			v0.ReasonFieldMissing, "/amount", "/amount is bounded by the grant but missing from the call"},
		{"pay a null amount", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "i", "amount": nil, "currency": "EUR"}},
			v0.ReasonFieldMissing, "/amount", "/amount is bounded by the grant but missing from the call"},
		{"amount as a string", alice, core.Call{payments, "pay_invoice", map[string]any{"invoice_id": "i", "amount": "100", "currency": "EUR"}},
			v0.ReasonConstraintViolated, "/amount", `"100" is a string, but the manifest declares number`},

		// Operations the grant does not name, or names elsewhere.
		{"refund", alice, core.Call{payments, "refund_payment", map[string]any{"payment_id": "p", "amount": 1.0}},
			v0.ReasonActionNotGranted, "", "the grant does not allow refund_payment at " + payments},
		{"right name, wrong resource", alice, core.Call{ledger, "get_invoice", nil},
			v0.ReasonActionNotGranted, "", "the grant does not allow get_invoice at " + ledger},
		{"write off 5000", reconciler, core.Call{ledger, "write_off", map[string]any{"payment_id": "p", "amount": 5000.0, "reason": "x"}},
			v0.ReasonConstraintViolated, "/amount", "5000 is above the grant's max of 1000"},
		// Reads with no bounds take any arguments.
		{"list unmatched", reconciler, core.Call{ledger, "list_unmatched", map[string]any{"day": "2026-10-30"}}, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check, reason := w.subset(c.grant, c.call)
			if check.Name != v0.CheckSubset {
				t.Fatalf("check %s", check.Name)
			}
			if c.code == "" {
				if check.Result != v0.CheckPass || reason != nil {
					t.Fatalf("refused: %+v %+v", check, reason)
				}
				return
			}
			if check.Result != v0.CheckFail || reason == nil {
				t.Fatalf("accepted: %+v", check)
			}
			if reason.Code != c.code || reason.Field != c.field || reason.Message != c.detail {
				t.Errorf("got %s %q %q\nwant %s %q %q", reason.Code, reason.Field, reason.Message, c.code, c.field, c.detail)
			}
			if c.field != "" && check.Detail != c.field {
				t.Errorf("check detail %q, want the field", check.Detail)
			}
		})
	}
}

func TestSubsetUnknownOperation(t *testing.T) {
	// The grant names an operation the manifest no longer has.
	g := load[v0.Grant](t, "grant/pay-invoice.json")
	_, reason := core.Subset(g, nil, core.Call{payments, "get_invoice", nil})
	if reason == nil || reason.Code != v0.ReasonActionNotGranted || reason.Message != "the manifest of "+payments+" declares no operation get_invoice" {
		t.Fatalf("%+v", reason)
	}
}

func ptr[T any](v T) *T { return &v }

func TestSubsetUndeclaredAndNestedArguments(t *testing.T) {
	g := v0.Grant{AuthorizationDetails: []v0.AuthorizationDetail{{
		Type: "tool_call", Locations: []string{payments}, Actions: []string{"get_invoice", "pay"},
		Constraints: map[string]v0.Constraint{
			"/amount":     {Max: ptr(100.0)},
			"/payee/iban": {Prefix: ptr("DE")},
			"/tags/0":     {Equals: "urgent"},
			"/a~1b":       {OneOf: []any{true}},
			"/count":      {Max: ptr(3.0)},
		},
	}}}
	getInvoice := &v0.Operation{Name: "get_invoice", Params: map[string]v0.Param{"/invoice_id": {Type: v0.ParamString}}}
	pay := &v0.Operation{Name: "pay", Params: map[string]v0.Param{
		"/amount":     {Type: v0.ParamNumber},
		"/payee/iban": {Type: v0.ParamString},
		"/count":      {Type: v0.ParamInteger},
	}}
	ok := map[string]any{"amount": 50.0, "payee": map[string]any{"iban": "DE89"}, "count": 2.0}

	cases := []struct {
		name  string
		op    *v0.Operation
		args  map[string]any
		field string // empty: accepted
	}{
		// get_invoice declares no amount: the entry's bounds do not apply...
		{"undeclared bound, absent", getInvoice, map[string]any{"invoice_id": "i"}, ""},
		// ...unless the agent sends the argument anyway.
		{"undeclared bound, sent and breaking it", getInvoice, map[string]any{"invoice_id": "i", "amount": 1e6}, "/amount"},
		{"undeclared bound, sent within it", getInvoice, map[string]any{"invoice_id": "i", "amount": 1.0}, ""},
		{"nested within", pay, ok, ""},
		{"nested outside", pay, map[string]any{"amount": 50.0, "payee": map[string]any{"iban": "FR76"}, "count": 2.0}, "/payee/iban"},
		{"nested missing", pay, map[string]any{"amount": 50.0, "payee": map[string]any{}, "count": 2.0}, "/payee/iban"},
		{"nested under a string", pay, map[string]any{"amount": 50.0, "payee": "DE89", "count": 2.0}, "/payee/iban"},
		{"array element", pay, map[string]any{"amount": 50.0, "payee": map[string]any{"iban": "DE"}, "count": 2.0, "tags": []any{"later"}}, "/tags/0"},
		{"escaped pointer", pay, map[string]any{"amount": 50.0, "payee": map[string]any{"iban": "DE"}, "count": 2.0, "a/b": false}, "/a~1b"},
		{"integer with a fraction", pay, map[string]any{"amount": 50.0, "payee": map[string]any{"iban": "DE"}, "count": 2.5}, "/count"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check, reason := core.Subset(g, c.op, core.Call{payments, c.op.Name, c.args})
			switch {
			case c.field == "" && reason != nil:
				t.Errorf("refused: %+v", reason)
			case c.field != "" && (reason == nil || reason.Field != c.field):
				t.Errorf("want a refusal on %s, got %+v %+v", c.field, check, reason)
			}
		})
	}
}

// P1: a grant whose entries bound one argument in contradictory ways allows
// no call. Before the fix, EUR in one entry and USD in another combined into
// no bound at all, and any currency passed.
func TestSubsetContradictoryEntries(t *testing.T) {
	g := v0.Grant{AuthorizationDetails: []v0.AuthorizationDetail{
		{Type: "tool_call", Locations: []string{payments}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/currency": {OneOf: []any{"EUR"}}}},
		{Type: "tool_call", Locations: []string{payments}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/currency": {OneOf: []any{"USD"}}}},
	}}
	w := newWorld(t)
	for _, cur := range []string{"EUR", "USD", "GBP"} {
		check, reason := w.subset(g, core.Call{Resource: payments, Action: "pay_invoice", Arguments: map[string]any{"invoice_id": "i", "amount": 10.0, "currency": cur}})
		if reason == nil || reason.Code != v0.ReasonConstraintViolated || reason.Field != "/currency" || check.Result != v0.CheckFail {
			t.Errorf("%s: %+v %+v", cur, check, reason)
		}
	}
}
