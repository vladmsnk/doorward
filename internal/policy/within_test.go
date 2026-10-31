package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/policy"
	"github.com/vladmsnk/agentbox/schema"
)

func f(x float64) *float64 { return &x }
func s(x string) *string   { return &x }

func load[T schema.Document](t *testing.T, rel string) T {
	t.Helper()
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("../../examples/v0/config", rel))
	if err != nil {
		t.Fatal(err)
	}
	srcs, err := schema.Read(rel, data, "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := schema.Decode[T](v, srcs[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The example mandates lie within the example agents, as the Admin API will
// require.
func TestExamplesAreWithin(t *testing.T) {
	invoices := load[v0.Mandate](t, "mandate-invoices.yaml")
	assistant := load[v0.Agent](t, "agent-invoice-assistant.yaml")
	// The payments API has /amount only on pay_invoice and refund_payment.
	declared := func(loc, act, field string) bool {
		return field != "/amount" || act == "pay_invoice" || act == "refund_payment" || act == "post_entry" || act == "write_off"
	}
	if p := policy.Within(invoices.Spec.Permissions, "mandate invoices", assistant.Spec.Permissions, "agent invoice-assistant", declared); p != nil {
		t.Errorf("invoices within invoice-assistant: %v", p)
	}
	reconcile := load[v0.Mandate](t, "mandate-reconcile.yaml")
	reconciler := load[v0.Agent](t, "agent-reconciler.yaml")
	if p := policy.Within(reconcile.Spec.Permissions, "mandate reconcile", reconciler.Spec.Permissions, "agent reconciler", declared); p != nil {
		t.Errorf("reconcile within reconciler: %v", p)
	}
}

func TestWithinFindsEveryWidening(t *testing.T) {
	pay := "https://payments.example.internal"
	agent := []v0.Permission{{
		Locations: []string{pay},
		Actions:   []string{"get_invoice", "pay_invoice"},
		Constraints: map[string]v0.Constraint{
			"/amount":   {Max: f(10000)},
			"/currency": {OneOf: []any{"EUR", "USD", "GBP"}},
			"/payee":    {Prefix: s("acme-")},
		},
	}}
	cases := []struct {
		name    string
		mandate []v0.Permission
		want    string // "" means within
	}{
		{"tighter on every field", []v0.Permission{{Locations: []string{pay}, Actions: []string{"pay_invoice"},
			Constraints: map[string]v0.Constraint{"/amount": {Max: f(5000)}, "/currency": {OneOf: []any{"EUR"}}, "/payee": {Prefix: s("acme-eu-")}}}}, ""},
		{"equals inside the bounds", []v0.Permission{{Locations: []string{pay}, Actions: []string{"pay_invoice"},
			Constraints: map[string]v0.Constraint{"/amount": {Equals: 100.0}, "/currency": {Equals: "USD"}, "/payee": {Equals: "acme-ltd"}}}}, ""},
		{"operation the agent lacks", []v0.Permission{{Locations: []string{pay}, Actions: []string{"refund_payment"}}}, "allows refund_payment"},
		{"location the agent lacks", []v0.Permission{{Locations: []string{"https://ledger.example.internal/mcp"}, Actions: []string{"get_invoice"}}}, "which agent does not"},
		{"amount unbounded", []v0.Permission{{Locations: []string{pay}, Actions: []string{"pay_invoice"},
			Constraints: map[string]v0.Constraint{"/currency": {OneOf: []any{"EUR"}}, "/payee": {Prefix: s("acme-")}}}}, "leaves /amount of pay_invoice unbounded"},
		{"amount above the ceiling", []v0.Permission{{Locations: []string{pay}, Actions: []string{"pay_invoice"},
			Constraints: map[string]v0.Constraint{"/amount": {Max: f(50000)}, "/currency": {OneOf: []any{"EUR"}}, "/payee": {Prefix: s("acme-")}}}}, "at or below 10000"},
		{"currency outside the list", []v0.Permission{{Locations: []string{pay}, Actions: []string{"pay_invoice"},
			Constraints: map[string]v0.Constraint{"/amount": {Max: f(10)}, "/currency": {OneOf: []any{"EUR", "JPY"}}, "/payee": {Prefix: s("acme-")}}}}, "must be one of"},
		{"prefix not under the agent's", []v0.Permission{{Locations: []string{pay}, Actions: []string{"pay_invoice"},
			Constraints: map[string]v0.Constraint{"/amount": {Max: f(10)}, "/currency": {Equals: "EUR"}, "/payee": {Prefix: s("globex-")}}}}, `must start with "acme-"`},
		{"two entries whose combination is tight enough", []v0.Permission{
			{Locations: []string{pay}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/amount": {Max: f(10)}}},
			{Locations: []string{pay}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/currency": {Equals: "EUR"}, "/payee": {Prefix: s("acme-x")}}},
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Within(tc.mandate, "mandate", agent, "agent", nil)
			if tc.want == "" && got != nil {
				t.Fatalf("unexpected problems: %v", got)
			}
			if tc.want != "" && (got == nil || !strings.Contains(strings.Join(got, "\n"), tc.want)) {
				t.Fatalf("want %q, got %v", tc.want, got)
			}
		})
	}
}

func TestTightenAndSatisfies(t *testing.T) {
	c := policy.Tighten(v0.Constraint{Max: f(100), OneOf: []any{"a", "b", "c"}}, v0.Constraint{Max: f(50), Min: f(1), OneOf: []any{"b", "c", "d"}})
	if *c.Max != 50 || *c.Min != 1 || len(c.OneOf) != 2 {
		t.Errorf("Tighten: %+v", c)
	}
	amount := v0.Constraint{Min: f(0.01), Max: f(5000)}
	for v, ok := range map[any]bool{1200.0: true, 7500.0: false, 0.0: false, "lots": false} {
		if err := policy.Satisfies(amount, v); (err == nil) != ok {
			t.Errorf("Satisfies(%v) = %v", v, err)
		}
	}
	if policy.Satisfies(amount, nil) == nil {
		t.Error("missing constrained argument accepted")
	}
	if policy.Satisfies(v0.Constraint{Equals: 5.0}, 5) != nil {
		t.Error("int 5 should equal 5.0")
	}
}
