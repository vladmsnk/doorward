package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/policy"
	"github.com/vladmsnk/doorward/schema"
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
	c, err := policy.Tighten(v0.Constraint{Max: f(100), OneOf: []any{1.0, 20.0, 70.0}}, v0.Constraint{Max: f(50), Min: f(1), OneOf: []any{20.0, 70.0, 80.0}})
	if err != nil || *c.Max != 50 || *c.Min != 1 || len(c.OneOf) != 2 {
		t.Errorf("Tighten: %+v %v", c, err)
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

// P1: bounds that cannot all hold allow nothing. Before the fix, two
// disjoint one_of lists combined into no list at all, which read as "any
// value", and conflicting equals or prefixes kept whichever came second.
func TestContradictionsAreUnsatisfiable(t *testing.T) {
	cases := []struct {
		name string
		a, b v0.Constraint
		why  string
	}{
		{"disjoint one_of", v0.Constraint{OneOf: []any{"EUR"}}, v0.Constraint{OneOf: []any{"USD"}}, "no value in common"},
		{"two equals", v0.Constraint{Equals: "acc_1"}, v0.Constraint{Equals: "acc_2"}, "equals acc_1 and equals acc_2"},
		{"diverging prefixes", v0.Constraint{Prefix: s("acme/")}, v0.Constraint{Prefix: s("other/")}, "diverge"},
		{"min above max", v0.Constraint{Max: f(10)}, v0.Constraint{Min: f(20)}, "min 20 is above max 10"},
		{"equals outside one_of", v0.Constraint{OneOf: []any{"EUR", "USD"}}, v0.Constraint{Equals: "GBP"}, "does not meet the other bounds"},
		{"one_of outside max", v0.Constraint{Max: f(5)}, v0.Constraint{OneOf: []any{10.0, 20.0}}, "no value of one_of"},
		{"number and prefix", v0.Constraint{Max: f(5)}, v0.Constraint{Prefix: s("a")}, "no value is both"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := policy.Tighten(c.a, c.b)
			if err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("Tighten = %+v, %v; want an error saying %q", got, err, c.why)
			}
			// Order does not matter.
			if _, err := policy.Tighten(c.b, c.a); err == nil {
				t.Error("unsatisfiable one way round only")
			}
		})
	}
	// Compatible prefixes keep the longer, in either order.
	for _, pair := range [][2]string{{"acme/", "acme/payments/"}, {"acme/payments/", "acme/"}} {
		c, err := policy.Tighten(v0.Constraint{Prefix: s(pair[0])}, v0.Constraint{Prefix: s(pair[1])})
		if err != nil || *c.Prefix != "acme/payments/" {
			t.Errorf("prefixes %v: %+v %v", pair, c, err)
		}
	}
	// One document's own constraint can contradict itself too.
	if err := policy.Admits(v0.Constraint{Min: f(10), Max: f(5)}); err == nil {
		t.Error("min above max admitted")
	}
	if err := policy.Admits(v0.Constraint{Min: f(1), Max: f(5), OneOf: []any{3.0, 9.0}}); err != nil {
		t.Errorf("satisfiable constraint refused: %v", err)
	}
}

func TestEffectiveAndCoherent(t *testing.T) {
	const loc = "https://payments.example.internal"
	perms := []v0.Permission{
		{Locations: []string{loc}, Actions: []string{"pay_invoice", "get_invoice"}, Constraints: map[string]v0.Constraint{"/currency": {OneOf: []any{"EUR"}}}},
		{Locations: []string{loc}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/currency": {OneOf: []any{"USD"}}}},
	}
	_, err := policy.Effective(perms, loc, "pay_invoice")
	var u *policy.Unsatisfiable
	if !errors.As(err, &u) || u.Field != "/currency" {
		t.Fatalf("Effective: %v", err)
	}
	if b, err := policy.Effective(perms, loc, "get_invoice"); err != nil || len(b["/currency"].OneOf) != 1 {
		t.Errorf("get_invoice: %+v %v", b, err)
	}
	p := policy.Coherent(perms, "mandate m")
	if len(p) != 1 || !strings.Contains(p[0], "mandate m allows pay_invoice at "+loc+", but the bounds on /currency cannot all hold") {
		t.Errorf("Coherent: %q", p)
	}
}

// P2: the old example grant listed pay_invoice unbounded in one entry and
// bounded in another. Merged, pay_invoice carries its bounds in a single
// entry, and nothing else changes.
func TestOnePerOperation(t *testing.T) {
	const pay = "https://payments.example.internal"
	amount := v0.Constraint{Min: f(0.01), Max: f(5000)}
	currency := v0.Constraint{OneOf: []any{"EUR", "USD"}}
	old := []v0.Permission{
		{Locations: []string{pay}, Actions: []string{"get_invoice", "list_payments", "pay_invoice"}},
		{Locations: []string{pay}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/amount": amount, "/currency": currency}},
	}
	got, err := policy.OnePerOperation(old)
	if err != nil {
		t.Fatal(err)
	}
	want := []v0.Permission{
		{Locations: []string{pay}, Actions: []string{"get_invoice", "list_payments"}},
		{Locations: []string{pay}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/amount": amount, "/currency": currency}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	// It allows exactly what the input allows, both ways round.
	if p := policy.Within(got, "merged", old, "old", nil); p != nil {
		t.Errorf("merged is wider: %v", p)
	}
	if p := policy.Within(old, "old", got, "merged", nil); p != nil {
		t.Errorf("merged is narrower: %v", p)
	}
	// Contradictory bounds cannot be merged into a grant.
	bad := append(old, v0.Permission{Locations: []string{pay}, Actions: []string{"pay_invoice"}, Constraints: map[string]v0.Constraint{"/currency": {OneOf: []any{"GBP"}}}})
	if _, err := policy.OnePerOperation(bad); err == nil {
		t.Error("merged bounds that cannot hold")
	}
}
