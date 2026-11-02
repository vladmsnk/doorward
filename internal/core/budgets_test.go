package core_test

import (
	"fmt"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/core"
)

func TestBudgets(t *testing.T) {
	alice := load[v0.Grant](t, "grant/pay-invoice.json")
	now := time.Date(2026, 10, 31, 23, 59, 0, 0, time.FixedZone("CET", 3600))
	pay := func(amount any) core.Call {
		args := map[string]any{"invoice_id": "inv_1", "currency": "EUR"}
		if amount != nil {
			args["amount"] = amount
		}
		return core.Call{Resource: payments, Action: "pay_invoice", Arguments: args}
	}

	// A payment draws on the monthly payout budget, shared by the consent,
	// and on the grant's call count. The month is the UTC month.
	got, reason := core.Budgets(alice, pay(1200.0), now)
	if reason != nil {
		t.Fatal(reason)
	}
	want := []budget.Draw{
		{Key: "consent:" + alice.Consent + ":payout-month:2026-10", Amount: "1200", Max: "5000"},
		{Key: "grant:" + alice.ID + ":calls", Amount: "1", Max: "50"},
	}
	if fmt.Sprint(core.Draws(got)) != fmt.Sprint(want) {
		t.Errorf("draws %v\nwant  %v", core.Draws(got), want)
	}
	// Amounts are written exactly as JSON gave them.
	got, _ = core.Budgets(alice, pay(0.1), now)
	if got[0].Draw.Amount != "0.1" {
		t.Errorf("0.1 drawn as %s", got[0].Draw.Amount)
	}
	// A read draws only on the call count: the payout budget counts
	// pay_invoice alone.
	got, _ = core.Budgets(alice, core.Call{Resource: payments, Action: "get_invoice", Arguments: map[string]any{"invoice_id": "i"}}, now)
	if len(got) != 1 || got[0].Limit.Name != "calls" {
		t.Errorf("get_invoice draws %v", core.Draws(got))
	}

	// A call that cannot be counted is refused.
	for _, c := range []struct {
		name   string
		amount any
		code   v0.ReasonCode
	}{
		{"no amount", nil, v0.ReasonFieldMissing},
		{"amount as text", "1200", v0.ReasonConstraintViolated},
		{"negative amount", -50.0, v0.ReasonConstraintViolated},
	} {
		if _, reason := core.Budgets(alice, pay(c.amount), now); reason == nil || reason.Code != c.code || reason.Field != "/amount" {
			t.Errorf("%s: %+v", c.name, reason)
		}
	}

	// A daily budget without a consent cannot be keyed, so the call is
	// refused rather than counted nowhere.
	svc := alice
	svc.Consent = ""
	svc.Limits = []v0.Limit{{Name: "daily", Kind: v0.LimitCount, Max: 5, Per: v0.PerDay}}
	if _, reason := core.Budgets(svc, pay(1.0), now); reason == nil || reason.Code != v0.ReasonLimitExceeded {
		t.Errorf("daily budget without a consent: %+v", reason)
	}
}

func TestLimitsCheck(t *testing.T) {
	alice := load[v0.Grant](t, "grant/pay-invoice.json")
	budgets, _ := core.Budgets(alice, core.Call{Resource: payments, Action: "pay_invoice",
		Arguments: map[string]any{"invoice_id": "i", "amount": 1200.0, "currency": "EUR"}}, time.Now())

	// Drawn: the check passes and the record lists each budget.
	check, reason, uses := core.LimitsCheck(budgets, []budget.Drawn{
		{Key: budgets[0].Draw.Key, Amount: "1200", Remaining: "3800"},
		{Key: budgets[1].Draw.Key, Amount: "1", Remaining: "49"},
	}, nil)
	if check.Result != v0.CheckPass || reason != nil || fmt.Sprint(uses) != "[{payout-month 1200 3800} {calls 1 49}]" {
		t.Errorf("drawn: %+v %+v %v", check, reason, uses)
	}

	// Exhausted: the check fails, naming the budget, and nothing is listed
	// as drawn.
	err := &budget.ExhaustedError{Key: budgets[0].Draw.Key, Amount: "1200", Remaining: "1000"}
	check, reason, uses = core.LimitsCheck(budgets, nil, err)
	if check.Result != v0.CheckFail || check.Detail != "payout-month" || uses != nil ||
		reason.Code != v0.ReasonLimitExceeded || reason.Message != "budget payout-month has 1000 left this month; the call needs 1200" {
		t.Errorf("exhausted: %+v %+v %v", check, reason, uses)
	}
}

// After a best-effort draw (observe mode), the first exhausted budget
// fails the check and the others are listed as drawn.
func TestLimitsCheckBestEffort(t *testing.T) {
	alice := load[v0.Grant](t, "grant/pay-invoice.json")
	budgets, _ := core.Budgets(alice, core.Call{Resource: payments, Action: "pay_invoice",
		Arguments: map[string]any{"invoice_id": "i", "amount": 1200.0, "currency": "EUR"}}, time.Now())
	check, reason, uses := core.LimitsCheck(budgets, []budget.Drawn{
		{Key: budgets[0].Draw.Key, Amount: "1200", Remaining: "1000", Exhausted: true},
		{Key: budgets[1].Draw.Key, Amount: "1", Remaining: "49"},
	}, nil)
	if check.Result != v0.CheckFail || check.Detail != "payout-month" || reason.Code != v0.ReasonLimitExceeded ||
		fmt.Sprint(uses) != "[{calls 1 49}]" {
		t.Errorf("%+v %+v %v", check, reason, uses)
	}
}
