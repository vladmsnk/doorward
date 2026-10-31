package core_test

import (
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/core"
)

func TestSensitivity(t *testing.T) {
	w := newWorld(t)
	op := func(res, name string) v0.Operation { return *core.Operation(w.manifests[res], name) }
	pay := core.Call{Resource: payments, Action: "pay_invoice", Arguments: map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": 1200.0, "currency": "EUR"}}
	payHash, err := pay.Hash()
	if err != nil {
		t.Fatal(err)
	}
	other := pay
	other.Arguments = map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": 1201.0, "currency": "EUR"}
	otherHash, _ := other.Hash()
	once := core.Binding{SingleUse: true, ActionHash: payHash}

	type want struct {
		result v0.CheckResult
		code   v0.ReasonCode
		hold   bool
		detail string
	}
	cases := []struct {
		name    string
		op      v0.Operation
		ceiling v0.Sensitivity
		binding core.Binding
		hash    string
		want    want
	}{
		{"read", op(payments, "get_invoice"), v0.SensitivityCritical, core.Binding{}, "h", want{v0.CheckPass, "", false, ""}},
		{"write", op(ledger, "post_entry"), v0.SensitivityCritical, core.Binding{}, "h", want{v0.CheckPass, "", false, ""}},
		// The third example record: a critical call on a standing grant.
		{"critical on a standing grant", op(payments, "pay_invoice"), v0.SensitivityCritical, core.Binding{}, payHash,
			want{v0.CheckFail, "", true, "critical tier needs a single-use grant"}},
		{"critical on its single-use grant", op(payments, "pay_invoice"), v0.SensitivityCritical, once, payHash,
			want{v0.CheckPass, "", false, "single-use grant for this exact call"}},
		{"single-use grant, one cent more", op(payments, "pay_invoice"), v0.SensitivityCritical, once, otherHash,
			want{v0.CheckFail, v0.ReasonActionNotGranted, false, "this single-use grant was issued for another call"}},
		{"single-use grant, a read", op(payments, "get_invoice"), v0.SensitivityCritical, once, "sha-256:x",
			want{v0.CheckFail, v0.ReasonActionNotGranted, false, "this single-use grant was issued for another call"}},
		{"single-use grant with no hash", op(payments, "pay_invoice"), v0.SensitivityCritical, core.Binding{SingleUse: true}, "",
			want{v0.CheckFail, v0.ReasonActionNotGranted, false, "this single-use grant was issued for another call"}},
		// The agent's ceiling was lowered after the grant was issued.
		{"critical above a write ceiling", op(payments, "pay_invoice"), v0.SensitivityWrite, once, payHash,
			want{v0.CheckFail, v0.ReasonSensitivityExceeded, false, "pay_invoice is critical, above the agent's ceiling of write"}},
		{"write above a read ceiling", op(ledger, "post_entry"), v0.SensitivityRead, core.Binding{}, "h",
			want{v0.CheckFail, v0.ReasonSensitivityExceeded, false, "post_entry is write, above the agent's ceiling of read"}},
		{"unknown ceiling", op(payments, "get_invoice"), "", core.Binding{}, "h",
			want{v0.CheckFail, v0.ReasonSensitivityExceeded, false, `the agent's ceiling "" is not a tier`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check, reason, hold := core.Sensitivity(c.op, c.ceiling, c.binding, c.hash)
			got := want{check.Result, "", hold, check.Detail}
			if reason != nil {
				got.code = reason.Code
			}
			if check.Name != v0.CheckSensitivity || got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
			if hold && reason != nil {
				t.Error("a held call carries no reason: it is not refused")
			}
		})
	}
}
