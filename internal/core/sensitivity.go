package core

import (
	"fmt"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/policy"
)

// Binding says what kind of grant the call came with. A standing grant
// has the zero Binding; a single-use grant was issued for one approved call
// and carries that call's hash.
type Binding struct {
	SingleUse  bool
	ActionHash string
}

// Sensitivity is the sensitivity check (B3): how risky the operation is,
// and whether this grant may run it.
//
//   - An operation above the agent's ceiling (its max_sensitivity, as it
//     stands now) is refused, whatever the grant says.
//   - A single-use grant runs only the call it was issued for: any other
//     call is refused, whatever its tier.
//   - A critical operation never runs on a standing grant. The call is held
//     (hold is true): a person approves this exact call, and the box issues
//     a single-use grant bound to its hash.
//   - read and write run.
//
// actionHash is the call's hash, Call.Hash.
func Sensitivity(op v0.Operation, ceiling v0.Sensitivity, b Binding, actionHash string) (check v0.Check, reason *v0.Reason, hold bool) {
	if !known(ceiling) {
		return deny(v0.ReasonSensitivityExceeded, fmt.Sprintf("the agent's ceiling %q is not a tier", ceiling))
	}
	if policy.Tier(op.Sensitivity) > policy.Tier(ceiling) {
		return deny(v0.ReasonSensitivityExceeded, fmt.Sprintf("%s is %s, above the agent's ceiling of %s", op.Name, op.Sensitivity, ceiling))
	}
	if b.SingleUse {
		if b.ActionHash == "" || b.ActionHash != actionHash {
			return deny(v0.ReasonActionNotGranted, "this single-use grant was issued for another call")
		}
		return v0.Check{Name: v0.CheckSensitivity, Result: v0.CheckPass, Detail: "single-use grant for this exact call"}, nil, false
	}
	if policy.Tier(op.Sensitivity) >= policy.Tier(v0.SensitivityCritical) {
		return v0.Check{Name: v0.CheckSensitivity, Result: v0.CheckFail, Detail: "critical tier needs a single-use grant"}, nil, true
	}
	return v0.Check{Name: v0.CheckSensitivity, Result: v0.CheckPass}, nil, false
}

func deny(code v0.ReasonCode, msg string) (v0.Check, *v0.Reason, bool) {
	return v0.Check{Name: v0.CheckSensitivity, Result: v0.CheckFail, Detail: msg}, &v0.Reason{Code: code, Message: msg}, false
}

func known(s v0.Sensitivity) bool {
	return s == v0.SensitivityRead || s == v0.SensitivityWrite || s == v0.SensitivityCritical
}
