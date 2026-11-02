package pdp

import (
	"context"
	"errors"
	"fmt"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/approval"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/core"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/x"
)

// evaluation is one call being decided: the record as it fills in, and
// what the checks so far have established. Its steps run in the record's
// order of checks; each one either passes, adding its check, or ends the
// decision with a refusal.
type evaluation struct {
	e     *Evaluator
	req   v0.EvaluationRequest
	now   time.Time
	token string
	d     v0.Decision

	// Set by checkRequest.
	call core.Call
	// Set by checkGrant.
	grant    v0.Grant
	standing grant.Standing
	// Set by loadPolicy. op is nil when the manifest declares no such
	// operation.
	mandate configuration.Mandate
	op      *v0.Operation
	// observe: the mandate's own rules (subset, limits) are recorded but do
	// not stop the call; everything else is still enforced. observed is
	// what enforcement would have refused.
	observe  bool
	observed []v0.Reason
	// Set by checkLimits.
	budgets []core.Budget
}

func (ev *evaluation) deny(failed v0.Check, reason v0.Reason) { deny(&ev.d, failed, reason) }

// checkRequest: the call is something the box can decide on.
func (ev *evaluation) checkRequest() bool {
	if msg := malformed(ev.req); msg != "" {
		ev.deny(v0.Check{Name: v0.CheckRequest, Result: v0.CheckFail, Detail: msg}, v0.Reason{Code: v0.ReasonRequestMalformed, Message: msg})
		return false
	}
	ev.d.Checks = append(ev.d.Checks, v0.Check{Name: v0.CheckRequest, Result: v0.CheckPass})
	args, _ := ev.req.Resource.Properties["arguments"].(map[string]any)
	ev.call = core.Call{Resource: ev.req.Resource.ID, Action: ev.req.Action.Name, Arguments: args}
	return true
}

// checkGrant: signature, status, pop, audience and time, as the verifier
// runs them. A good grant names who is asking: the agent, and the user it
// acts for or the team that owns it.
//
// So does a grant refused after its signature held: revoked, sent to
// another resource, expired. The box signed it, so the record can say
// whose it was, and those are the attempts a review looks for.
func (ev *evaluation) checkGrant(ctx context.Context) bool {
	r, err := ev.e.r.GrantVerifier().Verify(ctx, ev.token, ev.call.Resource)
	if err != nil {
		ev.e.r.Logger().Error("verifying a grant", "decision", ev.d.ID, "err", err)
	}
	ev.d.Checks = append(ev.d.Checks, r.Checks...)
	if !r.OK() {
		ev.d.Outcome, ev.d.Reasons = v0.OutcomeDeny, []v0.Reason{*r.Reason}
		if g := r.Grant; g != nil {
			ev.attribute(*g, ev.ownerOf(ctx, g.Actor.Subject))
			if ev.d.Principal.User == "" && ev.d.Principal.Owner == "" {
				// The record's contract wants a user or an owner; without
				// either, it names the grant alone.
				ev.d.Principal = nil
			}
		}
		return false
	}
	ev.grant, ev.standing = *r.Grant, *r.Standing
	ev.attribute(ev.grant, ev.standing.Owner)
	return true
}

// attribute names the grant and the principal in the record: the agent,
// and the user it acts for or, for a service agent, its owning team.
func (ev *evaluation) attribute(g v0.Grant, owner string) {
	ev.d.Request.Context[GrantKey] = g.ID
	ev.d.Grant = &v0.GrantRef{ID: g.ID, Mandate: g.Mandate, Consent: g.Consent}
	ev.d.Principal = &v0.Principal{Agent: g.Actor.Subject}
	if g.Subject == g.ClientID {
		ev.d.Principal.Owner = owner
	} else {
		ev.d.Principal.User = g.Subject
	}
}

// ownerOf is the team that owns an agent, from the configuration, for a
// grant whose status check did not establish it; "" when unknown.
func (ev *evaluation) ownerOf(ctx context.Context, agent string) string {
	a, err := ev.e.r.ConfigurationCache().Agent(ctx, agent)
	if err != nil || a.Spec.Owner == nil {
		return ""
	}
	return a.Spec.Owner.Team
}

// hashCall records the call's action hash, what an approval and a
// single-use grant name it by.
func (ev *evaluation) hashCall() error {
	hash, err := ev.call.Hash()
	if err != nil {
		return err
	}
	ev.d.ActionHash = hash
	return nil
}

// loadPolicy reads the configuration in force: the resource's manifest and
// the grant's mandate, whose versions the record names. A location no
// manifest declares gives the zero manifest, which declares no operation,
// so the subset check refuses the call.
func (ev *evaluation) loadPolicy(ctx context.Context) error {
	snap, err := ev.e.r.ConfigurationCache().Current(ctx)
	if err != nil {
		return err
	}
	man, _, err := snap.ManifestFor(ev.call.Resource)
	if err != nil {
		return err
	}
	mandate, err := snap.Mandate(ev.grant.Mandate)
	if err != nil {
		return fmt.Errorf("mandate %s: %w", ev.grant.Mandate, err)
	}
	ev.mandate = mandate
	ev.d.Versions = &v0.Versions{Mandate: mandate.Digest, Manifest: man.Digest}
	ev.op = core.Operation(man.Manifest, ev.call.Action)
	ev.observe = mandate.Spec.Enforcement == v0.EnforcementObserve || ev.standing.Enforcement == v0.EnforcementObserve
	if ev.observe {
		ev.d.Enforcement = v0.EnforcementObserve
	}
	return nil
}

// checkSubset: the call lies inside the grant. An operation the manifest
// does not declare is refused even when observed: its tier is unknown.
func (ev *evaluation) checkSubset() bool {
	check, reason := core.Subset(ev.grant, ev.op, ev.call)
	switch {
	case reason == nil:
	case ev.observe && ev.op != nil:
		ev.observed = append(ev.observed, *reason)
	default:
		ev.deny(check, *reason)
		return false
	}
	ev.d.Checks = append(ev.d.Checks, check)
	ev.d.Sensitivity = ev.op.Sensitivity
	return true
}

// checkSensitivity: how risky the operation is, and whether this grant may
// run it. A critical call on a standing grant is held: the check is
// returned for hold to record once the approval request is open.
func (ev *evaluation) checkSensitivity() (check v0.Check, hold, ok bool) {
	b := core.Binding{SingleUse: ev.standing.SingleUse, ActionHash: ev.standing.ActionHash}
	check, reason, hold := core.Sensitivity(*ev.op, ev.standing.Ceiling, b, ev.d.ActionHash)
	if reason != nil {
		ev.deny(check, *reason)
		return check, false, false
	}
	if !hold {
		ev.d.Checks = append(ev.d.Checks, check)
	}
	return check, hold, true
}

// hold answers a critical call: approval required, with the request for
// this exact call that people approve under the mandate's route. A mandate
// that names no one who may approve refuses the call instead.
func (ev *evaluation) hold(ctx context.Context, check v0.Check) error {
	if ev.mandate.Spec.Approval == nil {
		msg := fmt.Sprintf("%s is critical and mandate %s names no one who may approve it", ev.op.Name, ev.grant.Mandate)
		ev.deny(v0.Check{Name: v0.CheckSensitivity, Result: v0.CheckFail, Detail: msg}, v0.Reason{Code: v0.ReasonSensitivityExceeded, Message: msg})
		return nil
	}
	a, err := approval.Open(ctx, ev.e.r.ApprovalManager(), approval.Held{
		Grant:         ev.grant,
		Mandate:       ev.mandate.Mandate,
		MandateDigest: ev.mandate.Digest,
		Action:        v0.ApprovedAction{Name: ev.call.Action, Location: ev.call.Resource, Arguments: ev.call.Arguments},
		ActionHash:    ev.d.ActionHash,
		At:            ev.now,
	})
	if err != nil {
		return err
	}
	ev.d.Checks = append(ev.d.Checks, check)
	ev.d.Outcome, ev.d.Approval = v0.OutcomeApprovalRequired, &v0.ApprovalRef{Request: a.ID}
	ev.d.Observed = observedOf(ev.observed)
	return nil
}

// checkPolicy: the mandate is the policy; there is no second stage yet.
func (ev *evaluation) checkPolicy() {
	ev.d.Checks = append(ev.d.Checks, v0.Check{Name: v0.CheckPolicy, Result: v0.CheckSkip})
}

// checkLimits works out what the call spends: its budgets and, for a
// single-use grant, the grant. It runs last, and the spending is done with
// the record, in one transaction (settle). A call that cannot be counted is
// refused; observed, it runs uncounted.
func (ev *evaluation) checkLimits() (*budget.Allowance, bool) {
	budgets, reason := core.Budgets(ev.grant, ev.call, ev.now)
	allowance := &budget.Allowance{At: ev.now, BestEffort: ev.observe}
	if ev.standing.SingleUse {
		allowance.SingleUse = ev.grant.ID
	}
	if reason != nil {
		if !ev.observe {
			ev.deny(v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: reason.Message}, *reason)
			return nil, false
		}
		ev.d.Checks = append(ev.d.Checks, v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: reason.Message})
		ev.observed = append(ev.observed, *reason)
		budgets = nil
	}
	ev.budgets = budgets
	allowance.Draws = core.Draws(budgets)
	return allowance, true
}

// settle finishes an allowed call once its spending is known: drawn is what
// its budgets gave, err the store's refusal.
func (ev *evaluation) settle(d v0.Decision, drawn []budget.Drawn, err error) v0.Decision {
	if errors.Is(err, x.ErrState) {
		// Another call spent the single-use grant after this one's status
		// check. Enforced in every mode.
		msg := fmt.Sprintf("single-use grant %s was spent by another call", ev.grant.ID)
		deny(&d, v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: msg}, v0.Reason{Code: v0.ReasonGrantRevoked, Message: msg})
		return d
	}
	if ev.budgets != nil {
		check, reason, uses := core.LimitsCheck(ev.budgets, drawn, err)
		switch {
		case reason == nil:
		case ev.observe && reason.Code == v0.ReasonLimitExceeded:
			ev.observed = append(ev.observed, *reason)
		default:
			deny(&d, check, *reason)
			return d
		}
		d.Checks, d.Limits = append(d.Checks, check), uses
	}
	d.Outcome, d.Observed = v0.OutcomeAllow, observedOf(ev.observed)
	return d
}
