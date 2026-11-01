// Package pdp is doorward's decision point (B5). It takes an AuthZEN 1.0
// evaluation request from a point of enforcement, runs every check in the
// order a decision record lists them, spends what an allowed call spends,
// and appends the record to the hash-chained journal, the spending and the
// record in one transaction.
package pdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/url"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/core"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/ids"
	"github.com/vladmsnk/doorward/internal/store"
)

// TokenKey is the request context member that carries the grant. The record
// never keeps it: once the grant is verified, its ID takes its place, under
// GrantKey.
const (
	TokenKey = "token"
	GrantKey = "grant"
)

// ResourceType is the AuthZEN resource type of a tool call.
const ResourceType = "tool_call"

// PDP decides calls. Store and Verifier are required.
type PDP struct {
	Store    store.Store
	Verifier *grant.Verifier
	// ID and Version name this decision point in every record.
	ID      string
	Version string
	// Journal, when set, receives each record as one JSON line once it is
	// committed.
	Journal io.Writer
	Log     *slog.Logger
	// Tracer, when set, records one span per evaluation.
	Tracer trace.Tracer
	// Now defaults to time.Now.
	Now func() time.Time

	journalMu sync.Mutex
}

// order is the record's order of checks.
var order = []v0.CheckName{
	v0.CheckRequest, v0.CheckSignature, v0.CheckStatus, v0.CheckPoP, v0.CheckAudience,
	v0.CheckTime, v0.CheckSubset, v0.CheckSensitivity, v0.CheckPolicy, v0.CheckLimits,
}

// Evaluate decides one call and records the decision. The request is the
// point of enforcement's, with the grant in its context under TokenKey. An
// error means the decision could not be made or recorded; the caller then
// refuses the call.
func (p *PDP) Evaluate(ctx context.Context, req v0.EvaluationRequest, pep v0.PEP, traceID string) (v0.Decision, error) {
	now := p.now()
	token, _ := req.Context[TokenKey].(string)
	d := v0.Decision{
		ID:      ids.At(ids.Decision, now),
		Time:    v0.Timestamp{Time: now.UTC().Truncate(time.Millisecond)},
		Request: withoutToken(req),
		PDP:     v0.PDP{ID: p.ID, Version: p.Version},
		PEP:     pep,
		TraceID: traceID,
	}

	// request: the call is something the box can decide on.
	if msg := malformed(req); msg != "" {
		deny(&d, v0.Check{Name: v0.CheckRequest, Result: v0.CheckFail, Detail: msg}, v0.Reason{Code: v0.ReasonRequestMalformed, Message: msg})
		return p.record(ctx, d, nil, nil)
	}
	d.Checks = append(d.Checks, v0.Check{Name: v0.CheckRequest, Result: v0.CheckPass})
	args, _ := req.Resource.Properties["arguments"].(map[string]any)
	call := core.Call{Resource: req.Resource.ID, Action: req.Action.Name, Arguments: args}

	// signature, status, pop, audience, time: the grant.
	r, err := p.Verifier.Verify(ctx, token, call.Resource)
	if err != nil {
		p.log().Error("verifying a grant", "decision", d.ID, "err", err)
	}
	d.Checks = append(d.Checks, r.Checks...)
	if !r.OK() {
		d.Outcome, d.Reasons = v0.OutcomeDeny, []v0.Reason{*r.Reason}
		return p.record(ctx, d, nil, nil)
	}
	g, st := *r.Grant, *r.Standing
	d.Request.Context[GrantKey] = g.ID
	d.Grant = &v0.GrantRef{ID: g.ID, Mandate: g.Mandate, Consent: g.Consent}
	d.Principal = &v0.Principal{Agent: g.Actor.Subject}
	if g.Subject == g.ClientID {
		d.Principal.Owner = st.Owner
	} else {
		d.Principal.User = g.Subject
	}
	hash, err := call.Hash()
	if err != nil {
		return d, err
	}
	d.ActionHash = hash

	// The configuration in force: the resource's manifest, the mandate.
	man, manDigest, err := p.manifest(ctx, call.Resource)
	if err != nil {
		return d, err
	}
	mandate, mandateDigest, err := p.mandate(ctx, g.Mandate)
	if err != nil {
		return d, err
	}
	d.Versions = &v0.Versions{Mandate: mandateDigest, Manifest: manDigest}
	op := core.Operation(man, call.Action)

	// Observe mode: the mandate's own rules (subset, limits) are recorded
	// but do not stop the call. Everything else is still enforced.
	observe := mandate.Spec.Enforcement == v0.EnforcementObserve || st.Enforcement == v0.EnforcementObserve
	var observed []v0.Reason
	if observe {
		d.Enforcement = v0.EnforcementObserve
	}

	// subset: the call lies inside the grant. An operation the manifest
	// does not declare is refused even when observed: its tier is unknown.
	check, reason := core.Subset(g, op, call)
	switch {
	case reason == nil:
	case observe && op != nil:
		observed = append(observed, *reason)
	default:
		deny(&d, check, *reason)
		return p.record(ctx, d, nil, nil)
	}
	d.Checks = append(d.Checks, check)
	d.Sensitivity = op.Sensitivity

	// sensitivity: how risky, and whether this grant may run it.
	check, reason, hold := core.Sensitivity(*op, st.Ceiling, core.Binding{SingleUse: st.SingleUse, ActionHash: st.ActionHash}, hash)
	if reason != nil {
		deny(&d, check, *reason)
		return p.record(ctx, d, nil, nil)
	}
	if hold {
		if mandate.Spec.Approval == nil {
			msg := fmt.Sprintf("%s is critical and mandate %s names no one who may approve it", op.Name, g.Mandate)
			deny(&d, v0.Check{Name: v0.CheckSensitivity, Result: v0.CheckFail, Detail: msg}, v0.Reason{Code: v0.ReasonSensitivityExceeded, Message: msg})
			return p.record(ctx, d, nil, nil)
		}
		a, err := p.approval(ctx, g, mandate, mandateDigest, call, hash, now)
		if err != nil {
			return d, err
		}
		d.Checks = append(d.Checks, check)
		d.Outcome, d.Approval = v0.OutcomeApprovalRequired, &v0.ApprovalRef{Request: a.ID}
		d.Observed = observedOf(observed)
		return p.record(ctx, d, nil, nil)
	}
	d.Checks = append(d.Checks, check)

	// policy: the mandate is the policy; no second stage yet.
	d.Checks = append(d.Checks, v0.Check{Name: v0.CheckPolicy, Result: v0.CheckSkip})

	// limits: last, and spent together with the record.
	budgets, reason := core.Budgets(g, call, now)
	allowance := &store.Allowance{At: now, BestEffort: observe}
	if st.SingleUse {
		allowance.SingleUse = g.ID
	}
	if reason != nil {
		if !observe {
			deny(&d, v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: reason.Message}, *reason)
			return p.record(ctx, d, nil, nil)
		}
		// The call cannot be counted; observed, it runs uncounted.
		d.Checks = append(d.Checks, v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: reason.Message})
		observed = append(observed, *reason)
		budgets = nil
	}
	allowance.Draws = core.Draws(budgets)
	return p.record(ctx, d, allowance, func(d v0.Decision, drawn []store.Drawn, err error) v0.Decision {
		if errors.Is(err, store.ErrState) {
			// Another call spent the single-use grant after this one's
			// status check. Enforced in every mode.
			msg := fmt.Sprintf("single-use grant %s was spent by another call", g.ID)
			deny(&d, v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: msg}, v0.Reason{Code: v0.ReasonGrantRevoked, Message: msg})
			return d
		}
		if budgets != nil {
			check, reason, uses := core.LimitsCheck(budgets, drawn, err)
			switch {
			case reason == nil:
			case observe && reason.Code == v0.ReasonLimitExceeded:
				observed = append(observed, *reason)
			default:
				deny(&d, check, *reason)
				return d
			}
			d.Checks, d.Limits = append(d.Checks, check), uses
		}
		d.Outcome, d.Observed = v0.OutcomeAllow, observedOf(observed)
		return d
	})
}

// observedOf is what enforcement would have answered, if it would have
// refused.
func observedOf(reasons []v0.Reason) *v0.Observed {
	if len(reasons) == 0 {
		return nil
	}
	return &v0.Observed{Outcome: v0.OutcomeDeny, Reasons: reasons}
}

// record settles the allowance, if any, appends the decision with every
// check the core did not reach marked as skipped, and writes it to the
// journal.
func (p *PDP) record(ctx context.Context, d v0.Decision, a *store.Allowance, settle func(v0.Decision, []store.Drawn, error) v0.Decision) (v0.Decision, error) {
	out, err := p.Store.Settle(ctx, a, func(drawn []store.Drawn, refused error) (v0.Decision, error) {
		if settle != nil {
			d = settle(d, drawn, refused)
		}
		return complete(d), nil
	})
	if err != nil {
		return d, err
	}
	p.export(out)
	return out, nil
}

// complete lists the checks the core did not reach, as skipped, in the
// record's order.
func complete(d v0.Decision) v0.Decision {
	ran := make(map[v0.CheckName]bool, len(d.Checks))
	for _, c := range d.Checks {
		ran[c.Name] = true
	}
	for _, name := range order {
		if !ran[name] {
			d.Checks = append(d.Checks, v0.Check{Name: name, Result: v0.CheckSkip})
		}
	}
	return d
}

func deny(d *v0.Decision, failed v0.Check, reason v0.Reason) {
	d.Checks = append(d.Checks, failed)
	d.Outcome, d.Reasons = v0.OutcomeDeny, []v0.Reason{reason}
}

// malformed says what is wrong with a request the box cannot decide on, or
// returns "".
func malformed(req v0.EvaluationRequest) string {
	if req.Resource.Type != ResourceType {
		return fmt.Sprintf("resource.type is %q; doorward decides %q resources", req.Resource.Type, ResourceType)
	}
	if u, err := url.Parse(req.Resource.ID); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Sprintf("resource.id %q is not the resource's audience URL", req.Resource.ID)
	}
	if a, ok := req.Resource.Properties["arguments"]; ok && a != nil {
		if _, isObject := a.(map[string]any); !isObject {
			return "resource.properties.arguments is not an object"
		}
	}
	if t, ok := req.Context[TokenKey]; ok {
		if _, isString := t.(string); !isString {
			return "context.token is not a string"
		}
	}
	if _, ok := req.Context[GrantKey]; ok {
		return "context.grant is set by the decision point, not sent to it"
	}
	return ""
}

// withoutToken copies a request for the record, without the grant: a
// record never holds a credential.
func withoutToken(req v0.EvaluationRequest) v0.EvaluationRequest {
	out := req
	out.Context = maps.Clone(req.Context)
	if out.Context == nil {
		out.Context = map[string]any{}
	}
	delete(out.Context, TokenKey)
	return out
}

// manifest returns the enabled manifest whose audience is location, and its
// version digest. A location no manifest declares gives the zero manifest,
// which declares no operation, so the subset check refuses the call.
func (p *PDP) manifest(ctx context.Context, location string) (v0.Manifest, string, error) {
	docs, err := p.Store.Documents().List(ctx, v0.KindManifest)
	if err != nil {
		return v0.Manifest{}, "", err
	}
	for _, doc := range docs {
		if doc.Disabled {
			continue
		}
		var m v0.Manifest
		if err := json.Unmarshal(doc.Doc, &m); err != nil {
			return v0.Manifest{}, "", fmt.Errorf("manifest %s: %w", doc.Name, err)
		}
		if m.Spec.Audience == location {
			return m, doc.Digest, nil
		}
	}
	return v0.Manifest{}, "", nil
}

func (p *PDP) mandate(ctx context.Context, name string) (v0.Mandate, string, error) {
	doc, err := p.Store.Documents().Current(ctx, v0.KindMandate, name)
	if err != nil {
		return v0.Mandate{}, "", fmt.Errorf("mandate %s: %w", name, err)
	}
	var m v0.Mandate
	if err := json.Unmarshal(doc.Doc, &m); err != nil {
		return v0.Mandate{}, "", fmt.Errorf("mandate %s: %w", name, err)
	}
	return m, doc.Digest, nil
}

// approval returns the open approval request for this exact call, opening
// one if there is none. A request opened under another version of the
// mandate, or older than the mandate lets requests live, is closed as
// expired and replaced.
func (p *PDP) approval(ctx context.Context, g v0.Grant, m v0.Mandate, mandateDigest string, call core.Call, hash string, now time.Time) (v0.Approval, error) {
	policy := m.Spec.Approval
	open, err := p.Store.Approvals().PendingFor(ctx, g.Actor.Subject, g.Mandate, g.Consent, hash)
	switch {
	case err == nil:
		if open.PolicyVersion == mandateDigest && now.Before(open.Created.Add(policy.ExpiresAfter.D())) {
			return open, nil
		}
		if _, err := p.Store.Approvals().Close(ctx, open.ID, v0.ApprovalExpired, now, ""); err != nil && !errors.Is(err, store.ErrState) {
			return v0.Approval{}, err
		}
	case errors.Is(err, store.ErrNotFound):
	default:
		return v0.Approval{}, err
	}
	args := call.Arguments
	if args == nil {
		args = map[string]any{}
	}
	a := v0.Approval{
		ID:            ids.At(ids.Approval, now),
		Created:       v0.Timestamp{Time: now.UTC().Truncate(time.Millisecond)},
		Status:        v0.ApprovalPending,
		Mandate:       g.Mandate,
		Consent:       g.Consent,
		Grant:         g.ID,
		Agent:         g.Actor.Subject,
		User:          g.SubjectID,
		Route:         policy.Approvers,
		Action:        v0.ApprovedAction{Name: call.Action, Location: call.Resource, Arguments: args},
		ActionHash:    hash,
		PolicyVersion: mandateDigest,
		Required:      policy.Required,
		Votes:         []v0.Vote{},
	}
	if err := a.Check(); err != nil {
		return v0.Approval{}, fmt.Errorf("approval request: %w", err)
	}
	return a, p.Store.Approvals().Create(ctx, a)
}

func (p *PDP) export(d v0.Decision) {
	if p.Journal == nil {
		return
	}
	line, err := json.Marshal(d)
	if err != nil {
		p.log().Error("exporting a decision", "decision", d.ID, "err", err)
		return
	}
	p.journalMu.Lock()
	defer p.journalMu.Unlock()
	if _, err := p.Journal.Write(append(line, '\n')); err != nil {
		p.log().Error("exporting a decision", "decision", d.ID, "err", err)
	}
}

func (p *PDP) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *PDP) tracer() trace.Tracer {
	if p.Tracer != nil {
		return p.Tracer
	}
	return noop.NewTracerProvider().Tracer("")
}

func (p *PDP) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}
