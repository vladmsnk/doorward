// Package pdp is doorward's decision point (B5). It takes an AuthZEN 1.0
// evaluation request from a point of enforcement, runs every check in the
// order a decision record lists them, spends what an allowed call spends,
// and appends the record to the hash-chained journal, the spending and the
// record in one transaction.
//
// The Evaluator decides; the Handler serves it over HTTP. The built-in MCP
// gateway calls the Evaluator in process.
package pdp

import (
	"context"
	"errors"
	"fmt"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/ids"
	"github.com/vladmsnk/doorward/internal/x"
)

// ErrTimeout is returned when a decision ran out of time before it was
// recorded. Nothing was drawn or written.
var ErrTimeout = errors.New("the decision ran out of time")

// order is the record's order of checks.
var order = []v0.CheckName{
	v0.CheckRequest, v0.CheckSignature, v0.CheckStatus, v0.CheckPoP, v0.CheckAudience,
	v0.CheckTime, v0.CheckSubset, v0.CheckSensitivity, v0.CheckPolicy, v0.CheckLimits,
}

// Evaluator decides calls.
type Evaluator struct {
	r InternalRegistry
}

// NewEvaluator returns the decision point.
func NewEvaluator(r InternalRegistry) *Evaluator { return &Evaluator{r: r} }

// Evaluate decides one call and records the decision. The request is the
// point of enforcement's, with the grant in its context under TokenKey. An
// error means the decision could not be made or recorded; the caller then
// refuses the call.
//
// A decision has --decision-timeout to finish, the wait for the journal
// lock included. One that runs out of time is rolled back: nothing drawn,
// nothing recorded, and the error is ErrTimeout.
func (e *Evaluator) Evaluate(ctx context.Context, req v0.EvaluationRequest, pep v0.PEP, traceID string) (v0.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout())
	defer cancel()
	d, err := e.evaluate(ctx, req, pep, traceID)
	if errors.Is(err, x.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return d, fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return d, err
}

// evaluate runs the checks in the record's order. Each step passes and
// lets the next one run, or ends the decision: a refusal or a hold is
// recorded at once, and an error means nothing could be recorded.
func (e *Evaluator) evaluate(ctx context.Context, req v0.EvaluationRequest, pep v0.PEP, traceID string) (v0.Decision, error) {
	ev := e.begin(req, pep, traceID)
	if !ev.checkRequest() || !ev.checkGrant(ctx) {
		return e.record(ctx, ev.d, nil, nil)
	}
	if err := ev.hashCall(); err != nil {
		return ev.d, err
	}
	if err := ev.loadPolicy(ctx); err != nil {
		return ev.d, err
	}
	if !ev.checkSubset() {
		return e.record(ctx, ev.d, nil, nil)
	}
	check, hold, ok := ev.checkSensitivity()
	switch {
	case !ok:
		return e.record(ctx, ev.d, nil, nil)
	case hold:
		if err := ev.hold(ctx, check); err != nil {
			return ev.d, err
		}
		return e.record(ctx, ev.d, nil, nil)
	}
	ev.checkPolicy()
	allowance, ok := ev.checkLimits()
	if !ok {
		return e.record(ctx, ev.d, nil, nil)
	}
	return e.record(ctx, ev.d, allowance, ev.settle)
}

// begin starts the record of one decision.
func (e *Evaluator) begin(req v0.EvaluationRequest, pep v0.PEP, traceID string) *evaluation {
	now := e.r.Now()
	token, _ := req.Context[TokenKey].(string)
	conf := e.r.Config()
	return &evaluation{e: e, req: req, now: now, token: token, d: v0.Decision{
		ID:      ids.At(ids.Decision, now),
		Time:    v0.Timestamp{Time: now.UTC().Truncate(time.Millisecond)},
		Request: withoutToken(req),
		PDP:     v0.PDP{ID: conf.PDPID, Version: conf.Version},
		PEP:     pep,
		TraceID: traceID,
	}}
}

// record settles the allowance, if any, appends the decision with every
// check the core did not reach marked as skipped, and tells the journal.
// settle, when set, finishes the decision once the spending is known.
func (e *Evaluator) record(ctx context.Context, d v0.Decision, a *budget.Allowance, settle func(v0.Decision, []budget.Drawn, error) v0.Decision) (v0.Decision, error) {
	out, err := e.r.Settler().Settle(ctx, a, func(drawn []budget.Drawn, refused error) (v0.Decision, error) {
		if settle != nil {
			d = settle(d, drawn, refused)
		}
		return complete(d), nil
	})
	if err != nil {
		return d, err
	}
	if n := e.r.JournalNotifier(); n != nil {
		n.Notify()
	}
	return out, nil
}

func (e *Evaluator) timeout() time.Duration {
	if t := e.r.Config().DecisionTimeout; t > 0 {
		return t
	}
	return config.DefaultDecisionTimeout
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

// observedOf is what enforcement would have answered, if it would have
// refused.
func observedOf(reasons []v0.Reason) *v0.Observed {
	if len(reasons) == 0 {
		return nil
	}
	return &v0.Observed{Outcome: v0.OutcomeDeny, Reasons: reasons}
}
