package core

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/budget"
)

// Budget is one budget an allowed call draws on, and how much.
type Budget struct {
	Limit v0.Limit
	// Draw is what to take: the counter's key, the amount and the
	// budget's max, as exact decimals.
	Draw budget.Draw
}

// Budgets works out which of a grant's budgets a call draws on (B4). It
// changes nothing: budgets are drawn only for a call that passed every other
// check, all at once, through store.Allow.
//
// A count budget draws 1. A sum budget draws the value of its field, which
// must be present, a number and not negative: a call that cannot be
// counted is refused, and a negative amount would refill the budget. A
// per-grant budget is keyed by the grant; a daily or monthly one by the
// consent and the calendar day or month in UTC, so every grant under one
// consent shares it.
func Budgets(g v0.Grant, call Call, now time.Time) ([]Budget, *v0.Reason) {
	var out []Budget
	for _, l := range g.Limits {
		if len(l.Actions) > 0 && !slices.Contains(l.Actions, call.Action) {
			continue
		}
		amount := "1"
		if l.Kind == v0.LimitSum {
			v, present := lookup(call.Arguments, l.Field)
			if !present || v == nil {
				return nil, &v0.Reason{Code: v0.ReasonFieldMissing, Field: l.Field,
					Message: fmt.Sprintf("budget %s adds up %s, which the call does not carry", l.Name, l.Field)}
			}
			f, ok := v.(float64)
			if !ok {
				return nil, &v0.Reason{Code: v0.ReasonConstraintViolated, Field: l.Field,
					Message: fmt.Sprintf("budget %s adds up %s, but the call's %s is %s", l.Name, l.Field, jsonText(v), jsonType(v))}
			}
			if f < 0 {
				return nil, &v0.Reason{Code: v0.ReasonConstraintViolated, Field: l.Field,
					Message: fmt.Sprintf("budget %s adds up %s, which cannot be negative", l.Name, l.Field)}
			}
			amount = decimal(f)
		}
		key, err := budgetKey(g, l, now)
		if err != nil {
			return nil, &v0.Reason{Code: v0.ReasonLimitExceeded, Message: err.Error()}
		}
		out = append(out, Budget{Limit: l, Draw: budget.Draw{Key: key, Amount: amount, Max: decimal(l.Max)}})
	}
	return out, nil
}

// Draws are the store draws of a call's budgets.
func Draws(budgets []Budget) []budget.Draw {
	out := make([]budget.Draw, len(budgets))
	for i, b := range budgets {
		out[i] = b.Draw
	}
	return out
}

// LimitsCheck turns the outcome of store.Allow into the limits check and
// what the decision record lists as drawn. err is Allow's error.
//
// After a best-effort draw (observe mode), budgets without room are marked
// exhausted in drawn: the check fails for the first of them, and the uses
// list what the others drew.
func LimitsCheck(budgets []Budget, drawn []budget.Drawn, err error) (v0.Check, *v0.Reason, []v0.LimitUse) {
	var ex *budget.ExhaustedError
	var kept []budget.Drawn
	var keptBudgets []Budget
	for i, d := range drawn {
		if d.Exhausted {
			if ex == nil {
				ex = &budget.ExhaustedError{Key: d.Key, Amount: d.Amount, Remaining: d.Remaining}
			}
			continue
		}
		kept, keptBudgets = append(kept, d), append(keptBudgets, budgets[i])
	}
	if ex != nil {
		check, reason, _ := LimitsCheck(budgets, nil, ex)
		_, _, uses := LimitsCheck(keptBudgets, kept, nil)
		return check, reason, uses
	}
	if errors.As(err, &ex) {
		for _, b := range budgets {
			if b.Draw.Key != ex.Key {
				continue
			}
			msg := fmt.Sprintf("budget %s has %s left%s; the call needs %s", b.Limit.Name, ex.Remaining, periodWords(b.Limit.Per), ex.Amount)
			return v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: b.Limit.Name},
				&v0.Reason{Code: v0.ReasonLimitExceeded, Field: b.Limit.Field, Message: msg}, nil
		}
	}
	if err != nil {
		return v0.Check{Name: v0.CheckLimits, Result: v0.CheckFail, Detail: "budgets could not be drawn"},
			&v0.Reason{Code: v0.ReasonInternalError, Message: "budgets could not be drawn"}, nil
	}
	uses := make([]v0.LimitUse, 0, len(drawn))
	for i, d := range drawn {
		amount, _ := strconv.ParseFloat(d.Amount, 64)
		left, _ := strconv.ParseFloat(d.Remaining, 64)
		uses = append(uses, v0.LimitUse{Name: budgets[i].Limit.Name, Consumed: amount, Remaining: left})
	}
	return v0.Check{Name: v0.CheckLimits, Result: v0.CheckPass}, nil, uses
}

func budgetKey(g v0.Grant, l v0.Limit, now time.Time) (string, error) {
	switch l.Per {
	case "", v0.PerGrant:
		return budget.GrantKey(g.ID, l.Name), nil
	case v0.PerDay, v0.PerMonth:
		if g.Consent == "" {
			return "", fmt.Errorf("budget %s runs per %s of a consent, and the grant rests on none", l.Name, l.Per)
		}
		layout := "2006-01-02"
		if l.Per == v0.PerMonth {
			layout = "2006-01"
		}
		return budget.ConsentKey(g.Consent, l.Name, now.UTC().Format(layout)), nil
	}
	return "", fmt.Errorf("budget %s runs per %q, which is not a period", l.Name, l.Per)
}

func periodWords(p v0.LimitPeriod) string {
	switch p {
	case v0.PerDay:
		return " today"
	case v0.PerMonth:
		return " this month"
	}
	return " on this grant"
}

// decimal writes a number in plain decimal notation with the fewest digits
// that read back as the same number: what JSON said, for any amount JSON
// can carry exactly ("0.1", "1200", "240.5").
func decimal(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
