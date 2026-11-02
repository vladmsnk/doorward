// Package budget is what a call draws on: count and sum budgets kept as
// exact decimals, drawn all at once or not at all.
//
// The decision core works out which budgets a call draws on (core.Budgets);
// the store draws them, together with the single-use grant a call may run
// on, in one transaction.
package budget

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrExhausted is returned when a budget would be overdrawn.
var ErrExhausted = errors.New("limit exhausted")

// Manager reads budgets. A key names what a budget belongs to. Amounts are
// exact decimals written as strings ("1200", "0.1"), never floating point,
// so a budget of 0.30 holds exactly three draws of 0.10.
type Manager interface {
	// Consumed returns what the budget at key has drawn, "0" if nothing.
	Consumed(ctx context.Context, key string) (string, error)
}

// Allower spends an allowance on its own, outside a decision: the command
// line's grant verify --spend does.
type Allower interface {
	// Allow spends an allowance all at once or not at all: every draw fits
	// its budget and the single-use grant was unspent, or nothing changes
	// and the error says why (an *ExhaustedError, or x.ErrState for a
	// single-use grant already spent).
	Allow(ctx context.Context, a Allowance) ([]Drawn, error)
}

// Draw is one budget an allowed call draws on.
type Draw struct {
	Key    string
	Amount string // exact decimal, not negative
	Max    string // exact decimal
}

// Drawn is what one draw left. Exhausted marks a best-effort draw that
// did not fit and took nothing.
type Drawn struct {
	Key       string
	Amount    string
	Remaining string
	Exhausted bool
}

// ExhaustedError is a draw refused because the budget has no room for it.
// It matches ErrExhausted.
type ExhaustedError struct {
	Key       string
	Amount    string
	Remaining string
}

func (e *ExhaustedError) Error() string {
	return fmt.Sprintf("budget %s has %s left; the call needs %s", e.Key, e.Remaining, e.Amount)
}

func (e *ExhaustedError) Is(target error) bool { return target == ErrExhausted }

// Allowance is everything allowing one call spends: its budgets and, for a
// single-use grant, the grant itself.
type Allowance struct {
	Draws []Draw
	// SingleUse is the jti of the single-use grant the call runs on.
	SingleUse string
	// BestEffort draws every budget that has room and reports the others as
	// exhausted, instead of drawing nothing: an observed call runs, so what
	// it used counts where it fits. A spent single-use grant still refuses.
	BestEffort bool
	At         time.Time
}

// GrantKey and ConsentKey name a budget. Period is a calendar day
// (2026-10-30) or month (2026-10) in UTC.
func GrantKey(jti, limit string) string          { return "grant:" + jti + ":" + limit }
func ConsentKey(id, limit, period string) string { return "consent:" + id + ":" + limit + ":" + period }
