package journal

import (
	"context"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/budget"
)

// Manager is the hash-chained journal of decision records.
type Manager interface {
	// Append stores d as the next link: it fills d.Chain from the previous
	// record, computes the hash, and returns the stored record.
	Append(ctx context.Context, d v0.Decision) (v0.Decision, error)
	Get(ctx context.Context, id string) (v0.Decision, error)
	// Range returns records with seq in [from, to), oldest first.
	Range(ctx context.Context, from, to uint64) ([]v0.Decision, error)
	// Head returns the newest record, or x.ErrNotFound on an empty journal.
	Head(ctx context.Context) (v0.Decision, error)
}

// ManagerProvider gives access to the journal.
type ManagerProvider interface {
	JournalManager() Manager
}

// Settler spends what an allowed call spends and appends its record, in one
// transaction, so an allowed call's record is written exactly when its
// spending is.
type Settler interface {
	// Settle spends an allowance, when there is one, and appends the
	// decision that results. decide receives what was drawn, or the
	// refusal (*budget.ExhaustedError, x.ErrState), after which nothing
	// was drawn; any other error aborts it all. It returns the decision as
	// appended, chain filled in.
	Settle(ctx context.Context, a *budget.Allowance, decide func(drawn []budget.Drawn, err error) (v0.Decision, error)) (v0.Decision, error)
}

// SettlerProvider gives the settler.
type SettlerProvider interface {
	Settler() Settler
}

// Notifier is told about every record committed: the follower is one.
type Notifier interface {
	Notify()
}

// NotifierProvider gives the journal's notifier, nil when no follower
// copies the journal out.
type NotifierProvider interface {
	JournalNotifier() Notifier
}
