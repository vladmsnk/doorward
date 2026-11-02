// Package approval keeps approval requests, from the moment a critical call
// is held to the moment people approve, reject or let it expire, and opens
// the request for a held call.
package approval

import (
	"context"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// Manager keeps approval requests from opening to closing.
type Manager interface {
	Create(ctx context.Context, a v0.Approval) error
	Get(ctx context.Context, id string) (v0.Approval, error)
	// Pending lists open requests, oldest first.
	Pending(ctx context.Context) ([]v0.Approval, error)
	// PendingFor returns the newest open request for one call: the same
	// agent, mandate, consent ("" for a service agent) and action hash.
	// x.ErrNotFound if there is none.
	PendingFor(ctx context.Context, agent, mandate, consent, actionHash string) (v0.Approval, error)
	// Vote adds a vote to a pending request. x.ErrState if it is not pending.
	Vote(ctx context.Context, id string, v v0.Vote) (v0.Approval, error)
	// Close moves a pending request to approved, rejected or expired.
	// x.ErrState if it is not pending.
	Close(ctx context.Context, id string, status v0.ApprovalStatus, at time.Time, singleUseGrant string) (v0.Approval, error)
}

// ManagerProvider gives access to the approval requests.
type ManagerProvider interface {
	ApprovalManager() Manager
}
