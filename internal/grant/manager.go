package grant

import (
	"context"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// Record is a grant as the box issued it, with the state the gateway needs
// on every call.
type Record struct {
	Grant      v0.Grant
	Agent      string
	RevokedAt  *time.Time
	SingleUse  bool
	ActionHash string
	UsedAt     *time.Time
}

// Manager keeps every grant issued and whether it still stands.
type Manager interface {
	Create(ctx context.Context, g Record) error
	Get(ctx context.Context, jti string) (Record, error)
	// Revoke marks one grant revoked.
	Revoke(ctx context.Context, jti string, at time.Time) error
	// RevokeByConsent revokes every live grant resting on a consent and
	// returns their IDs.
	RevokeByConsent(ctx context.Context, consent string, at time.Time) ([]string, error)
	// RevokeByAgent revokes every live grant of an agent and returns their IDs.
	RevokeByAgent(ctx context.Context, agent string, at time.Time) ([]string, error)
}

// ManagerProvider gives access to the grants.
type ManagerProvider interface {
	GrantManager() Manager
}
