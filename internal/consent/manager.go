// Package consent keeps the consents users give to an agent under a
// mandate. A grant to a user rests on one; revoking it revokes the grants.
package consent

import (
	"context"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// Manager keeps Consent records.
type Manager interface {
	Create(ctx context.Context, c v0.Consent) error
	Get(ctx context.Context, id string) (v0.Consent, error)
	// ByUser lists a user's consents, newest first; activeOnly drops the
	// ended ones.
	ByUser(ctx context.Context, user v0.SubjectID, activeOnly bool) ([]v0.Consent, error)
	// Revoke ends an active consent. x.ErrState if it is not active.
	Revoke(ctx context.Context, id string, by v0.Revoker, at time.Time) (v0.Consent, error)
}

// ManagerProvider gives access to the consents.
type ManagerProvider interface {
	ConsentManager() Manager
}
