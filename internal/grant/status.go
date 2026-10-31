package grant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/store"
)

// StoreStatus reads a grant's standing from the box's own records: the
// grant must be one the box recorded when it issued it, not revoked, and
// its agent must be registered and not suspended.
//
// Revoking a consent or suspending an agent already revokes the grants
// resting on it; reading the agent too covers a grant issued in the same
// instant as a suspension.
type StoreStatus struct {
	Store store.Store
}

func (s StoreStatus) Standing(ctx context.Context, g v0.Grant) (string, error) {
	rec, err := s.Store.Grants().Get(ctx, g.ID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Sprintf("the box has no record of grant %s", g.ID), nil
	}
	if err != nil {
		return "", err
	}
	if rec.RevokedAt != nil {
		return fmt.Sprintf("grant %s was revoked at %s", g.ID, rec.RevokedAt.UTC().Format(v0.TimestampLayout)), nil
	}
	doc, err := s.Store.Documents().Current(ctx, v0.KindAgent, rec.Agent)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Sprintf("agent %s is not registered", rec.Agent), nil
	}
	if err != nil {
		return "", err
	}
	var a v0.Agent
	if err := json.Unmarshal(doc.Doc, &a); err != nil {
		return "", fmt.Errorf("agent %s: %w", rec.Agent, err)
	}
	if a.Spec.Status == v0.AgentSuspended {
		return fmt.Sprintf("agent %s is suspended", rec.Agent), nil
	}
	return "", nil
}
