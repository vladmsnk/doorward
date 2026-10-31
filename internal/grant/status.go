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
// grant must be one the box recorded when it issued it, not revoked, not
// used if it is single-use, and its agent must be registered and not
// suspended. The agent's current max_sensitivity is the ceiling.
//
// Revoking a consent or suspending an agent already revokes the grants
// resting on it; reading the agent too covers a grant issued in the same
// instant as a suspension.
type StoreStatus struct {
	Store store.Store
}

func (s StoreStatus) Standing(ctx context.Context, g v0.Grant) (Standing, error) {
	refuse := func(format string, a ...any) (Standing, error) {
		return Standing{Refusal: fmt.Sprintf(format, a...)}, nil
	}
	rec, err := s.Store.Grants().Get(ctx, g.ID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse("the box has no record of grant %s", g.ID)
	}
	if err != nil {
		return Standing{}, err
	}
	if rec.RevokedAt != nil {
		return refuse("grant %s was revoked at %s", g.ID, rec.RevokedAt.UTC().Format(v0.TimestampLayout))
	}
	if rec.SingleUse && rec.UsedAt != nil {
		return refuse("single-use grant %s was used at %s", g.ID, rec.UsedAt.UTC().Format(v0.TimestampLayout))
	}
	doc, err := s.Store.Documents().Current(ctx, v0.KindAgent, rec.Agent)
	if errors.Is(err, store.ErrNotFound) {
		return refuse("agent %s is not registered", rec.Agent)
	}
	if err != nil {
		return Standing{}, err
	}
	var a v0.Agent
	if err := json.Unmarshal(doc.Doc, &a); err != nil {
		return Standing{}, fmt.Errorf("agent %s: %w", rec.Agent, err)
	}
	if a.Spec.Status == v0.AgentSuspended {
		return refuse("agent %s is suspended", rec.Agent)
	}
	return Standing{Ceiling: a.Spec.MaxSensitivity, SingleUse: rec.SingleUse, ActionHash: rec.ActionHash}, nil
}
