package grant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/consent"
	"github.com/vladmsnk/doorward/internal/x"
)

// StoreStatus reads a grant's standing from the box's own records: the
// grant must be one the box recorded when it issued it, not revoked, not
// used if it is single-use; its agent must be registered and not
// suspended; the consent it rests on, if any, must be active and not
// expired; and its mandate must exist and be enabled. The agent's current
// max_sensitivity is the ceiling.
//
// Revoking a consent or suspending an agent already revokes the grants
// resting on it; reading the agent too covers a grant issued in the same
// instant as a suspension.
type StoreStatus struct {
	Store StatusSource
	// Config, when set, answers for agents and mandates instead of the
	// store, from a snapshot kept current by the decision point.
	Config Config
	// Now defaults to time.Now.
	Now func() time.Time
}

// StatusSource is what StoreStatus reads: the grants, the consents they
// rest on, and the documents of their agents and mandates.
type StatusSource interface {
	Grants() Manager
	Consents() consent.Manager
	Documents() configuration.Manager
}

// Config answers for the agents and mandates a grant depends on.
// x.ErrNotFound means there is none.
type Config interface {
	Agent(ctx context.Context, name string) (v0.Agent, error)
	Mandate(ctx context.Context, name string) (m v0.Mandate, disabled bool, err error)
}

func (s StoreStatus) Standing(ctx context.Context, g v0.Grant) (Standing, error) {
	refuse := func(format string, a ...any) (Standing, error) {
		return Standing{Refusal: fmt.Sprintf(format, a...)}, nil
	}
	rec, err := s.Store.Grants().Get(ctx, g.ID)
	if errors.Is(err, x.ErrNotFound) {
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
	a, err := s.agent(ctx, rec.Agent)
	if errors.Is(err, x.ErrNotFound) {
		return refuse("agent %s is not registered", rec.Agent)
	}
	if err != nil {
		return Standing{}, err
	}
	if a.Spec.Status == v0.AgentSuspended {
		return refuse("agent %s is suspended", rec.Agent)
	}
	if g.Consent != "" {
		c, err := s.Store.Consents().Get(ctx, g.Consent)
		if errors.Is(err, x.ErrNotFound) {
			return refuse("consent %s, which the grant rests on, is not recorded", g.Consent)
		}
		if err != nil {
			return Standing{}, err
		}
		if c.Status != v0.ConsentActive {
			return refuse("consent %s is %s", c.ID, c.Status)
		}
		if !s.now().Before(c.ExpiresAt.Time) {
			return refuse("consent %s expired at %s", c.ID, c.ExpiresAt.UTC().Format(v0.TimestampLayout))
		}
	}
	_, disabled, err := s.mandate(ctx, g.Mandate)
	if errors.Is(err, x.ErrNotFound) {
		return refuse("mandate %s does not exist", g.Mandate)
	}
	if err != nil {
		return Standing{}, err
	}
	if disabled {
		return refuse("mandate %s is disabled", g.Mandate)
	}
	st := Standing{Ceiling: a.Spec.MaxSensitivity, SingleUse: rec.SingleUse, ActionHash: rec.ActionHash, Enforcement: a.Spec.Enforcement}
	if a.Spec.Owner != nil {
		st.Owner = a.Spec.Owner.Team
	}
	return st, nil
}

func (s StoreStatus) agent(ctx context.Context, name string) (v0.Agent, error) {
	if s.Config != nil {
		return s.Config.Agent(ctx, name)
	}
	doc, err := s.Store.Documents().Current(ctx, v0.KindAgent, name)
	if err != nil {
		return v0.Agent{}, err
	}
	var a v0.Agent
	if err := json.Unmarshal(doc.Doc, &a); err != nil {
		return v0.Agent{}, fmt.Errorf("agent %s: %w", name, err)
	}
	return a, nil
}

func (s StoreStatus) mandate(ctx context.Context, name string) (v0.Mandate, bool, error) {
	if s.Config != nil {
		return s.Config.Mandate(ctx, name)
	}
	doc, err := s.Store.Documents().Current(ctx, v0.KindMandate, name)
	if err != nil {
		return v0.Mandate{}, false, err
	}
	var m v0.Mandate
	if err := json.Unmarshal(doc.Doc, &m); err != nil {
		return v0.Mandate{}, false, fmt.Errorf("mandate %s: %w", name, err)
	}
	return m, doc.Disabled, nil
}

func (s StoreStatus) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
