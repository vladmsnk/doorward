package approval

import (
	"context"
	"errors"
	"fmt"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/ids"
	"github.com/vladmsnk/doorward/internal/x"
)

// Held is a critical call the decision point holds for approval: the grant
// it came with, the mandate (and the version of it) that names who may
// approve, and the exact call with its hash.
type Held struct {
	Grant         v0.Grant
	Mandate       v0.Mandate
	MandateDigest string
	// Action is the call. Absent arguments are recorded as an empty object.
	Action     v0.ApprovedAction
	ActionHash string
	At         time.Time
}

// Open returns the open approval request for this exact call, opening one
// if there is none. A request opened under another version of the mandate,
// or older than the mandate lets requests live, is closed as expired and
// replaced. Two decisions holding the same call at once share one request:
// the store keeps one open request per call.
func Open(ctx context.Context, m Manager, h Held) (v0.Approval, error) {
	g, policy := h.Grant, h.Mandate.Spec.Approval
	open, err := m.PendingFor(ctx, g.Actor.Subject, g.Mandate, g.Consent, h.ActionHash)
	switch {
	case err == nil:
		if open.PolicyVersion == h.MandateDigest && h.At.Before(open.Created.Add(policy.ExpiresAfter.D())) {
			return open, nil
		}
		if _, err := m.Close(ctx, open.ID, v0.ApprovalExpired, h.At, ""); err != nil && !errors.Is(err, x.ErrState) {
			return v0.Approval{}, err
		}
	case errors.Is(err, x.ErrNotFound):
	default:
		return v0.Approval{}, err
	}
	action := h.Action
	if action.Arguments == nil {
		action.Arguments = map[string]any{}
	}
	a := v0.Approval{
		ID:            ids.At(ids.Approval, h.At),
		Created:       v0.Timestamp{Time: h.At.UTC().Truncate(time.Millisecond)},
		Status:        v0.ApprovalPending,
		Mandate:       g.Mandate,
		Consent:       g.Consent,
		Grant:         g.ID,
		Agent:         g.Actor.Subject,
		User:          g.SubjectID,
		Route:         policy.Approvers,
		Action:        action,
		ActionHash:    h.ActionHash,
		PolicyVersion: h.MandateDigest,
		Required:      policy.Required,
		Votes:         []v0.Vote{},
	}
	if err := a.Check(); err != nil {
		return v0.Approval{}, fmt.Errorf("approval request: %w", err)
	}
	err = m.Create(ctx, a)
	if errors.Is(err, x.ErrConflict) {
		// Another decision opened the request for this call first. Use theirs.
		return m.PendingFor(ctx, g.Actor.Subject, g.Mandate, g.Consent, h.ActionHash)
	}
	return a, err
}
