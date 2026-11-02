package sql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/x"
)

type approvals struct{ pool *pgxpool.Pool }

func (s approvals) Create(ctx context.Context, a v0.Approval) error {
	doc, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO approvals (id, status, created_at, closed_at, mandate, consent, grant_id, agent, action_hash, single_use_grant, doc)
		VALUES ($1, $2, $3, $4, $5, nullif($6, ''), $7, $8, $9, nullif($10, ''), $11)`,
		a.ID, a.Status, a.Created.Time, timePtr(a.Closed), a.Mandate, a.Consent, a.Grant, a.Agent, a.ActionHash, a.SingleUseGrant, doc)
	return mapErr(err)
}

func (s approvals) Get(ctx context.Context, id string) (v0.Approval, error) {
	var a v0.Approval
	err := scanJSON(s.pool.QueryRow(ctx, "SELECT doc FROM approvals WHERE id = $1", id), &a)
	return a, err
}

func (s approvals) Pending(ctx context.Context) ([]v0.Approval, error) {
	rows, err := s.pool.Query(ctx, "SELECT doc FROM approvals WHERE status = 'pending' ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	return collectJSON[v0.Approval](rows)
}

func (s approvals) PendingFor(ctx context.Context, agent, mandate, consent, actionHash string) (v0.Approval, error) {
	var a v0.Approval
	err := scanJSON(s.pool.QueryRow(ctx, `
		SELECT doc FROM approvals
		WHERE status = 'pending' AND agent = $1 AND mandate = $2 AND coalesce(consent, '') = $3 AND action_hash = $4
		ORDER BY created_at DESC LIMIT 1`, agent, mandate, consent, actionHash), &a)
	return a, err
}

func (s approvals) Vote(ctx context.Context, id string, v v0.Vote) (v0.Approval, error) {
	return s.update(ctx, id, func(a *v0.Approval) error {
		a.Votes = append(a.Votes, v)
		return nil
	})
}

func (s approvals) Close(ctx context.Context, id string, status v0.ApprovalStatus, at time.Time, singleUseGrant string) (v0.Approval, error) {
	if status == v0.ApprovalPending {
		return v0.Approval{}, x.ErrState
	}
	return s.update(ctx, id, func(a *v0.Approval) error {
		a.Status = status
		a.Closed = &v0.Timestamp{Time: at.UTC().Truncate(time.Millisecond)}
		a.SingleUseGrant = singleUseGrant
		return nil
	})
}

// update applies change to a pending request under a row lock and stores
// the result, after the contract's own Check.
func (s approvals) update(ctx context.Context, id string, change func(*v0.Approval) error) (v0.Approval, error) {
	var out v0.Approval
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var a v0.Approval
		if err := scanJSON(tx.QueryRow(ctx, "SELECT doc FROM approvals WHERE id = $1 FOR UPDATE", id), &a); err != nil {
			return err
		}
		if a.Status != v0.ApprovalPending {
			return x.ErrState
		}
		if err := change(&a); err != nil {
			return err
		}
		if err := a.Check(); err != nil {
			return err
		}
		doc, err := json.Marshal(a)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			"UPDATE approvals SET status = $2, closed_at = $3, single_use_grant = nullif($4, ''), doc = $5 WHERE id = $1",
			id, a.Status, timePtr(a.Closed), a.SingleUseGrant, doc)
		out = a
		return err
	})
	return out, mapErr(err)
}
