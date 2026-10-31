package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/store"
)

// Every record is stored twice over: the full document as JSON, which is
// what readers get back, and the few columns queries filter on. The columns
// are derived from the document on write and never edited on their own.

// ---------------------------------------------------------------- consents

type consents struct{ pool *pgxpool.Pool }

func (s consents) Create(ctx context.Context, c v0.Consent) error {
	doc, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO consents (id, user_iss, user_sub, agent, mandate, mandate_version, status,
		                      granted_at, expires_at, revoked_at, revoked_by, doc)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, nullif($11, ''), $12)`,
		c.ID, c.User.Issuer, c.User.Sub, c.Agent, c.Mandate, c.MandateVersion, c.Status,
		c.GrantedAt.Time, c.ExpiresAt.Time, timePtr(c.RevokedAt), string(c.RevokedBy), doc)
	return mapErr(err)
}

func (s consents) Get(ctx context.Context, id string) (v0.Consent, error) {
	var c v0.Consent
	err := scanJSON(s.pool.QueryRow(ctx, "SELECT doc FROM consents WHERE id = $1", id), &c)
	return c, err
}

func (s consents) ByUser(ctx context.Context, user v0.SubjectID, activeOnly bool) ([]v0.Consent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT doc FROM consents
		WHERE user_iss = $1 AND user_sub = $2 AND ($3 = false OR status = 'active')
		ORDER BY granted_at DESC`, user.Issuer, user.Sub, activeOnly)
	if err != nil {
		return nil, err
	}
	return collectJSON[v0.Consent](rows)
}

func (s consents) Revoke(ctx context.Context, id string, by v0.Revoker, at time.Time) (v0.Consent, error) {
	var out v0.Consent
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var c v0.Consent
		if err := scanJSON(tx.QueryRow(ctx, "SELECT doc FROM consents WHERE id = $1 FOR UPDATE", id), &c); err != nil {
			return err
		}
		if c.Status != v0.ConsentActive {
			return store.ErrState
		}
		c.Status = v0.ConsentRevoked
		c.RevokedAt = &v0.Timestamp{Time: at.UTC().Truncate(time.Millisecond)}
		c.RevokedBy = by
		doc, err := json.Marshal(c)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			"UPDATE consents SET status = $2, revoked_at = $3, revoked_by = $4, doc = $5 WHERE id = $1",
			id, c.Status, c.RevokedAt.Time, string(by), doc)
		out = c
		return err
	})
	return out, mapErr(err)
}

func (s consents) Expire(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE consents SET status = 'expired', doc = jsonb_set(doc, '{status}', '"expired"')
		WHERE status = 'active' AND expires_at <= $1`, now)
	return int(tag.RowsAffected()), err
}

// ---------------------------------------------------------------- grants

type grants struct{ pool *pgxpool.Pool }

func (s grants) Create(ctx context.Context, g store.GrantRecord) error {
	doc, err := json.Marshal(g.Grant)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO grants (jti, subject, client_id, agent, mandate, consent, issued_at, expires_at,
		                    revoked_at, single_use, action_hash, used_at, doc)
		VALUES ($1, $2, $3, $4, $5, nullif($6, ''), $7, $8, $9, $10, nullif($11, ''), $12, $13)`,
		g.Grant.ID, g.Grant.Subject, g.Grant.ClientID, g.Agent, g.Grant.Mandate, g.Grant.Consent,
		time.Unix(g.Grant.IssuedAt, 0).UTC(), time.Unix(g.Grant.Expiry, 0).UTC(),
		g.RevokedAt, g.SingleUse, g.ActionHash, g.UsedAt, doc)
	return mapErr(err)
}

func (s grants) Get(ctx context.Context, jti string) (store.GrantRecord, error) {
	var g store.GrantRecord
	var doc []byte
	var actionHash *string
	err := s.pool.QueryRow(ctx,
		"SELECT doc, agent, revoked_at, single_use, action_hash, used_at FROM grants WHERE jti = $1", jti,
	).Scan(&doc, &g.Agent, &g.RevokedAt, &g.SingleUse, &actionHash, &g.UsedAt)
	if err != nil {
		return g, mapErr(err)
	}
	if actionHash != nil {
		g.ActionHash = *actionHash
	}
	return g, json.Unmarshal(doc, &g.Grant)
}

func (s grants) Revoke(ctx context.Context, jti string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, "UPDATE grants SET revoked_at = $2 WHERE jti = $1 AND revoked_at IS NULL", jti, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s grants) RevokeByConsent(ctx context.Context, consent string, at time.Time) ([]string, error) {
	return s.revokeWhere(ctx, "consent = $1", consent, at)
}

func (s grants) RevokeByAgent(ctx context.Context, agent string, at time.Time) ([]string, error) {
	return s.revokeWhere(ctx, "agent = $1", agent, at)
}

func (s grants) revokeWhere(ctx context.Context, where, arg string, at time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		"UPDATE grants SET revoked_at = $2 WHERE "+where+" AND revoked_at IS NULL AND expires_at > $2 RETURNING jti", arg, at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s grants) Spend(ctx context.Context, jti string, at time.Time) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE grants SET used_at = $2 WHERE jti = $1 AND single_use AND used_at IS NULL AND revoked_at IS NULL", jti, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := s.Get(ctx, jti); err != nil {
			return err
		}
		return store.ErrState
	}
	return nil
}

// ---------------------------------------------------------------- decisions

type decisions struct{ pool *pgxpool.Pool }

// chainLock serializes appends, so each record sees the true head.
const chainLock = 0x444543495349 // "DECISI"

func (s decisions) Append(ctx context.Context, d v0.Decision) (v0.Decision, error) {
	var out v0.Decision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", chainLock); err != nil {
			return err
		}
		var prev *v0.Decision
		var head v0.Decision
		err := scanJSON(tx.QueryRow(ctx, "SELECT doc FROM decisions ORDER BY seq DESC LIMIT 1"), &head)
		switch {
		case err == nil:
			prev = &head
		case errors.Is(err, store.ErrNotFound):
		default:
			return err
		}
		linked, err := v0.Link(d, prev)
		if err != nil {
			return err
		}
		doc, err := json.Marshal(linked)
		if err != nil {
			return err
		}
		var user, owner, grantID, mandate, consent *string
		if p := linked.Principal; p != nil {
			user, owner = nilIfEmpty(p.User), nilIfEmpty(p.Owner)
		}
		if g := linked.Grant; g != nil {
			grantID, mandate, consent = &g.ID, &g.Mandate, nilIfEmpty(g.Consent)
		}
		var agent *string
		if linked.Principal != nil {
			agent = &linked.Principal.Agent
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO decisions (seq, id, at, agent, "user", owner, grant_id, mandate, consent, outcome, prev, hash, doc)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, nullif($11, ''), $12, $13)`,
			linked.Chain.Seq, linked.ID, linked.Time.Time, agent, user, owner, grantID, mandate, consent,
			linked.Outcome, linked.Chain.Prev, linked.Chain.Hash, doc)
		out = linked
		return err
	})
	return out, mapErr(err)
}

func (s decisions) Get(ctx context.Context, id string) (v0.Decision, error) {
	var d v0.Decision
	err := scanJSON(s.pool.QueryRow(ctx, "SELECT doc FROM decisions WHERE id = $1", id), &d)
	return d, err
}

func (s decisions) Range(ctx context.Context, from, to uint64) ([]v0.Decision, error) {
	rows, err := s.pool.Query(ctx, "SELECT doc FROM decisions WHERE seq >= $1 AND seq < $2 ORDER BY seq", from, to)
	if err != nil {
		return nil, err
	}
	return collectJSON[v0.Decision](rows)
}

func (s decisions) Head(ctx context.Context) (v0.Decision, error) {
	var d v0.Decision
	err := scanJSON(s.pool.QueryRow(ctx, "SELECT doc FROM decisions ORDER BY seq DESC LIMIT 1"), &d)
	return d, err
}

// ---------------------------------------------------------------- approvals

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

func (s approvals) Vote(ctx context.Context, id string, v v0.Vote) (v0.Approval, error) {
	return s.update(ctx, id, func(a *v0.Approval) error {
		a.Votes = append(a.Votes, v)
		return nil
	})
}

func (s approvals) Close(ctx context.Context, id string, status v0.ApprovalStatus, at time.Time, singleUseGrant string) (v0.Approval, error) {
	if status == v0.ApprovalPending {
		return v0.Approval{}, store.ErrState
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
			return store.ErrState
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

// ---------------------------------------------------------------- counters

type counters struct{ pool *pgxpool.Pool }

func (s counters) Consume(ctx context.Context, key string, amount, max float64) (float64, error) {
	var consumed float64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO counters (key, consumed) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET consumed = counters.consumed + EXCLUDED.consumed
		WHERE counters.consumed + EXCLUDED.consumed <= $3
		RETURNING consumed`, key, amount, max).Scan(&consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, store.ErrExhausted
	}
	if err != nil {
		return 0, err
	}
	if consumed > max { // a fresh counter whose first draw is already too big
		if _, err := s.pool.Exec(ctx, "UPDATE counters SET consumed = consumed - $2 WHERE key = $1", key, amount); err != nil {
			return 0, err
		}
		return 0, store.ErrExhausted
	}
	return max - consumed, nil
}

func (s counters) Consumed(ctx context.Context, key string) (float64, error) {
	var v float64
	err := s.pool.QueryRow(ctx, "SELECT coalesce((SELECT consumed FROM counters WHERE key = $1), 0)", key).Scan(&v)
	return v, err
}

// ---------------------------------------------------------------- helpers

func scanJSON(row pgx.Row, out any) error {
	var doc []byte
	if err := row.Scan(&doc); err != nil {
		return mapErr(err)
	}
	return json.Unmarshal(doc, out)
}

func collectJSON[T any](rows pgx.Rows) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal(doc, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func timePtr(t *v0.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	tt := t.Time
	return &tt
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
