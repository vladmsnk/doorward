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
			return x.ErrState
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
