package sql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/x"
)

type grants struct{ pool *pgxpool.Pool }

func (s grants) Create(ctx context.Context, g grant.Record) error {
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

func (s grants) Get(ctx context.Context, jti string) (grant.Record, error) {
	var g grant.Record
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
		return x.ErrNotFound
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
		return x.ErrState
	}
	return nil
}
