package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vladmsnk/agentbox/internal/store"
)

// ---------------------------------------------------------------- signing keys

type signingKeys struct{ pool *pgxpool.Pool }

func (s signingKeys) Create(ctx context.Context, k store.SigningKey) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO signing_keys (kid, alg, public_jwk, private_enc) VALUES ($1, $2, $3, $4)",
		k.KID, k.Alg, k.PublicJWK, k.PrivateEnc)
	return mapErr(err)
}

func (s signingKeys) Active(ctx context.Context) (store.SigningKey, error) {
	return scanKey(s.pool.QueryRow(ctx,
		"SELECT kid, alg, public_jwk, private_enc, created_at, retired_at FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1"))
}

func (s signingKeys) List(ctx context.Context) ([]store.SigningKey, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT kid, alg, public_jwk, private_enc, created_at, retired_at FROM signing_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SigningKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s signingKeys) Retire(ctx context.Context, kid string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, "UPDATE signing_keys SET retired_at = $2 WHERE kid = $1 AND retired_at IS NULL", kid, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func scanKey(row pgx.Row) (store.SigningKey, error) {
	var k store.SigningKey
	err := row.Scan(&k.KID, &k.Alg, &k.PublicJWK, &k.PrivateEnc, &k.CreatedAt, &k.RetiredAt)
	return k, mapErr(err)
}

// ---------------------------------------------------------------- secrets

type secrets struct{ pool *pgxpool.Pool }

func (s secrets) Put(ctx context.Context, name string, sealed []byte, by string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO secrets (name, value_enc, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		name, sealed, by)
	return err
}

func (s secrets) Get(ctx context.Context, name string) ([]byte, error) {
	var sealed []byte
	err := s.pool.QueryRow(ctx, "SELECT value_enc FROM secrets WHERE name = $1", name).Scan(&sealed)
	return sealed, mapErr(err)
}

func (s secrets) List(ctx context.Context) ([]store.SecretInfo, error) {
	rows, err := s.pool.Query(ctx, "SELECT name, created_at, updated_at, updated_by FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SecretInfo
	for rows.Next() {
		var i store.SecretInfo
		if err := rows.Scan(&i.Name, &i.CreatedAt, &i.UpdatedAt, &i.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s secrets) Delete(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM secrets WHERE name = $1", name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}
