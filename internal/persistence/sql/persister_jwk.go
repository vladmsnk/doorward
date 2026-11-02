package sql

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/x"
)

type signingKeys struct{ pool *pgxpool.Pool }

func (s signingKeys) Create(ctx context.Context, k jwk.SigningKey) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO signing_keys (kid, alg, public_jwk, private_enc) VALUES ($1, $2, $3, $4)",
		k.KID, k.Alg, k.PublicJWK, k.PrivateEnc)
	return mapErr(err)
}

func (s signingKeys) Active(ctx context.Context) (jwk.SigningKey, error) {
	return scanKey(s.pool.QueryRow(ctx,
		"SELECT kid, alg, public_jwk, private_enc, created_at, retired_at FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1"))
}

func (s signingKeys) List(ctx context.Context) ([]jwk.SigningKey, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT kid, alg, public_jwk, private_enc, created_at, retired_at FROM signing_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []jwk.SigningKey
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
		return x.ErrNotFound
	}
	return nil
}

func scanKey(row pgx.Row) (jwk.SigningKey, error) {
	var k jwk.SigningKey
	err := row.Scan(&k.KID, &k.Alg, &k.PublicJWK, &k.PrivateEnc, &k.CreatedAt, &k.RetiredAt)
	return k, mapErr(err)
}
