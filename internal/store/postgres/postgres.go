// Package postgres is the Store on PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vladmsnk/agentbox/internal/store"
)

// Store is a store.Store on a connection pool.
type Store struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

// Open connects, applies pending migrations, and returns the store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Documents() store.Documents { return documents{s.pool} }
func (s *Store) Consents() store.Consents   { return consents{s.pool} }
func (s *Store) Grants() store.Grants       { return grants{s.pool} }
func (s *Store) Decisions() store.Decisions { return decisions{s.pool} }
func (s *Store) Approvals() store.Approvals { return approvals{s.pool} }
func (s *Store) Counters() store.Counters   { return counters{s.pool} }
func (s *Store) Keys() store.Keys           { return signingKeys{s.pool} }
func (s *Store) Secrets() store.Secrets     { return secrets{s.pool} }

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Pool exposes the connection pool, for tests and migrations.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// mapErr turns driver errors into the store's.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return store.ErrConflict
	}
	return err
}
