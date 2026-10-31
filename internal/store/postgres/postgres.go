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

// configLock is the advisory lock key every configuration change holds.
const configLock = "agentbox:config"

func (s *Store) LockConfig(ctx context.Context, fn func(store.Config) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", configLock); err != nil {
			return err
		}
		return fn(configTx{tx})
	})
}

// configTx is the configuration seen through one transaction.
type configTx struct{ tx pgx.Tx }

func (c configTx) Documents() store.Documents { return documents{c.tx} }
func (c configTx) Secrets() store.Secrets     { return secrets{c.tx} }

// db is what the configuration parts need from either the pool or a
// transaction. A Begin on a transaction opens a savepoint.
type db interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

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
