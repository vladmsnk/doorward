// Package sql is the Persister on PostgreSQL: one table per kind of record,
// migrations embedded in the binary, and every change that spans rows in
// one transaction.
package sql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/approval"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/consent"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/persistence"
	"github.com/vladmsnk/doorward/internal/x"
)

// Every record is stored twice over: the full document as JSON, which is
// what readers get back, and the few columns queries filter on. The columns
// are derived from the document on write and never edited on their own.

// Persister is the persistence.Persister on a PostgreSQL connection pool.
type Persister struct {
	pool *pgxpool.Pool

	settleOnce sync.Once
	writer     *settler
}

var _ persistence.Persister = (*Persister)(nil)

// Open connects, applies pending migrations, and returns the Persister.
func Open(ctx context.Context, dsn string) (*Persister, error) {
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
	return &Persister{pool: pool}, nil
}

// Ping reports whether the database answers.
func (s *Persister) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Persister) Close() error {
	if s.writer != nil {
		s.writer.close()
	}
	s.pool.Close()
	return nil
}

// Pool exposes the connection pool, for tests and migrations.
func (s *Persister) Pool() *pgxpool.Pool { return s.pool }

func (s *Persister) Documents() configuration.Manager     { return documents{s.pool} }
func (s *Persister) Consents() consent.Manager            { return consents{s.pool} }
func (s *Persister) Grants() grant.Manager                { return grants{s.pool} }
func (s *Persister) Decisions() journal.Manager           { return decisions{s.pool} }
func (s *Persister) Approvals() approval.Manager          { return approvals{s.pool} }
func (s *Persister) Counters() budget.Manager             { return counters{s.pool} }
func (s *Persister) Keys() jwk.Manager                    { return signingKeys{s.pool} }
func (s *Persister) Secrets() configuration.SecretManager { return secrets{s.pool} }

// configLock is the advisory lock key every configuration change holds.
const configLock = "doorward:config"

func (s *Persister) LockConfig(ctx context.Context, fn func(configuration.Store) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", configLock); err != nil {
			return err
		}
		return fn(configTx{tx})
	})
}

func (s *Persister) ConfigVersion(ctx context.Context) (uint64, error) {
	var v uint64
	err := s.pool.QueryRow(ctx, "SELECT version FROM config_version WHERE id = 1").Scan(&v)
	return v, err
}

// bumpConfig marks the configuration changed, inside the writer's own
// transaction.
func bumpConfig(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "UPDATE config_version SET version = version + 1, changed_at = now() WHERE id = 1")
	return err
}

// configTx is the configuration seen through one transaction.
type configTx struct{ tx pgx.Tx }

func (c configTx) Documents() configuration.Manager     { return documents{c.tx} }
func (c configTx) Secrets() configuration.SecretManager { return secrets{c.tx} }

// db is what the configuration parts need from either the pool or a
// transaction. A Begin on a transaction opens a savepoint.
type db interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// mapErr turns driver errors into the store's.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return x.ErrNotFound
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", x.ErrTimeout, err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return x.ErrConflict
		case "55P03", "57014": // lock_not_available, query_canceled (statement_timeout)
			return fmt.Errorf("%w: %s", x.ErrTimeout, pgErr.Message)
		}
	}
	return err
}

// deadlineSQL bounds how long a transaction waits for a lock, so a caller's
// deadline holds inside the database as well as around it. Without a
// deadline it sets nothing.
func deadlineSQL(ctx context.Context, tx pgx.Tx) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	left := time.Until(deadline)
	if left <= 0 {
		return fmt.Errorf("%w: no time left", x.ErrTimeout)
	}
	// SET LOCAL takes no bind parameters; the value is an integer we made.
	_, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", max(left.Milliseconds(), 1)))
	return err
}

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
