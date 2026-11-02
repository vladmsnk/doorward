package sql

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/x"
)

type decisions struct{ pool *pgxpool.Pool }

// ChainLock is the advisory lock key that serializes appends to the
// journal, so each record sees the true head. It is exported so an operator
// can find waits on it in pg_locks, and tests can hold it.
const ChainLock = 0x444543495349 // "DECISI"

func (s decisions) Append(ctx context.Context, d v0.Decision) (v0.Decision, error) {
	var out v0.Decision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) (err error) {
		out, err = appendTx(ctx, tx, d)
		return err
	})
	return out, mapErr(err)
}

// appendTx appends d as the next link, under the chain lock, inside tx.
func appendTx(ctx context.Context, tx pgx.Tx, d v0.Decision) (v0.Decision, error) {
	prev, err := lockChain(ctx, tx)
	if err != nil {
		return d, err
	}
	return linkAndInsert(ctx, tx, d, prev)
}

// lockChain takes the chain lock for tx and returns the head record, nil
// on an empty journal.
func lockChain(ctx context.Context, tx pgx.Tx) (*v0.Decision, error) {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", ChainLock); err != nil {
		return nil, err
	}
	var head v0.Decision
	err := scanJSON(tx.QueryRow(ctx, "SELECT doc FROM decisions ORDER BY seq DESC LIMIT 1"), &head)
	switch {
	case err == nil:
		return &head, nil
	case errors.Is(err, x.ErrNotFound):
		return nil, nil
	default:
		return nil, err
	}
}

// linkAndInsert chains d after prev and stores it. The caller holds the
// chain lock.
func linkAndInsert(ctx context.Context, tx pgx.Tx, d v0.Decision, prev *v0.Decision) (v0.Decision, error) {
	linked, err := v0.Link(d, prev)
	if err != nil {
		return d, err
	}
	args, err := decisionRow(linked)
	if err != nil {
		return d, err
	}
	_, err = tx.Exec(ctx, insertDecisionSQL, args...)
	return linked, err
}

// insertDecisionSQL stores one linked record; decisionRow gives its
// arguments.
const insertDecisionSQL = `
	INSERT INTO decisions (seq, id, at, agent, "user", owner, grant_id, mandate, consent, outcome, prev, hash, doc)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, nullif($11, ''), $12, $13)`

// decisionRow is a linked record as insertDecisionSQL's arguments: the
// columns queries filter on, derived from the record, then the record.
func decisionRow(linked v0.Decision) ([]any, error) {
	doc, err := json.Marshal(linked)
	if err != nil {
		return nil, err
	}
	var user, owner, grantID, mandate, consent, agent *string
	if p := linked.Principal; p != nil {
		user, owner, agent = nilIfEmpty(p.User), nilIfEmpty(p.Owner), &p.Agent
	}
	if g := linked.Grant; g != nil {
		grantID, mandate, consent = &g.ID, &g.Mandate, nilIfEmpty(g.Consent)
	}
	return []any{linked.Chain.Seq, linked.ID, linked.Time.Time, agent, user, owner, grantID, mandate, consent,
		linked.Outcome, linked.Chain.Prev, linked.Chain.Hash, doc}, nil
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
