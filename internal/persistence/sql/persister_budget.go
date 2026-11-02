package sql

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/x"
)

type counters struct{ pool *pgxpool.Pool }

func (s counters) Consumed(ctx context.Context, key string) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx, "SELECT trim_scale(coalesce((SELECT consumed FROM counters WHERE key = $1), 0))::text", key).Scan(&v)
	return v, err
}

// Allow spends a call's single-use grant and draws its budgets in one
// transaction.
func (s *Persister) Allow(ctx context.Context, a budget.Allowance) ([]budget.Drawn, error) {
	var out []budget.Drawn
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) (err error) {
		out, err = allowTx(ctx, tx, a)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// allowTx spends one allowance inside tx, all or nothing (or, best effort,
// every budget that fits): the two statements of spendStatements, read
// back with readSpend.
func allowTx(ctx context.Context, tx pgx.Tx, a budget.Allowance) ([]budget.Drawn, error) {
	var b pgx.Batch
	queueSpend(&b, a)
	br := tx.SendBatch(ctx, &b)
	defer func() { _ = br.Close() }()
	if _, err := br.Exec(); err != nil {
		return nil, err
	}
	rows, err := br.Query()
	if err != nil {
		return nil, err
	}
	return readSpend(rows, a)
}

// spendSQL spends one allowance in one statement. Every budget row is
// locked in key order (two allowances sharing budgets lock them in the same
// order and cannot deadlock); the single-use grant row, if any, is locked
// too. Then, all or nothing: every budget has room and the grant is
// unspent, or no row changes. Best effort ($6) instead draws each budget
// that has room on its own, and still spends the grant. The statement
// never raises for a refusal: the gate columns say what happened.
//
// $1 keys, $2 amounts, $3 maxes (parallel arrays, sorted by key);
// $4 single-use jti or ”; $5 time; $6 best effort.
const spendSQL = `
WITH want AS (
    SELECT key, amount, max, ord
    FROM unnest($1::text[], $2::numeric[], $3::numeric[]) WITH ORDINALITY AS w(key, amount, max, ord)
), locked AS (
    SELECT c.key, c.consumed, w.amount, w.max, w.ord
    FROM want w JOIN counters c ON c.key = w.key
    ORDER BY w.key
    FOR UPDATE OF c
), single AS (
    SELECT count(*) AS n FROM (
        SELECT 1 FROM grants WHERE $4 <> '' AND jti = $4 AND single_use AND used_at IS NULL FOR UPDATE
    ) g
), gate AS (
    SELECT ($4 = '' OR (SELECT n FROM single) = 1) AS single_ok,
           coalesce(bool_and(consumed + amount <= max), true) AS all_fit
    FROM locked
), upd AS (
    UPDATE counters c SET consumed = c.consumed + l.amount
    FROM locked l, gate g
    WHERE c.key = l.key AND g.single_ok AND (g.all_fit OR ($6 AND l.consumed + l.amount <= l.max))
    RETURNING c.key
), spend AS (
    UPDATE grants SET used_at = $5
    FROM gate g
    WHERE $4 <> '' AND jti = $4 AND single_use AND used_at IS NULL AND g.single_ok AND (g.all_fit OR $6)
    RETURNING 1
)
SELECT g.single_ok, g.all_fit, l.ord, l.key,
       trim_scale(l.max - l.consumed)::text            AS before,
       (u.key IS NOT NULL)                              AS drawn,
       trim_scale(l.max - l.consumed - l.amount)::text AS after
FROM gate g
LEFT JOIN locked l ON true
LEFT JOIN upd u ON u.key = l.key
ORDER BY l.ord`

// queueSpend adds an allowance's two statements to a batch: make sure every
// budget row exists (so it can be locked), then spend.
func queueSpend(b *pgx.Batch, a budget.Allowance) {
	draws := sortedDraws(a.Draws)
	keys := make([]string, len(draws))
	amounts := make([]string, len(draws))
	maxes := make([]string, len(draws))
	for i, d := range draws {
		keys[i], amounts[i], maxes[i] = d.Key, d.Amount, d.Max
	}
	b.Queue("INSERT INTO counters (key, consumed) SELECT unnest($1::text[]), 0 ON CONFLICT (key) DO NOTHING", keys)
	b.Queue(spendSQL, keys, amounts, maxes, a.SingleUse, a.At, a.BestEffort)
}

// readSpend turns spendSQL's rows into what was drawn, or the refusal.
func readSpend(rows pgx.Rows, a budget.Allowance) ([]budget.Drawn, error) {
	defer rows.Close()
	byKey := make(map[string]budget.Drawn, len(a.Draws))
	var refused error
	singleOK, allFit, seen := true, true, false
	for rows.Next() {
		var ord *int64
		var key, before, after *string
		var drawn *bool
		if err := rows.Scan(&singleOK, &allFit, &ord, &key, &before, &drawn, &after); err != nil {
			return nil, err
		}
		seen = true
		if key == nil {
			continue // no budgets: the single-use gate alone
		}
		switch {
		case drawn != nil && *drawn:
			byKey[*key] = budget.Drawn{Key: *key, Amount: amountOf(a, *key), Remaining: *after}
		case a.BestEffort && singleOK:
			byKey[*key] = budget.Drawn{Key: *key, Amount: amountOf(a, *key), Remaining: *before, Exhausted: true}
		case refused == nil && singleOK:
			refused = &budget.ExhaustedError{Key: *key, Amount: amountOf(a, *key), Remaining: *before}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !seen {
		return nil, errors.New("spend returned no row")
	}
	if !singleOK {
		return nil, fmt.Errorf("single-use grant %s: already spent or not single-use: %w", a.SingleUse, x.ErrState)
	}
	if refused != nil {
		return nil, refused
	}
	out := make([]budget.Drawn, len(a.Draws))
	for i, d := range a.Draws {
		out[i] = byKey[d.Key]
	}
	return out, nil
}

func amountOf(a budget.Allowance, key string) string {
	for _, d := range a.Draws {
		if d.Key == key {
			return d.Amount
		}
	}
	return ""
}

// sortedDraws orders draws by key, so two allowances drawing the same
// budgets lock them in the same order and cannot deadlock.
func sortedDraws(draws []budget.Draw) []budget.Draw {
	out := slices.Clone(draws)
	slices.SortFunc(out, func(x, y budget.Draw) int { return strings.Compare(x.Key, y.Key) })
	return out
}
