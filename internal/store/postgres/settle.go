package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/store"
)

// Every record joins one chain, so appends are serialized by one lock. One
// transaction per decision made that lock, with its commit to disk, the
// ceiling: about 550 decisions a second on a small machine, whatever the
// concurrency. The writer below groups the settlements that arrive within a
// short window into one transaction: one lock, one read of the head, one
// commit, with each settlement in its own savepoint so one failure does not
// fail the others. Under light load the window costs each decision at most
// its length; under heavy load batches fill at once.

// Batching parameters.
const (
	// BatchMax is the most settlements one transaction carries.
	BatchMax = 64
	// batchFloor is the least time a batch transaction gets, so one item
	// with little time left does not starve the others.
	batchFloor = 500 * time.Millisecond
	// batchCeiling bounds a batch transaction.
	batchCeiling = 20 * time.Second
)

type settlement struct {
	ctx    context.Context
	a      *store.Allowance
	decide func([]store.Drawn, error) (v0.Decision, error)
	done   chan outcome
}

type outcome struct {
	d   v0.Decision
	err error
}

// BatchStats counts what the writer has done, for tests and metrics.
type BatchStats struct {
	Batches     uint64
	Settlements uint64
	Largest     uint64
}

type settler struct {
	pool    beginner
	queue   chan settlement
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once

	batches     atomic.Uint64
	settlements atomic.Uint64
	largest     atomic.Uint64
}

// beginner is the part of the pool the settler needs.
type beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// settler returns the store's writer, starting it on first use.
func (s *Store) settler() *settler {
	s.settleOnce.Do(func() {
		s.writer = &settler{pool: s.pool, queue: make(chan settlement, BatchMax*4), stop: make(chan struct{}), stopped: make(chan struct{})}
		go s.writer.run()
	})
	return s.writer
}

// Batches reports what the writer has done so far.
func (s *Store) Batches() BatchStats {
	w := s.settler()
	return BatchStats{Batches: w.batches.Load(), Settlements: w.settlements.Load(), Largest: w.largest.Load()}
}

func (w *settler) settle(ctx context.Context, a *store.Allowance, decide func([]store.Drawn, error) (v0.Decision, error)) (v0.Decision, error) {
	item := settlement{ctx: ctx, a: a, decide: decide, done: make(chan outcome, 1)}
	select {
	case w.queue <- item:
	case <-ctx.Done():
		return v0.Decision{}, fmt.Errorf("%w: %w", store.ErrTimeout, ctx.Err())
	case <-w.stop:
		return v0.Decision{}, errors.New("store closed")
	}
	// Once queued, the outcome is awaited: the writer honours ctx before it
	// starts the item, and a started item is reported whatever ctx does.
	out := <-item.done
	return out.d, out.err
}

func (w *settler) close() {
	w.once.Do(func() { close(w.stop) })
	<-w.stopped
}

func (w *settler) run() {
	defer close(w.stopped)
	for {
		var first settlement
		select {
		case first = <-w.queue:
		case <-w.stop:
			w.failQueued(errors.New("store closed"))
			return
		}
		batch := w.gather(first)
		w.execute(batch)
	}
}

// gather takes the settlements already queued, up to BatchMax. It never
// waits: a lone settlement goes at once, and under load the next batch
// forms while this one runs, so batches grow with the arrival rate and
// cost nothing when there is none.
func (w *settler) gather(first settlement) []settlement {
	batch := []settlement{first}
	for len(batch) < BatchMax {
		select {
		case it := <-w.queue:
			batch = append(batch, it)
		default:
			return batch
		}
	}
	return batch
}

func (w *settler) failQueued(err error) {
	for {
		select {
		case it := <-w.queue:
			it.done <- outcome{err: err}
		default:
			return
		}
	}
}

// execute runs one batch in one transaction.
func (w *settler) execute(batch []settlement) {
	// Items whose caller already gave up are answered without work; the
	// transaction gets the longest remaining deadline among the rest, so
	// one item that is nearly out of time does not starve the others.
	live := batch[:0]
	longest := batchFloor
	for _, it := range batch {
		if it.ctx.Err() != nil {
			it.done <- outcome{err: fmt.Errorf("%w: %w", store.ErrTimeout, it.ctx.Err())}
			continue
		}
		if dl, ok := it.ctx.Deadline(); ok {
			longest = max(longest, time.Until(dl))
		} else {
			longest = batchCeiling
		}
		live = append(live, it)
	}
	if len(live) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(longest, batchCeiling))
	defer cancel()
	results := make([]outcome, len(live))
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.fail(live, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			rbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rbCtx)
		}
	}()
	if err := deadlineSQL(ctx, tx); err != nil {
		w.fail(live, err)
		return
	}
	prev, err := lockChain(ctx, tx)
	if err != nil {
		w.fail(live, err)
		return
	}
	// Two round trips for the whole batch: every item's spending goes in
	// one pipeline, then every item's record in another. The draw and
	// single-use statements never raise, they return no row when refused,
	// so a pipeline is never poisoned by a refusal.
	spent, err := spendPipelined(ctx, tx, live)
	if err != nil {
		w.fail(live, err)
		return
	}
	var records []v0.Decision
	var owners []int
	for i, it := range live {
		if it.ctx.Err() != nil {
			results[i] = outcome{err: fmt.Errorf("%w: %w", store.ErrTimeout, it.ctx.Err())}
			continue
		}
		if spent[i].refused == nil && it.a != nil && spent[i].drawn == nil {
			// Its allowance was never sent: the caller gave up before.
			results[i] = outcome{err: fmt.Errorf("%w: %w", store.ErrTimeout, context.DeadlineExceeded)}
			continue
		}
		d, err := it.decide(spent[i].drawn, spent[i].refused)
		if err != nil {
			// A refused allowance wrote nothing, an accepted one must not
			// stand without its record: the batch cannot keep this item's
			// spending, so the whole transaction is abandoned.
			if spent[i].refused == nil && it.a != nil {
				w.fail(live, fmt.Errorf("decision after spending failed: %w", err))
				return
			}
			results[i] = outcome{err: err}
			continue
		}
		linked, err := v0.Link(d, prev)
		if err != nil {
			if spent[i].refused == nil && it.a != nil {
				w.fail(live, err)
				return
			}
			results[i] = outcome{err: err}
			continue
		}
		prev = &linked
		records = append(records, linked)
		owners = append(owners, i)
	}
	if err := recordPipelined(ctx, tx, records); err != nil {
		w.fail(live, err)
		return
	}
	appended := len(records)
	for k, i := range owners {
		results[i] = outcome{d: records[k]}
	}
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCommit()
	if err := tx.Commit(commitCtx); err != nil {
		// Nothing of this batch is recorded.
		for i := range results {
			if results[i].err == nil {
				results[i] = outcome{err: mapErr(err)}
			}
		}
		w.deliver(live, results)
		return
	}
	committed = true
	w.batches.Add(1)
	w.settlements.Add(uint64(appended))
	for {
		cur := w.largest.Load()
		if uint64(appended) <= cur || w.largest.CompareAndSwap(cur, uint64(appended)) {
			break
		}
	}
	w.deliver(live, results)
}

func (w *settler) fail(items []settlement, err error) {
	for _, it := range items {
		it.done <- outcome{err: mapErr(err)}
	}
}

func (w *settler) deliver(items []settlement, results []outcome) {
	for i, it := range items {
		it.done <- results[i]
	}
}

// spending is what one item's allowance did.
type spending struct {
	drawn   []store.Drawn
	refused error
}

// spendPipelined sends every item's allowance to the database in one round
// trip and reads back what each did. An allowance is one statement that
// writes everything or nothing (spendSQL), so no item leaves partial state
// and nothing needs undoing.
func spendPipelined(ctx context.Context, tx pgx.Tx, items []settlement) ([]spending, error) {
	out := make([]spending, len(items))
	var b pgx.Batch
	var queued []int
	for i, it := range items {
		if it.a == nil || it.ctx.Err() != nil {
			continue
		}
		queueSpend(&b, *it.a)
		queued = append(queued, i)
	}
	if b.Len() == 0 {
		return out, nil
	}
	br := tx.SendBatch(ctx, &b)
	defer func() { _ = br.Close() }()
	for _, i := range queued {
		if _, err := br.Exec(); err != nil {
			return nil, err
		}
		rows, err := br.Query()
		if err != nil {
			return nil, err
		}
		drawn, err := readSpend(rows, *items[i].a)
		switch {
		case err == nil:
			out[i].drawn = drawn
		case errors.Is(err, store.ErrExhausted), errors.Is(err, store.ErrState):
			out[i].refused = err
		default:
			return nil, err
		}
	}
	return out, nil
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
func queueSpend(b *pgx.Batch, a store.Allowance) {
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
func readSpend(rows pgx.Rows, a store.Allowance) ([]store.Drawn, error) {
	defer rows.Close()
	byKey := make(map[string]store.Drawn, len(a.Draws))
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
			byKey[*key] = store.Drawn{Key: *key, Amount: amountOf(a, *key), Remaining: *after}
		case a.BestEffort && singleOK:
			byKey[*key] = store.Drawn{Key: *key, Amount: amountOf(a, *key), Remaining: *before, Exhausted: true}
		case refused == nil && singleOK:
			refused = &store.ExhaustedError{Key: *key, Amount: amountOf(a, *key), Remaining: *before}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !seen {
		return nil, errors.New("spend returned no row")
	}
	if !singleOK {
		return nil, fmt.Errorf("single-use grant %s: already spent or not single-use: %w", a.SingleUse, store.ErrState)
	}
	if refused != nil {
		return nil, refused
	}
	out := make([]store.Drawn, len(a.Draws))
	for i, d := range a.Draws {
		out[i] = byKey[d.Key]
	}
	return out, nil
}

func amountOf(a store.Allowance, key string) string {
	for _, d := range a.Draws {
		if d.Key == key {
			return d.Amount
		}
	}
	return ""
}

// recordPipelined inserts every record in one round trip. The caller holds
// the chain lock and has linked the records.
func recordPipelined(ctx context.Context, tx pgx.Tx, records []v0.Decision) error {
	if len(records) == 0 {
		return nil
	}
	var b pgx.Batch
	for _, linked := range records {
		doc, err := json.Marshal(linked)
		if err != nil {
			return err
		}
		var user, owner, grantID, mandate, consent, agent *string
		if p := linked.Principal; p != nil {
			user, owner, agent = nilIfEmpty(p.User), nilIfEmpty(p.Owner), &p.Agent
		}
		if g := linked.Grant; g != nil {
			grantID, mandate, consent = &g.ID, &g.Mandate, nilIfEmpty(g.Consent)
		}
		b.Queue(`
			INSERT INTO decisions (seq, id, at, agent, "user", owner, grant_id, mandate, consent, outcome, prev, hash, doc)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, nullif($11, ''), $12, $13)`,
			linked.Chain.Seq, linked.ID, linked.Time.Time, agent, user, owner, grantID, mandate, consent,
			linked.Outcome, linked.Chain.Prev, linked.Chain.Hash, doc)
	}
	br := tx.SendBatch(ctx, &b)
	defer func() { _ = br.Close() }()
	for n := b.Len(); n > 0; n-- {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// sortedDraws orders draws by key, so two allowances drawing the same
// budgets lock them in the same order and cannot deadlock.
func sortedDraws(draws []store.Draw) []store.Draw {
	out := slices.Clone(draws)
	slices.SortFunc(out, func(x, y store.Draw) int { return strings.Compare(x.Key, y.Key) })
	return out
}
