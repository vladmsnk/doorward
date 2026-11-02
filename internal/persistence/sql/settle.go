package sql

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/x"
)

// Every record joins one chain, so appends are serialized by one lock. One
// transaction per decision made that lock, with its commit to disk, the
// ceiling: about 550 decisions a second on a small machine, whatever the
// concurrency. Instead, the writer below takes the settlements that arrived
// while the previous batch was committing (up to BatchMax) and settles them
// in one transaction: one lock, one read of the head, every allowance in one
// pipelined round trip, every record in another, one commit. A lone
// settlement goes at once; batches grow with the arrival rate. Each
// allowance is one statement that writes all of its spending or none of it
// (spendSQL), so no item leaves partial state whatever happens to the
// others.

// Settle hands the settlement to the store's writer, which groups
// settlements arriving together into one transaction (see settle.go), and
// waits for the outcome. A caller whose context ends before its turn gets
// ErrTimeout and nothing is done for it; once its turn has started, the
// outcome is reported whatever happens to the context.
func (s *Persister) Settle(ctx context.Context, a *budget.Allowance, decide func([]budget.Drawn, error) (v0.Decision, error)) (v0.Decision, error) {
	return s.settler().settle(ctx, a, decide)
}

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
	a      *budget.Allowance
	decide func([]budget.Drawn, error) (v0.Decision, error)
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
func (s *Persister) settler() *settler {
	s.settleOnce.Do(func() {
		s.writer = &settler{pool: s.pool, queue: make(chan settlement, BatchMax*4), stop: make(chan struct{}), stopped: make(chan struct{})}
		go s.writer.run()
	})
	return s.writer
}

// Batches reports what the writer has done so far.
func (s *Persister) Batches() BatchStats {
	w := s.settler()
	return BatchStats{Batches: w.batches.Load(), Settlements: w.settlements.Load(), Largest: w.largest.Load()}
}

func (w *settler) settle(ctx context.Context, a *budget.Allowance, decide func([]budget.Drawn, error) (v0.Decision, error)) (v0.Decision, error) {
	item := settlement{ctx: ctx, a: a, decide: decide, done: make(chan outcome, 1)}
	select {
	case w.queue <- item:
	case <-ctx.Done():
		return v0.Decision{}, fmt.Errorf("%w: %w", x.ErrTimeout, ctx.Err())
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
			it.done <- outcome{err: fmt.Errorf("%w: %w", x.ErrTimeout, it.ctx.Err())}
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
			results[i] = outcome{err: fmt.Errorf("%w: %w", x.ErrTimeout, it.ctx.Err())}
			continue
		}
		if spent[i].refused == nil && it.a != nil && spent[i].drawn == nil {
			// Its allowance was never sent: the caller gave up before.
			results[i] = outcome{err: fmt.Errorf("%w: %w", x.ErrTimeout, context.DeadlineExceeded)}
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
	drawn   []budget.Drawn
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
		case errors.Is(err, budget.ErrExhausted), errors.Is(err, x.ErrState):
			out[i].refused = err
		default:
			return nil, err
		}
	}
	return out, nil
}

// recordPipelined inserts every record in one round trip. The caller holds
// the chain lock and has linked the records.
func recordPipelined(ctx context.Context, tx pgx.Tx, records []v0.Decision) error {
	if len(records) == 0 {
		return nil
	}
	var b pgx.Batch
	for _, linked := range records {
		args, err := decisionRow(linked)
		if err != nil {
			return err
		}
		b.Queue(insertDecisionSQL, args...)
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
