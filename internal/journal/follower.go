// Package journal copies the hash-chained journal out of the database as
// JSON lines, complete and in order, so a file or a log stream holds the
// same chain the database does and verifies on its own.
package journal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// Batch is how many records one read takes.
const Batch = 500

// DefaultPoll is how often the follower looks for records it was not told
// about: those committed by another instance sharing the journal.
const DefaultPoll = 250 * time.Millisecond

// Follower writes every record from a sequence number on, in order,
// whichever instance committed it. It is told about local commits with
// Notify and polls for the rest, so a file it writes is a complete copy of
// the chain, and a restart continues where the file ended.
type Follower struct {
	src  Manager
	w    io.Writer
	poll time.Duration
	log  *slog.Logger

	mu   sync.Mutex
	next uint64
	wake chan struct{}
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

// NewFollower returns a follower that writes records from seq `from` on
// to w. Run starts it.
func NewFollower(src Manager, w io.Writer, from uint64, poll time.Duration, log *slog.Logger) *Follower {
	if poll <= 0 {
		poll = DefaultPoll
	}
	if log == nil {
		log = slog.Default()
	}
	return &Follower{src: src, w: w, poll: poll, log: log, next: from,
		wake: make(chan struct{}, 1), done: make(chan struct{}), stop: make(chan struct{})}
}

// Next is the sequence number the follower writes next.
func (f *Follower) Next() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.next
}

// Notify says a record was committed; the follower writes it soon. It
// never blocks.
func (f *Follower) Notify() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Run copies records until Close is called or ctx ends. A read or write
// that fails is retried on the next wake-up; nothing is skipped.
func (f *Follower) Run(ctx context.Context) {
	defer close(f.done)
	t := time.NewTicker(f.poll)
	defer t.Stop()
	for {
		if err := f.drain(ctx); err != nil && ctx.Err() == nil {
			f.log.Error("journal follower", "next_seq", f.Next(), "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-f.stop:
			return
		case <-f.wake:
		case <-t.C:
		}
	}
}

// Close stops Run, writes what is committed up to now, and returns. ctx
// bounds the final drain.
func (f *Follower) Close(ctx context.Context) error {
	f.once.Do(func() { close(f.stop) })
	select {
	case <-f.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return f.drain(ctx)
}

// Drain writes everything committed so far; tests and Close use it.
func (f *Follower) Drain(ctx context.Context) error { return f.drain(ctx) }

func (f *Follower) drain(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		page, err := f.src.Range(ctx, f.next, f.next+Batch)
		if err != nil {
			return err
		}
		for _, d := range page {
			if d.Chain == nil || d.Chain.Seq != f.next {
				return fmt.Errorf("journal: expected seq %d, read %v", f.next, d.Chain)
			}
			line, err := json.Marshal(d)
			if err != nil {
				return err
			}
			if _, err := f.w.Write(append(line, '\n')); err != nil {
				return err
			}
			f.next++
		}
		if len(page) < Batch {
			return nil
		}
	}
}

// Resume returns the sequence number after the last record in an existing
// journal file, or 0 for an empty one, so a follower continues where the
// file ended. It reads only the file's tail.
func Resume(r io.ReadSeeker) (uint64, error) {
	end, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	if end == 0 {
		return 0, nil
	}
	const tail = 1 << 20
	start := max(end-tail, 0)
	if _, err := r.Seek(start, io.SeekStart); err != nil {
		return 0, err
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	buf = bytes.TrimRight(buf, "\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	} else if start > 0 {
		return 0, errors.New("journal: the last line is longer than 1 MiB")
	}
	var last struct {
		Chain *v0.ChainLink `json:"chain"`
	}
	if err := json.Unmarshal(buf, &last); err != nil || last.Chain == nil {
		return 0, fmt.Errorf("journal: the last line is not a decision record: %w", err)
	}
	return last.Chain.Seq + 1, nil
}

// Read reads decision records from JSON lines, one per line, blank lines
// skipped. decode turns one line into a record and may validate it.
func Read(r io.Reader, decode func([]byte) (v0.Decision, error)) ([]v0.Decision, error) {
	var out []v0.Decision
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		d, err := decode(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, d)
	}
	return out, sc.Err()
}
