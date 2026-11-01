package telemetry

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Sampled returns a handler that passes one warning or error per message
// per window to next and drops the rest, noting on the next record that
// gets through how many were dropped (attribute "suppressed"). An outage
// then costs a few lines a second instead of two per failed call. Records
// below Warn pass unchanged.
func Sampled(next slog.Handler, window time.Duration) slog.Handler {
	return &sampled{Handler: next, state: &sampleState{window: window, seen: map[string]*sampleEntry{}, now: time.Now}}
}

type sampled struct {
	slog.Handler
	state *sampleState
}

type sampleState struct {
	window time.Duration
	now    func() time.Time
	mu     sync.Mutex
	seen   map[string]*sampleEntry
}

type sampleEntry struct {
	last    time.Time
	dropped int
}

func (s *sampled) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < slog.LevelWarn {
		return s.Handler.Handle(ctx, r)
	}
	key := r.Level.String() + "|" + r.Message
	st := s.state
	st.mu.Lock()
	e, ok := st.seen[key]
	now := st.now()
	if ok && now.Sub(e.last) < st.window {
		e.dropped++
		st.mu.Unlock()
		return nil
	}
	dropped := 0
	if !ok {
		e = &sampleEntry{}
		st.seen[key] = e
	} else {
		dropped = e.dropped
	}
	e.last, e.dropped = now, 0
	st.mu.Unlock()
	if dropped > 0 {
		r.AddAttrs(slog.Int("suppressed", dropped))
	}
	return s.Handler.Handle(ctx, r)
}

func (s *sampled) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &sampled{Handler: s.Handler.WithAttrs(attrs), state: s.state}
}

func (s *sampled) WithGroup(name string) slog.Handler {
	return &sampled{Handler: s.Handler.WithGroup(name), state: s.state}
}
