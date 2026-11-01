package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSampledLogsOnePerWindow(t *testing.T) {
	var out bytes.Buffer
	h := Sampled(slog.NewJSONHandler(&out, nil), time.Second).(*sampled)
	clock := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	h.state.now = func() time.Time { return clock }
	log := slog.New(h)

	for i := 0; i < 1000; i++ {
		log.Error("evaluation failed", "n", i)
		log.Error("verifying a grant", "n", i)
		log.Info("fine", "n", i)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	errs, infos := 0, 0
	for _, l := range lines {
		switch {
		case strings.Contains(l, `"level":"ERROR"`):
			errs++
		case strings.Contains(l, `"level":"INFO"`):
			infos++
		}
	}
	if errs != 2 || infos != 1000 {
		t.Fatalf("%d error lines (want 2: one per message) and %d info lines (want 1000)", errs, infos)
	}
	// The next window's first record of a message says how many were dropped.
	out.Reset()
	clock = clock.Add(time.Second)
	log.Error("evaluation failed", "n", 1000)
	if got := out.String(); !strings.Contains(got, `"suppressed":999`) {
		t.Errorf("no suppressed count: %s", got)
	}
	// Attributes added with With share the same sampling state.
	out.Reset()
	clock = clock.Add(time.Second)
	log.With("pep", "g1").Error("evaluation failed")
	log.With("pep", "g2").Error("evaluation failed")
	if n := strings.Count(out.String(), "evaluation failed"); n != 1 {
		t.Errorf("%d lines from two loggers in one window, want 1", n)
	}
}
