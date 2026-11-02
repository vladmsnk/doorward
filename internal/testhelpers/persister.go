package testhelpers

import (
	"context"
	"os"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/persistence/sql"
)

// OpenPersister returns the store on the database DOORWARD_TEST_POSTGRES_DSN
// names, emptied, skipping the test without one. It is closed when the
// test ends.
func OpenPersister(t testing.TB) *sql.Persister {
	t.Helper()
	dsn := os.Getenv("DOORWARD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("DOORWARD_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	s, err := sql.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Pool().Exec(ctx, "TRUNCATE "+Tables); err != nil {
		t.Fatal(err)
	}
	return s
}

// Record appends d to the journal the way the decision point does: as a
// settled decision with nothing to spend. It returns the record as
// appended, chain filled in.
func Record(t testing.TB, s journal.Settler, d v0.Decision) v0.Decision {
	t.Helper()
	out, err := s.Settle(context.Background(), nil, func([]budget.Drawn, error) (v0.Decision, error) { return d, nil })
	if err != nil {
		t.Fatalf("recording %s: %v", d.ID, err)
	}
	return out
}
