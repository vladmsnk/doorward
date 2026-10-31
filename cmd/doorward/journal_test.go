package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/schema"
)

func TestJournalExportAndVerify(t *testing.T) {
	dsn, _, st := grantEnv(t)
	ctx := context.Background()
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	// Three records appended as the decision point would.
	for i, f := range []string{"1-allow-get-invoice.json", "2-deny-amount-over-grant.json", "3-approval-required-pay-invoice.json"} {
		data, err := os.ReadFile(filepath.Join("../../examples/v0/decision", f))
		if err != nil {
			t.Fatal(err)
		}
		d, err := schema.Decode[v0.Decision](v, data)
		if err != nil {
			t.Fatal(err)
		}
		d.ID, d.Chain = []string{"dec_journal_test_00000001", "dec_journal_test_00000002", "dec_journal_test_00000003"}[i], nil
		if _, err := st.Decisions().Append(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	code, out, stderr := runCLI("journal", "export", "--db", dsn)
	if code != 0 || strings.Count(out, "\n") != 3 {
		t.Fatalf("export: %d %s\n%s", code, stderr, out)
	}
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := os.WriteFile(journal, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	code, got, _ := runCLI("journal", "verify", journal)
	if code != 0 || !strings.Contains(got, "3 records valid, chain intact from seq 0 to 2") {
		t.Fatalf("verify: %d %s", code, got)
	}
	// From seq 1 on: still a chain, starting later.
	if code, out, _ := runCLI("journal", "export", "--db", dsn, "--from", "1"); code != 0 || strings.Count(out, "\n") != 2 {
		t.Errorf("export --from 1: %d\n%s", code, out)
	}

	// A changed value breaks the chain; a dropped record breaks the links.
	tampered := strings.Replace(out, `"amount":7500`, `"amount":75`, 1)
	if tampered == out {
		t.Fatal("nothing to tamper with")
	}
	if err := os.WriteFile(journal, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI("journal", "verify", journal); code != 1 || !strings.Contains(stderr, "hash does not match") {
		t.Errorf("tampered record: %d %s", code, stderr)
	}
	lines := strings.SplitAfter(out, "\n")
	if err := os.WriteFile(journal, []byte(lines[0]+lines[2]), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI("journal", "verify", journal); code != 1 || !strings.Contains(stderr, "does not follow") {
		t.Errorf("dropped record: %d %s", code, stderr)
	}
}
