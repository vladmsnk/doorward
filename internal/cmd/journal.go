package cmd

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/schema"
)

const journalUsage = `usage:
  doorward journal export [--db DSN] [--from SEQ]   print decision records as JSON lines
  doorward journal verify FILE                      check records and their chain; FILE - reads stdin
`

func runJournal(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return dispatch("journal", journalUsage, args, stderr, map[string]func([]string) int{
		"export": func(a []string) int { return runJournalExport(a, stdout, stderr) },
		"verify": func(a []string) int { return runJournalVerify(a, stdin, stdout, stderr) },
	})
}

func runJournalExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("journal export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("DOORWARD_DB"), "PostgreSQL connection string (or DOORWARD_DB)")
	from := fs.Uint64("from", 0, "first sequence number to export")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	ctx := context.Background()
	reg, code, ok := openRegistry(ctx, &config.DefaultProvider{DSN: *dsn}, nil, "journal export", stderr)
	if !ok {
		return code
	}
	defer func() { _ = reg.Close() }()
	w := bufio.NewWriter(stdout)
	defer func() { _ = w.Flush() }()
	if err := journal.Export(ctx, reg.JournalManager(), *from, w); err != nil {
		fmt.Fprintf(stderr, "doorward journal export: %v\n", err)
		return 1
	}
	return 0
}

func runJournalVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprint(stderr, journalUsage)
		return 2
	}
	in := stdin
	if args[0] != "-" {
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(stderr, "doorward journal verify: %v\n", err)
			return 2
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	v, err := schema.NewValidator()
	if err != nil {
		fmt.Fprintf(stderr, "doorward journal verify: %v\n", err)
		return 1
	}
	records, err := journal.Read(in, func(line []byte) (v0.Decision, error) {
		d, err := schema.Decode[v0.Decision](v, line)
		if err != nil {
			return d, fmt.Errorf("not a valid decision record: %w", err)
		}
		return d, nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "doorward journal verify: %v\n", err)
		return 1
	}
	// Lines may arrive in any order (several files concatenated): the chain
	// is checked in sequence order, and a sequence number seen twice is
	// reported as such.
	sort.SliceStable(records, func(i, j int) bool { return records[i].Chain.Seq < records[j].Chain.Seq })
	for i := 1; i < len(records); i++ {
		if records[i].Chain.Seq == records[i-1].Chain.Seq {
			fmt.Fprintf(stderr, "seq %d appears twice (%s and %s)\n", records[i].Chain.Seq, records[i-1].ID, records[i].ID)
			return 1
		}
	}
	if len(records) == 0 {
		fmt.Fprintln(stdout, "no records")
		return 0
	}
	if broken, err := v0.Verify(records); broken != -1 {
		fmt.Fprintf(stderr, "chain broken: %v\n", err)
		return 1
	}
	last := records[len(records)-1].Chain
	fmt.Fprintf(stdout, "%d records valid, chain intact from seq %d to %d, head hash %s\n", len(records), records[0].Chain.Seq, last.Seq, last.Hash)
	return 0
}
