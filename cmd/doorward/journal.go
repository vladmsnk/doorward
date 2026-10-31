package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/schema"
)

const journalUsage = `usage:
  doorward journal export [--db DSN] [--from SEQ]   print decision records as JSON lines
  doorward journal verify FILE                      check records and their chain; FILE - reads stdin
`

func runJournal(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, journalUsage)
		return 2
	}
	switch args[0] {
	case "export":
		return runJournalExport(args[1:], stdout, stderr)
	case "verify":
		return runJournalVerify(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "doorward journal: unknown command %q\n\n%s", args[0], journalUsage)
		return 2
	}
}

// exportPage is how many records are read from the store at a time.
const exportPage = 1000

func runJournalExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("journal export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("DOORWARD_DB"), "PostgreSQL connection string (or DOORWARD_DB)")
	from := fs.Uint64("from", 0, "first sequence number to export")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	ctx := context.Background()
	st, code, ok := openStore(ctx, *dsn, "journal export", stderr)
	if !ok {
		return code
	}
	defer func() { _ = st.Close() }()
	w := bufio.NewWriter(stdout)
	defer func() { _ = w.Flush() }()
	if err := exportJournal(ctx, st.Decisions(), *from, w); err != nil {
		fmt.Fprintf(stderr, "doorward journal export: %v\n", err)
		return 1
	}
	return 0
}

// exportJournal writes the records from seq on as JSON lines.
func exportJournal(ctx context.Context, d store.Decisions, from uint64, w io.Writer) error {
	head, err := d.Head(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for seq := from; seq <= head.Chain.Seq; seq += exportPage {
		page, err := d.Range(ctx, seq, seq+exportPage)
		if err != nil {
			return err
		}
		for _, rec := range page {
			line, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if _, err := w.Write(append(line, '\n')); err != nil {
				return err
			}
		}
	}
	return nil
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
	var records []v0.Decision
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		d, err := schema.Decode[v0.Decision](v, sc.Bytes())
		if err != nil {
			fmt.Fprintf(stderr, "line %d: not a valid decision record: %v\n", n, err)
			return 1
		}
		records = append(records, d)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(stderr, "doorward journal verify: %v\n", err)
		return 2
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
