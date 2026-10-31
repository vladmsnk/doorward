// Command doorward is the box's command-line tool: it validates documents,
// runs the box, and signs and verifies grants.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/vladmsnk/doorward/schema"
)

// Set by the release build (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = ""
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  doorward validate [--kind KIND] FILE...   validate documents against the v0 schemas
  doorward serve --db DSN --admin-token T   run the box: public listener on :8080, Admin API on 127.0.0.1:8081
  doorward grant mint|verify ...            sign and record a grant; run a grant's checks
  doorward master-key                       print a new master key for DOORWARD_MASTER_KEY
  doorward version                          print the version

Configuration documents (Manifest, Agent, Mandate) name their kind. Records
need it given: --kind consent, grant, decision or approval.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "grant":
		return runGrant(args[1:], os.Stdin, stdout, stderr)
	case "master-key":
		return runMasterKey(stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, versionString())
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "doorward: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kindFlag := fs.String("kind", "", "kind of every document: "+kindList())
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "doorward validate: no files given")
		return 2
	}

	var kind schema.Kind
	if *kindFlag != "" {
		k, err := schema.ParseKind(*kindFlag)
		if err != nil {
			fmt.Fprintf(stderr, "doorward validate: %v\n", err)
			return 2
		}
		kind = k
	}

	v, err := schema.NewValidator()
	if err != nil {
		fmt.Fprintf(stderr, "doorward validate: %v\n", err)
		return 1
	}

	failed := 0
	for _, name := range fs.Args() {
		data, err := os.ReadFile(name) // #nosec G304 -- reading the files the user named is the command's job
		if err != nil {
			fmt.Fprintf(stderr, "FAIL %v\n", err)
			failed++
			continue
		}
		sources, err := schema.Read(name, data, kind)
		if err != nil {
			fmt.Fprintf(stderr, "FAIL %v\n", err)
			failed++
			continue
		}
		for _, src := range sources {
			if err := v.Check(src.Kind, src.JSON); err != nil {
				fmt.Fprintf(stderr, "FAIL %s (%s)\n%v\n", src.Name, src.Kind, err)
				failed++
				continue
			}
			fmt.Fprintf(stdout, "ok   %s (%s)\n", src.Name, src.Kind)
		}
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "%d document(s) failed validation\n", failed)
		return 1
	}
	return 0
}

func kindList() string {
	s := ""
	for i, k := range schema.Kinds {
		if i > 0 {
			s += ", "
		}
		s += string(k)
	}
	return s
}

// versionString reports the release version, or the VCS revision for a
// development build.
func versionString() string {
	v, c := version, commit
	if c == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" {
					c = s.Value
				}
			}
		}
	}
	if c == "" {
		return "doorward " + v
	}
	return "doorward " + v + " (" + c + ")"
}
