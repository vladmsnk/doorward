// Package cmd is doorward's command line: it reads arguments and files,
// calls the domain packages, and prints. doorward serve is in package
// server.
package cmd

import (
	"fmt"
	"io"

	"github.com/vladmsnk/doorward/internal/cmd/server"
	"github.com/vladmsnk/doorward/internal/sealer"
)

const usage = `usage:
  doorward validate [--kind KIND] FILE...   validate documents against the v0 schemas
  doorward serve --db DSN --admin-token T   run the box: public listener on :8080, Admin API on 127.0.0.1:8081
  doorward import mcp [flags] URL           draft a manifest from an MCP server's tools
  doorward grant mint|verify ...            sign and record a grant; run a grant's checks
  doorward journal export|verify ...        print decision records; check records and their chain
  doorward master-key                       print a new master key for DOORWARD_MASTER_KEY
  doorward version                          print the version

Configuration documents (Manifest, Agent, Mandate) name their kind. Records
need it given: --kind consent, grant, decision or approval.
`

// Run runs the command line with args, without the program name, and
// returns the exit code. version names the build.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "serve":
		return server.Serve(args[1:], stdout, stderr, version)
	case "import":
		return runImport(args[1:], stdout, stderr)
	case "grant":
		return runGrant(args[1:], stdin, stdout, stderr)
	case "journal":
		return runJournal(args[1:], stdin, stdout, stderr)
	case "master-key":
		return runMasterKey(stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "doorward: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// dispatch runs the subcommand args name, or prints usage and returns 2
// when there is none or it is unknown.
func dispatch(command, usage string, args []string, stderr io.Writer, subcommands map[string]func([]string) int) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	run, ok := subcommands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "doorward %s: unknown command %q\n\n%s", command, args[0], usage)
		return 2
	}
	return run(args[1:])
}

// runMasterKey prints a fresh master key for an operator setting up a box.
func runMasterKey(stdout, stderr io.Writer) int {
	k, err := sealer.Generate()
	if err != nil {
		fmt.Fprintf(stderr, "doorward master-key: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, k)
	return 0
}
