// Command doorward is the box's command-line tool: it validates documents,
// runs the box, and signs and verifies grants. The commands are in
// internal/cmd; this file only names the build.
package main

import (
	"os"
	"runtime/debug"

	"github.com/vladmsnk/doorward/internal/cmd"
)

// Set by the release build (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = ""
)

func main() {
	os.Exit(cmd.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, versionString()))
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
