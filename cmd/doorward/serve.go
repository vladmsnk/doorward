package main

import (
	"fmt"
	"io"

	"github.com/vladmsnk/doorward/internal/cmd/server"
	"github.com/vladmsnk/doorward/internal/sealer"
)

// runServe starts the box; package server has the details.
func runServe(args []string, stdout, stderr io.Writer) int {
	return server.Serve(args, stdout, stderr, versionString())
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
