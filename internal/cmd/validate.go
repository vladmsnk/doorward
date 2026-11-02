package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/vladmsnk/doorward/schema"
)

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
