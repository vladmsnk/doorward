package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/vladmsnk/doorward/internal/cmd"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	code := cmd.Run([]string{"version"}, os.Stdin, &out, &out, versionString())
	if code != 0 || !strings.HasPrefix(out.String(), "doorward dev") {
		t.Errorf("exit %d, output %q", code, out.String())
	}
}
