package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Run(args, os.Stdin, &out, &errb, "doorward dev")
	return code, out.String(), errb.String()
}

func TestValidateReportsEveryFailure(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	doc := "apiVersion: doorward/v0\nkind: Agent\nmetadata: {name: x}\nspec: {}\n---\napiVersion: doorward/v0\nkind: Mandate\nmetadata: {name: y}\nspec: {}\n"
	if err := os.WriteFile(bad, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI("validate", bad, filepath.Join(dir, "missing.yaml"))
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for _, want := range []string{"bad.yaml#1 (Agent)", "bad.yaml#2 (Mandate)", "missing.yaml", "3 document(s) failed"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("output lacks %q:\n%s", want, errOut)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"frobnicate"}, {"validate"}, {"validate", "--kind", "policy", "x.json"}} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

// P5: the Admin API listens on this machine only unless told otherwise.
func TestAdminAPIDefaultsToLocalhost(t *testing.T) {
	_, _, stderr := runCLI("serve", "--help")
	if !strings.Contains(stderr, `(default "127.0.0.1:8081")`) {
		t.Errorf("serve --help does not show the Admin API on localhost:\n%s", stderr)
	}
}
