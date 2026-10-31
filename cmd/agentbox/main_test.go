package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestValidateExamples(t *testing.T) {
	glob := func(pattern string) []string {
		files, _ := filepath.Glob("../../examples/v0/" + pattern)
		return files
	}
	for _, tc := range []struct {
		args  []string
		files []string
	}{
		{nil, glob("config/*.yaml")},
		{[]string{"--kind", "taskrequest"}, glob("taskrequest/*.json")},
		{[]string{"--kind", "grant"}, glob("grant/*.json")},
		{[]string{"--kind", "decision"}, glob("decision/*.json")},
		{[]string{"--kind", "approval"}, glob("approval/*.json")},
	} {
		if len(tc.files) == 0 {
			t.Fatal("no example files found")
		}
		args := append(append([]string{"validate"}, tc.args...), tc.files...)
		code, out, errOut := runCLI(args...)
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		if n := strings.Count(out, "ok   "); n != len(tc.files) {
			t.Errorf("%d ok lines for %d files:\n%s", n, len(tc.files), out)
		}
	}
}

func TestValidateReportsEveryFailure(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	doc := "apiVersion: agentbox/v0\nkind: Agent\nmetadata: {name: x}\nspec: {}\n---\napiVersion: agentbox/v0\nkind: TaskType\nmetadata: {name: y}\nspec: {}\n"
	if err := os.WriteFile(bad, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI("validate", bad, filepath.Join(dir, "missing.yaml"))
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for _, want := range []string{"bad.yaml#1 (Agent)", "bad.yaml#2 (TaskType)", "missing.yaml", "3 document(s) failed"} {
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

func TestVersion(t *testing.T) {
	code, out, _ := runCLI("version")
	if code != 0 || !strings.HasPrefix(out, "agentbox dev") {
		t.Errorf("exit %d, output %q", code, out)
	}
}
