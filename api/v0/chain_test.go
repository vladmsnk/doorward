package v0_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	v0 "github.com/vladmsnk/agentbox/api/v0"
)

func loadDecisions(t *testing.T) []v0.Decision {
	t.Helper()
	paths, err := filepath.Glob("../../examples/v0/decision/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatal("no decision examples")
	}
	sort.Strings(paths)
	var out []v0.Decision
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var d v0.Decision
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		d.Chain = nil // the examples carry placeholder hashes
		out = append(out, d)
	}
	return out
}

func TestChainLinksAndVerifies(t *testing.T) {
	var prev *v0.Decision
	var chain []v0.Decision
	for _, d := range loadDecisions(t) {
		linked, err := v0.Link(d, prev)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, linked)
		prev = &chain[len(chain)-1]
	}
	if chain[0].Chain.Seq != 0 || chain[0].Chain.Prev != "" {
		t.Errorf("first record: %+v", chain[0].Chain)
	}
	if chain[1].Chain.Prev != chain[0].Chain.Hash || chain[1].Chain.Seq != 1 {
		t.Errorf("second record does not follow the first: %+v", chain[1].Chain)
	}
	if bad, err := v0.Verify(chain); bad != -1 {
		t.Fatalf("valid chain rejected at %d: %v", bad, err)
	}

	// Hashes are deterministic.
	again, _ := v0.Link(loadDecisions(t)[0], nil)
	if again.Chain.Hash != chain[0].Chain.Hash {
		t.Error("the same record hashed differently twice")
	}

	// Tampering with a record's content breaks its own hash.
	tampered := append([]v0.Decision(nil), chain...)
	tampered[1].Outcome = v0.OutcomeAllow
	if bad, _ := v0.Verify(tampered); bad != 1 {
		t.Errorf("edited record not caught: bad=%d", bad)
	}

	// Removing a record breaks the link of the next one.
	gap := append([]v0.Decision(nil), chain[0], chain[2], chain[3])
	if bad, _ := v0.Verify(gap); bad != 1 {
		t.Errorf("missing record not caught: bad=%d", bad)
	}
}

func TestDigest(t *testing.T) {
	// SHA-256("") in base64url without padding.
	if got := v0.Digest(nil); got != "sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Errorf("Digest(\"\") = %s", got)
	}
}
