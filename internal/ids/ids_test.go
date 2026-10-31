package ids_test

import (
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/vladmsnk/doorward/internal/ids"
)

// The schemas' id pattern, and the ULID shape on top of it.
var shape = regexp.MustCompile(`^grt_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func TestShapeAndOrder(t *testing.T) {
	base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	var got []string
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := ids.At(ids.Grant, base.Add(time.Duration(i)*time.Millisecond))
		if !shape.MatchString(id) {
			t.Fatalf("%q does not look like a grant id", id)
		}
		if seen[id] {
			t.Fatalf("%q made twice", id)
		}
		seen[id] = true
		got = append(got, id)
	}
	if !sort.StringsAreSorted(got) {
		t.Error("ids made later do not sort later")
	}
}

func TestKnownTime(t *testing.T) {
	// The ULID spec's example time encodes as 01ARYZ6S41.
	id := ids.At("x", time.UnixMilli(1469918176385))
	if id[2:12] != "01ARYZ6S41" {
		t.Errorf("time part %q, want 01ARYZ6S41", id[2:12])
	}
}
