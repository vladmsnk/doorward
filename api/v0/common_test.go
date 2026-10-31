package v0_test

import (
	"encoding/json"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

func TestTimestampHasOneSerialization(t *testing.T) {
	// The same instant, given in another zone and with trailing zero
	// nanoseconds, must be written exactly one way.
	at := time.Date(2026, 10, 30, 11, 30, 12, 250_000_000, time.FixedZone("CEST", 2*3600))
	got, err := json.Marshal(v0.Timestamp{Time: at})
	if err != nil {
		t.Fatal(err)
	}
	if want := `"2026-10-30T09:30:12.250Z"`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}

	var back v0.Timestamp
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Equal(at) {
		t.Errorf("round trip: %v != %v", back.Time, at)
	}
	for _, bad := range []string{`"2026-10-30T09:30:12Z"`, `"2026-10-30T11:30:12.250+02:00"`, `1793352612`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestDurationIsWrittenCompactly(t *testing.T) {
	for in, want := range map[string]string{"15m": "15m", "1h": "1h", "1h30m": "1h30m", "90s": "1m30s", "500ms": "500ms"} {
		var d v0.Duration
		if err := json.Unmarshal([]byte(`"`+in+`"`), &d); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != `"`+want+`"` {
			t.Errorf("%s: got %s, want %q", in, got, want)
		}
	}
	var d v0.Duration
	if err := json.Unmarshal([]byte(`900`), &d); err == nil {
		t.Error("accepted a bare number")
	}
}
