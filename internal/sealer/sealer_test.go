package sealer_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/vladmsnk/doorward/internal/sealer"
)

func TestSealAndOpen(t *testing.T) {
	keyHex, err := sealer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := sealer.Parse(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal([]byte("api-key-123"), "secret:ledger")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("api-key")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	pt, err := s.Open(ct, "secret:ledger")
	if err != nil || string(pt) != "api-key-123" {
		t.Fatalf("Open: %q %v", pt, err)
	}
	// Two seals of the same value differ (fresh nonce).
	ct2, _ := s.Seal([]byte("api-key-123"), "secret:ledger")
	if bytes.Equal(ct, ct2) {
		t.Error("identical ciphertexts for two seals")
	}
	// Another purpose cannot open it.
	if _, err := s.Open(ct, "key:abc"); err == nil {
		t.Error("opened under another purpose")
	}
	// Another master key cannot open it.
	other, _ := sealer.Parse(mustGenerate(t))
	if _, err := other.Open(ct, "secret:ledger"); err == nil {
		t.Error("opened with another master key")
	}
	// One flipped byte is noticed.
	ct[len(ct)-1] ^= 1
	if _, err := s.Open(ct, "secret:ledger"); err == nil {
		t.Error("tampered ciphertext opened")
	}
}

func TestParseAcceptsHexAndBase64(t *testing.T) {
	raw, _ := hex.DecodeString(mustGenerate(t))
	for _, enc := range []string{hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)} {
		if _, err := sealer.Parse(enc); err != nil {
			t.Errorf("Parse(%q): %v", enc, err)
		}
	}
	for _, bad := range []string{"", "abc", hex.EncodeToString(raw[:16])} {
		if _, err := sealer.Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func mustGenerate(t *testing.T) string {
	t.Helper()
	k, err := sealer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
