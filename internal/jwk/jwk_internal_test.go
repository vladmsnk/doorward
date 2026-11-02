package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The ES256 key of RFC 7515, appendix A.3; its RFC 7638 thumbprint was
// computed independently.
var rfc7515 = JWK{Kty: "EC", Crv: "P-256", X: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", Y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}

const rfc7515Thumbprint = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"

func TestJWKEncoding(t *testing.T) {
	pub, err := rfc7515.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := publicJWK(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.X != rfc7515.X || got.Y != rfc7515.Y || got.Kid != rfc7515Thumbprint {
		t.Errorf("encoded as %+v", got)
	}

	// A fresh key goes out and comes back the same, whatever its leading
	// zero bytes.
	for range 64 {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		j, err := publicJWK(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		back, err := j.PublicKey()
		if err != nil || !back.Equal(&priv.PublicKey) {
			t.Fatalf("round trip of %+v: %v", j, err)
		}
	}

	offCurve := rfc7515
	offCurve.Y = "y_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	short := rfc7515
	short.X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVA"
	// The same bytes, spelled with the unused low bits set.
	nonCanonical := rfc7515
	nonCanonical.Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a1"
	for name, j := range map[string]JWK{"off the curve": offCurve, "a short coordinate": short, "a non-canonical encoding": nonCanonical} {
		if _, err := j.PublicKey(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
