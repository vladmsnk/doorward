package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Alg is the only signing algorithm v0 issues. ES256 is what every JWT
// library on the resource side understands.
const Alg = "ES256"

// JWK is a public EC key as published (RFC 7517, RFC 7518 §6.2).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// Set is a JWK Set.
type Set struct {
	Keys []JWK `json:"keys"`
}

// publicJWK encodes a P-256 public key with its RFC 7638 thumbprint as kid.
func publicJWK(pub *ecdsa.PublicKey) (JWK, error) {
	// The uncompressed point: 0x04, then X and Y, each the curve's full
	// 32 bytes, as RFC 7518 wants the coordinates.
	point, err := pub.Bytes()
	if err != nil {
		return JWK{}, err
	}
	if len(point) != 65 {
		return JWK{}, fmt.Errorf("not a P-256 key: %d-byte point", len(point))
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:])
	// The thumbprint hashes the required members in lexicographic order
	// with no whitespace.
	canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)
	sum := sha256.Sum256([]byte(canon))
	return JWK{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: base64.RawURLEncoding.EncodeToString(sum[:]), Alg: Alg, Use: "sig"}, nil
}

// PublicKey decodes the JWK: a point on P-256, each coordinate the curve's
// full 32 bytes in canonical base64url.
func (j JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("key %s is not a P-256 key", j.Kid)
	}
	// Strict: one encoding per coordinate, so no two spellings of a key.
	x, err := base64.RawURLEncoding.Strict().DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("key %s: x: %w", j.Kid, err)
	}
	y, err := base64.RawURLEncoding.Strict().DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("key %s: y: %w", j.Kid, err)
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("key %s: a P-256 coordinate is 32 bytes", j.Kid)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("key %s is not on the curve: %w", j.Kid, err)
	}
	return pub, nil
}
