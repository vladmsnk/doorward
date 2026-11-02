package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
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
func publicJWK(pub *ecdsa.PublicKey) JWK {
	x := base64.RawURLEncoding.EncodeToString(pad32(pub.X))
	y := base64.RawURLEncoding.EncodeToString(pad32(pub.Y))
	// The thumbprint hashes the required members in lexicographic order
	// with no whitespace.
	canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)
	sum := sha256.Sum256([]byte(canon))
	return JWK{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: base64.RawURLEncoding.EncodeToString(sum[:]), Alg: Alg, Use: "sig"}
}

// PublicKey decodes the JWK.
func (j JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("key %s is not a P-256 key", j.Kid)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("key %s is not on the curve", j.Kid)
	}
	return pub, nil
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
