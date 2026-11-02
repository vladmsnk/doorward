// Package grant signs grants and verifies them on every call (B1).
//
// A grant travels as a compact JWS (RFC 7515) with an at+jwt header
// (RFC 9068), signed ES256 with the box's active key. Verification is
// deliberately narrow: one algorithm, one header shape, keys only from the
// box's own key table. Nothing in the token chooses how it is checked.
package grant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/schema"
)

// MaxTokenSize bounds what the parser looks at. A grant with a few
// permissions is well under 2 KiB.
const MaxTokenSize = 16 << 10

// header is the whole JOSE header the box writes and the only one it
// accepts: an unknown member, crit included, is refused.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

var b64 = base64.RawURLEncoding.Strict()

// Sign encodes g as a JWT signed by s.
func Sign(s *jwk.Signer, g v0.Grant) (string, error) {
	h, err := json.Marshal(header{Alg: jwk.Alg, Typ: v0.GrantJWTType, Kid: s.KID})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, s.Private, sum[:])
	if err != nil {
		return "", err
	}
	// JWS carries R and S as two fixed 32-byte halves, not as ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return input + "." + b64.EncodeToString(sig), nil
}

// token is a compact JWS split into its parts; nothing in it is trusted yet.
type token struct {
	header  header
	payload []byte
	input   string // what the signature covers
	sig     []byte
}

// parse splits a compact JWS and reads its header. It checks shape only.
func parse(s string) (token, error) {
	if len(s) > MaxTokenSize {
		return token{}, fmt.Errorf("token is %d bytes, more than %d", len(s), MaxTokenSize)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return token{}, errors.New("not a compact JWS: want three dot-separated parts")
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return token{}, fmt.Errorf("header: %w", err)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return token{}, fmt.Errorf("payload: %w", err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return token{}, fmt.Errorf("signature: %w", err)
	}
	h, err := readHeader(rawHeader)
	if err != nil {
		return token{}, err
	}
	return token{header: h, payload: payload, input: parts[0] + "." + parts[1], sig: sig}, nil
}

func readHeader(raw []byte) (header, error) {
	var h header
	if err := schema.CheckDuplicateKeys(raw); err != nil {
		return h, fmt.Errorf("header: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, fmt.Errorf("header: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return h, errors.New("header: trailing data")
	}
	if h.Alg != jwk.Alg {
		return h, fmt.Errorf("header: alg is %q; grants are signed %s only", h.Alg, jwk.Alg)
	}
	// RFC 9068 §2.1: typ is at+jwt; the media type form is equivalent and
	// media types compare without regard to case.
	if t := strings.ToLower(h.Typ); t != v0.GrantJWTType && t != "application/"+v0.GrantJWTType {
		return h, fmt.Errorf("header: typ is %q, not %s: this is not an access token", h.Typ, v0.GrantJWTType)
	}
	if h.Kid == "" {
		return h, errors.New("header: kid is missing")
	}
	return h, nil
}

// verifySignature checks an ES256 signature over the token's signing input.
func (t token) verifySignature(pub *ecdsa.PublicKey) bool {
	if len(t.sig) != 64 {
		return false
	}
	sum := sha256.Sum256([]byte(t.input))
	r, sv := new(big.Int).SetBytes(t.sig[:32]), new(big.Int).SetBytes(t.sig[32:])
	return ecdsa.Verify(pub, sum[:], r, sv)
}
