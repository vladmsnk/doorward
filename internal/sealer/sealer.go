// Package sealer encrypts what the database must not hold in clear: the
// box's private signing keys and the secrets the gateway presents to
// upstreams. One master key, held by the operator and given to the process
// at start, seals everything; the database holds only ciphertext.
package sealer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// KeySize is the master key's length: AES-256.
const KeySize = 32

// Sealer seals and opens with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
}

// New takes the master key as 32 raw bytes.
func New(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Parse accepts the master key as 64 hex characters or as base64 of 32
// bytes, which is how an operator passes it in an environment variable.
func Parse(s string) (*Sealer, error) {
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == KeySize {
		return New(raw)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == KeySize {
			return New(raw)
		}
	}
	return nil, errors.New("master key must be 32 bytes, as 64 hex characters or base64")
}

// Generate returns a fresh master key as hex, for an operator setting up a
// box.
func Generate() (string, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Seal encrypts plaintext. purpose is bound into the ciphertext, so a
// value sealed as one thing cannot be opened as another: a secret cannot
// be swapped into a key's slot by someone who can write to the database.
func (s *Sealer) Seal(plaintext []byte, purpose string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(purpose)), nil
}

// Open decrypts what Seal produced under the same purpose.
func (s *Sealer) Open(ciphertext []byte, purpose string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := s.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(purpose))
	if err != nil {
		return nil, errors.New("cannot open: wrong master key, wrong purpose, or tampered data")
	}
	return plain, nil
}
