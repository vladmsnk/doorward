// Package keys manages the box's signing keys: ES256 keys created on first
// start, sealed in the database, published as a JWK Set, rotated and retired
// without a restart.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/store"
)

// Alg is the only signing algorithm v0 issues. ES256 is what every JWT
// library on the resource side understands.
const Alg = "ES256"

const purpose = "signing-key:"

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

// Signer is the active key: what signs grants now.
type Signer struct {
	KID     string
	Private *ecdsa.PrivateKey
}

// Manager keeps the active key in memory and the rest in the store.
type Manager struct {
	store  store.Keys
	sealer *sealer.Sealer

	mu     sync.RWMutex
	active *Signer
}

// New returns a manager; call Ensure before signing.
func New(s store.Keys, sl *sealer.Sealer) *Manager {
	return &Manager{store: s, sealer: sl}
}

// Ensure loads the active key, creating the first one on a fresh box.
func (m *Manager) Ensure(ctx context.Context) (*Signer, error) {
	k, err := m.store.Active(ctx)
	if errors.Is(err, store.ErrNotFound) {
		if _, err := m.Rotate(ctx); err != nil {
			return nil, err
		}
		return m.Signer(), nil
	}
	if err != nil {
		return nil, err
	}
	signer, err := m.open(k)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.active = signer
	m.mu.Unlock()
	return signer, nil
}

// Signer returns the active key, or nil before Ensure.
func (m *Manager) Signer() *Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// Rotate creates a new key and makes it the active one. Older keys stay
// published until retired, so grants they signed keep verifying.
func (m *Manager) Rotate(ctx context.Context) (JWK, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return JWK{}, err
	}
	jwk := publicJWK(&priv.PublicKey)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return JWK{}, err
	}
	sealed, err := m.sealer.Seal(der, purpose+jwk.Kid)
	if err != nil {
		return JWK{}, err
	}
	pub, err := json.Marshal(jwk)
	if err != nil {
		return JWK{}, err
	}
	if err := m.store.Create(ctx, store.SigningKey{KID: jwk.Kid, Alg: Alg, PublicJWK: pub, PrivateEnc: sealed}); err != nil {
		return JWK{}, err
	}
	m.mu.Lock()
	m.active = &Signer{KID: jwk.Kid, Private: priv}
	m.mu.Unlock()
	return jwk, nil
}

// Retire stops publishing a key. The active key cannot be retired; rotate
// first.
func (m *Manager) Retire(ctx context.Context, kid string, at time.Time) error {
	if s := m.Signer(); s != nil && s.KID == kid {
		return fmt.Errorf("key %s is the active key; rotate before retiring it", kid)
	}
	return m.store.Retire(ctx, kid, at)
}

// JWKS returns every key that is not retired, newest first.
func (m *Manager) JWKS(ctx context.Context) (Set, error) {
	keys, err := m.store.List(ctx)
	if err != nil {
		return Set{}, err
	}
	set := Set{Keys: []JWK{}}
	for _, k := range keys {
		if k.RetiredAt != nil {
			continue
		}
		var jwk JWK
		if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
			return Set{}, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

// Public returns the public key for a kid, retired or not, so a grant
// signed before a retirement can still be checked against the record.
func (m *Manager) Public(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	keys, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.KID != kid {
			continue
		}
		var jwk JWK
		if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
			return nil, err
		}
		return jwk.PublicKey()
	}
	return nil, store.ErrNotFound
}

func (m *Manager) open(k store.SigningKey) (*Signer, error) {
	der, err := m.sealer.Open(k.PrivateEnc, purpose+k.KID)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", k.KID, err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s is not an EC key", k.KID)
	}
	return &Signer{KID: k.KID, Private: priv}, nil
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
