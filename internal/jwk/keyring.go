// Package jwk manages the box's signing keys: ES256 keys created on first
// start, sealed in the database, published as a JWK Set (RFC 7517), rotated
// and retired without a restart.
package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
)

const purpose = "signing-key:"

// Signer is the active key: what signs grants now.
type Signer struct {
	KID     string
	Private *ecdsa.PrivateKey
}

// KeyRing keeps the active key in memory and the rest in the store.
type KeyRing struct {
	store  Manager
	sealer *sealer.Sealer

	mu     sync.RWMutex
	active *Signer
	// public caches keys by kid: a kid names one key forever, retired or
	// not, so a lookup that hit the store once need never hit it again.
	public sync.Map
}

// NewKeyRing returns a key ring over the stored keys; call Ensure before
// signing. A nil sealer is enough for looking up public keys.
func NewKeyRing(s Manager, sl *sealer.Sealer) *KeyRing {
	return &KeyRing{store: s, sealer: sl}
}

// Ensure loads the active key, creating the first one on a fresh box.
func (m *KeyRing) Ensure(ctx context.Context) (*Signer, error) {
	k, err := m.store.Active(ctx)
	if errors.Is(err, x.ErrNotFound) {
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
func (m *KeyRing) Signer() *Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// Rotate creates a new key and makes it the active one. Older keys stay
// published until retired, so grants they signed keep verifying.
func (m *KeyRing) Rotate(ctx context.Context) (JWK, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return JWK{}, err
	}
	key := publicJWK(&priv.PublicKey)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return JWK{}, err
	}
	sealed, err := m.sealer.Seal(der, purpose+key.Kid)
	if err != nil {
		return JWK{}, err
	}
	pub, err := json.Marshal(key)
	if err != nil {
		return JWK{}, err
	}
	if err := m.store.Create(ctx, SigningKey{KID: key.Kid, Alg: Alg, PublicJWK: pub, PrivateEnc: sealed}); err != nil {
		return JWK{}, err
	}
	m.mu.Lock()
	m.active = &Signer{KID: key.Kid, Private: priv}
	m.mu.Unlock()
	return key, nil
}

// Retire stops publishing a key. The active key cannot be retired; rotate
// first.
func (m *KeyRing) Retire(ctx context.Context, kid string, at time.Time) error {
	if s := m.Signer(); s != nil && s.KID == kid {
		return fmt.Errorf("key %s is the active key; rotate before retiring it", kid)
	}
	return m.store.Retire(ctx, kid, at)
}

// JWKS returns every key that is not retired, newest first.
func (m *KeyRing) JWKS(ctx context.Context) (Set, error) {
	keys, err := m.store.List(ctx)
	if err != nil {
		return Set{}, err
	}
	set := Set{Keys: []JWK{}}
	for _, k := range keys {
		if k.RetiredAt != nil {
			continue
		}
		var key JWK
		if err := json.Unmarshal(k.PublicJWK, &key); err != nil {
			return Set{}, err
		}
		set.Keys = append(set.Keys, key)
	}
	return set, nil
}

// Public returns the public key for a kid, retired or not, so a grant
// signed before a retirement can still be checked against the record.
func (m *KeyRing) Public(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if pub, ok := m.public.Load(kid); ok {
		return pub.(*ecdsa.PublicKey), nil
	}
	keys, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.KID != kid {
			continue
		}
		var key JWK
		if err := json.Unmarshal(k.PublicJWK, &key); err != nil {
			return nil, err
		}
		pub, err := key.PublicKey()
		if err != nil {
			return nil, err
		}
		m.public.Store(kid, pub)
		return pub, nil
	}
	return nil, x.ErrNotFound
}

func (m *KeyRing) open(k SigningKey) (*Signer, error) {
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
