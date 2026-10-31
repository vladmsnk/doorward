package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vladmsnk/agentbox/internal/keys"
	"github.com/vladmsnk/agentbox/internal/sealer"
	"github.com/vladmsnk/agentbox/internal/store"
)

// memKeys is an in-memory store.Keys, enough to test the manager's logic
// without a database; the Postgres store has its own tests.
type memKeys struct {
	mu   sync.Mutex
	keys []store.SigningKey
}

func (m *memKeys) Create(_ context.Context, k store.SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k.CreatedAt = time.Now()
	m.keys = append(m.keys, k)
	return nil
}

func (m *memKeys) Active(context.Context) (store.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.keys) - 1; i >= 0; i-- {
		if m.keys[i].RetiredAt == nil {
			return m.keys[i], nil
		}
	}
	return store.SigningKey{}, store.ErrNotFound
}

func (m *memKeys) List(context.Context) ([]store.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SigningKey, len(m.keys))
	for i := range m.keys {
		out[len(m.keys)-1-i] = m.keys[i]
	}
	return out, nil
}

func (m *memKeys) Retire(_ context.Context, kid string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.keys {
		if m.keys[i].KID == kid {
			m.keys[i].RetiredAt = &at
			return nil
		}
	}
	return store.ErrNotFound
}

func newSealer(t *testing.T) *sealer.Sealer {
	t.Helper()
	k, _ := sealer.Generate()
	s, err := sealer.Parse(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEnsureCreatesOnceAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	st, sl := &memKeys{}, newSealer(t)

	first, err := keys.New(st, sl).Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A "restart": a new manager over the same store and master key.
	again, err := keys.New(st, sl).Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.KID != first.KID || !again.Private.Equal(first.Private) {
		t.Fatal("restart produced a different key")
	}
	if len(st.keys) != 1 {
		t.Fatalf("%d keys stored", len(st.keys))
	}
	// A restart with the wrong master key cannot open it.
	if _, err := keys.New(st, newSealer(t)).Ensure(ctx); err == nil {
		t.Fatal("opened the key with another master key")
	}
}

func TestSignVerifyAndJWKS(t *testing.T) {
	ctx := context.Background()
	m := keys.New(&memKeys{}, newSealer(t))
	signer, err := m.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("a grant"))
	sig, err := ecdsa.SignASN1(rand.Reader, signer.Private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	set, err := m.JWKS(ctx)
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("JWKS: %+v %v", set, err)
	}
	jwk := set.Keys[0]
	if jwk.Kid != signer.KID || jwk.Alg != "ES256" || jwk.Use != "sig" || jwk.Kty != "EC" || jwk.Crv != "P-256" {
		t.Errorf("published key: %+v", jwk)
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("signature does not verify with the published key")
	}
	// The kid is the RFC 7638 thumbprint, so it is 43 base64url characters.
	if len(jwk.Kid) != 43 {
		t.Errorf("kid %q is not a thumbprint", jwk.Kid)
	}
}

func TestRotateAndRetire(t *testing.T) {
	ctx := context.Background()
	m := keys.New(&memKeys{}, newSealer(t))
	first, _ := m.Ensure(ctx)

	rotated, err := m.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Signer().KID != rotated.Kid || rotated.Kid == first.KID {
		t.Fatal("rotation did not switch the active key")
	}
	set, _ := m.JWKS(ctx)
	if len(set.Keys) != 2 || set.Keys[0].Kid != rotated.Kid {
		t.Errorf("after rotation the set should hold both keys, newest first: %+v", set)
	}
	if err := m.Retire(ctx, rotated.Kid, time.Now()); err == nil {
		t.Error("retired the active key")
	}
	if err := m.Retire(ctx, first.KID, time.Now()); err != nil {
		t.Fatal(err)
	}
	set, _ = m.JWKS(ctx)
	if len(set.Keys) != 1 {
		t.Errorf("retired key still published: %+v", set)
	}
	// A retired key can still be looked up to check an old signature.
	if _, err := m.Public(ctx, first.KID); err != nil {
		t.Errorf("Public(retired): %v", err)
	}
	if _, err := m.Public(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Public(unknown): %v", err)
	}
}
