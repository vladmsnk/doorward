package jwk

import (
	"context"
	"time"
)

// SigningKey is one of the box's keys as stored. PrivateEnc is sealed; the
// store never sees the private key in clear.
type SigningKey struct {
	KID        string
	Alg        string
	PublicJWK  []byte
	PrivateEnc []byte
	CreatedAt  time.Time
	RetiredAt  *time.Time
}

// Manager keeps the signing keys.
type Manager interface {
	Create(ctx context.Context, k SigningKey) error
	// Active returns the newest key that is not retired.
	Active(ctx context.Context) (SigningKey, error)
	// List returns every key, newest first, retired ones included.
	List(ctx context.Context) ([]SigningKey, error)
	Retire(ctx context.Context, kid string, at time.Time) error
}

// ManagerProvider gives access to the stored keys.
type ManagerProvider interface {
	KeyManager() Manager
}

// KeyRingProvider gives access to the box's key ring.
type KeyRingProvider interface {
	KeyRing() *KeyRing
}
