package configuration

import (
	"context"
	"fmt"

	"github.com/vladmsnk/doorward/internal/sealer"
)

// SecretPurpose is the sealing purpose of a secret: bound to its name, so
// one secret's ciphertext cannot be moved under another name.
func SecretPurpose(name string) string { return "secret:" + name }

// OpenSecret reads a stored secret and unseals it.
func OpenSecret(ctx context.Context, secrets SecretManager, s *sealer.Sealer, name string) ([]byte, error) {
	sealed, err := secrets.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	plain, err := s.Open(sealed, SecretPurpose(name))
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	return plain, nil
}
