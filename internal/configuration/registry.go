package configuration

import (
	"context"
	"time"

	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
)

// Registry is what the configuration domain offers the rest of the box.
type Registry interface {
	ManagerProvider
	SecretManagerProvider
	CacheProvider
}

// InternalRegistry is what the configuration handlers need.
type InternalRegistry interface {
	Registry
	LockerProvider
	GrantRevokerProvider
	sealer.Provider
	x.LoggerProvider
	x.ClockProvider
	x.ValidatorProvider
}

// CacheProvider gives the decision point's copy of the configuration.
type CacheProvider interface {
	ConfigurationCache() *Cache
}

// LockerProvider gives what makes configuration changes one at a time.
type LockerProvider interface {
	ConfigurationLocker() Locker
}

// GrantRevoker revokes the live grants of an agent being suspended.
// grant.Manager is one; the interface is declared here so that
// configuration does not depend on grant.
type GrantRevoker interface {
	RevokeByAgent(ctx context.Context, agent string, at time.Time) ([]string, error)
}

// GrantRevokerProvider gives the grant revoker.
type GrantRevokerProvider interface {
	GrantRevoker() GrantRevoker
}
