package driver

import (
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/gateway"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/persistence"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
)

// registry is everything the domain packages ask a registry for. The
// assertion below keeps RegistryDefault honest: a package that declares a
// new need does not compile until the registry meets it.
type registry interface {
	config.Provider
	persistence.Provider
	sealer.Provider
	x.LoggerProvider
	x.TracerProvider
	x.ClockProvider
	x.ValidatorProvider

	configuration.InternalRegistry
	jwk.InternalRegistry
	journal.InternalRegistry
	grant.ManagerProvider
	pdp.InternalRegistry
	gateway.InternalRegistry
	grant.IssuerRegistry
}

var _ registry = (*RegistryDefault)(nil)
