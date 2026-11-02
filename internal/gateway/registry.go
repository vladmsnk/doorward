package gateway

import (
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
)

// InternalRegistry is what the gateway needs: its name and allowed origins,
// the configuration in force, the upstream secrets and the sealer that
// opens them, the grant verifier, and the decision point.
type InternalRegistry interface {
	config.Provider
	configuration.CacheProvider
	configuration.SecretManagerProvider
	sealer.Provider
	grant.VerifierProvider
	pdp.EvaluatorProvider
	x.LoggerProvider
}
