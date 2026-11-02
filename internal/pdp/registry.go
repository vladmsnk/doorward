package pdp

import (
	"github.com/vladmsnk/doorward/internal/approval"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/x"
)

// Registry is what the decision point offers the rest of the box.
type Registry interface {
	EvaluatorProvider
}

// EvaluatorProvider gives the decision point.
type EvaluatorProvider interface {
	Evaluator() *Evaluator
}

// InternalRegistry is what the decision point needs: the settings that
// name it and bound a decision, the configuration in force, the grant
// verifier, the approval requests, and the journal it settles into.
type InternalRegistry interface {
	Registry
	config.Provider
	configuration.CacheProvider
	grant.VerifierProvider
	approval.ManagerProvider
	journal.SettlerProvider
	journal.NotifierProvider
	x.LoggerProvider
	x.TracerProvider
	x.ClockProvider
}
