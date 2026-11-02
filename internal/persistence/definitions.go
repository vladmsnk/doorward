// Package persistence is doorward's one database, seen whole: the storage
// interfaces every domain package defines for itself, composed into one
// Persister that a single implementation (package sql, on PostgreSQL)
// provides. Domain packages never import it; they ask for their own
// Manager, and the registry hands them the Persister's.
package persistence

import (
	"context"

	"github.com/vladmsnk/doorward/internal/approval"
	"github.com/vladmsnk/doorward/internal/budget"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/consent"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/jwk"
)

type (
	// Persister is everything the box keeps: versioned configuration and
	// its secrets, and the append-only records.
	Persister interface {
		configuration.Store
		configuration.Locker
		configuration.Versioner
		Consents() consent.Manager
		Grants() grant.Manager
		Decisions() journal.Manager
		Approvals() approval.Manager
		Counters() budget.Manager
		Keys() jwk.Manager
		budget.Allower
		journal.Settler

		// Ping reports whether the database answers.
		Ping(ctx context.Context) error
		Close() error
	}

	// Provider gives access to the Persister.
	Provider interface {
		Persister() Persister
	}
)
