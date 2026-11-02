package configuration

import (
	"context"
	"time"
)

// Document is one version of a configuration document.
type Document struct {
	Kind      string
	Name      string
	Version   int
	Digest    string
	Doc       []byte // canonical JSON, as validated
	Disabled  bool
	CreatedAt time.Time
	CreatedBy string
}

// Manager keeps Manifest, Agent and Mandate documents, every version of
// them. A write never overwrites: it adds the next version.
type Manager interface {
	// Put stores doc as the next version of (kind, name) and returns it.
	// The caller validates first; the store checks nothing but shape.
	Put(ctx context.Context, kind, name string, doc []byte, by string) (Document, error)
	// Current returns the newest version, disabled or not.
	Current(ctx context.Context, kind, name string) (Document, error)
	// Version returns one specific version.
	Version(ctx context.Context, kind, name string, version int) (Document, error)
	// ByDigest returns the version with that digest, whatever its number.
	ByDigest(ctx context.Context, kind, name, digest string) (Document, error)
	// List returns the current version of every document of a kind, by name.
	List(ctx context.Context, kind string) ([]Document, error)
	// History returns every version of one document, oldest first.
	History(ctx context.Context, kind, name string) ([]Document, error)
	// SetDisabled adds a version identical to the current one with the
	// disabled flag set as given, so the change is in the history too.
	SetDisabled(ctx context.Context, kind, name string, disabled bool, by string) (Document, error)
}

// SecretInfo is what is known about a secret without its value.
type SecretInfo struct {
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}

// SecretManager keeps sealed values the gateway presents to upstreams,
// named by a manifest's secret_ref. Values are sealed before they get here.
type SecretManager interface {
	Put(ctx context.Context, name string, sealed []byte, by string) error
	Get(ctx context.Context, name string) ([]byte, error)
	List(ctx context.Context) ([]SecretInfo, error)
	Delete(ctx context.Context, name string) error
}

// Store holds the configuration: the documents, and the secrets they name.
type Store interface {
	Documents() Manager
	Secrets() SecretManager
}

// Locker makes configuration changes one at a time.
type Locker interface {
	// LockConfig runs fn in one transaction holding the configuration
	// lock. No two LockConfig calls run at once, fn reads the
	// configuration as the last of them left it, and its writes commit
	// together or, if it returns an error, not at all. Every change to
	// configuration goes through it, so a change is checked against the
	// configuration it will actually join.
	LockConfig(ctx context.Context, fn func(Store) error) error
}

// Versioner tells whether the configuration changed.
type Versioner interface {
	// ConfigVersion is a counter every configuration write bumps: a reader
	// that sees the same value it saw before can keep its copy.
	ConfigVersion(ctx context.Context) (uint64, error)
}

// Source is what a Cache reads: the documents, and whether they changed.
type Source interface {
	Store
	Versioner
}

// ManagerProvider gives access to the documents.
type ManagerProvider interface {
	ConfigurationManager() Manager
}

// SecretManagerProvider gives access to the secrets.
type SecretManagerProvider interface {
	SecretManager() SecretManager
}
