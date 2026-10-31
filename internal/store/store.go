// Package store is the box's one database: versioned configuration and
// append-only records, behind one interface. The STS, the gateway and the
// decision core read and write through it and never touch SQL.
package store

import (
	"context"
	"errors"
	"time"

	v0 "github.com/vladmsnk/agentbox/api/v0"
)

var (
	// ErrNotFound is returned when a document or record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a write would repeat an ID.
	ErrConflict = errors.New("already exists")
	// ErrDisabled is returned when the current version of a document is
	// disabled and the caller asked for a usable one.
	ErrDisabled = errors.New("disabled")
	// ErrExhausted is returned by Consume when the budget would be overdrawn.
	ErrExhausted = errors.New("limit exhausted")
	// ErrState is returned when a record cannot move to the requested state.
	ErrState = errors.New("invalid state transition")
)

// Store is everything the box keeps.
type Store interface {
	Documents() Documents
	Consents() Consents
	Grants() Grants
	Decisions() Decisions
	Approvals() Approvals
	Counters() Counters
	Keys() Keys
	Secrets() Secrets
	Close() error
}

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

// Documents keeps Manifest, Agent and Mandate documents, every version of
// them. A write never overwrites: it adds the next version.
type Documents interface {
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

// Consents keeps Consent records.
type Consents interface {
	Create(ctx context.Context, c v0.Consent) error
	Get(ctx context.Context, id string) (v0.Consent, error)
	// ByUser lists a user's consents, newest first; activeOnly drops the
	// ended ones.
	ByUser(ctx context.Context, user v0.SubjectID, activeOnly bool) ([]v0.Consent, error)
	// Revoke ends an active consent. ErrState if it is not active.
	Revoke(ctx context.Context, id string, by v0.Revoker, at time.Time) (v0.Consent, error)
	// Expire marks active consents past their expiry; it returns how many.
	Expire(ctx context.Context, now time.Time) (int, error)
}

// GrantRecord is a grant as the STS issued it, with the state the gateway
// needs on every call.
type GrantRecord struct {
	Grant      v0.Grant
	Agent      string
	RevokedAt  *time.Time
	SingleUse  bool
	ActionHash string
	UsedAt     *time.Time
}

// Grants keeps every grant issued and whether it still stands.
type Grants interface {
	Create(ctx context.Context, g GrantRecord) error
	Get(ctx context.Context, jti string) (GrantRecord, error)
	// Revoke marks one grant revoked.
	Revoke(ctx context.Context, jti string, at time.Time) error
	// RevokeByConsent revokes every live grant resting on a consent and
	// returns their IDs.
	RevokeByConsent(ctx context.Context, consent string, at time.Time) ([]string, error)
	// RevokeByAgent revokes every live grant of an agent and returns their IDs.
	RevokeByAgent(ctx context.Context, agent string, at time.Time) ([]string, error)
	// Spend marks a single-use grant used, once. ErrState if it is not
	// single-use or was already spent.
	Spend(ctx context.Context, jti string, at time.Time) error
}

// Decisions is the hash-chained journal of decision records.
type Decisions interface {
	// Append stores d as the next link: it fills d.Chain from the previous
	// record, computes the hash, and returns the stored record.
	Append(ctx context.Context, d v0.Decision) (v0.Decision, error)
	Get(ctx context.Context, id string) (v0.Decision, error)
	// Range returns records with seq in [from, to), oldest first.
	Range(ctx context.Context, from, to uint64) ([]v0.Decision, error)
	// Head returns the newest record, or ErrNotFound on an empty journal.
	Head(ctx context.Context) (v0.Decision, error)
}

// Approvals keeps approval requests from opening to closing.
type Approvals interface {
	Create(ctx context.Context, a v0.Approval) error
	Get(ctx context.Context, id string) (v0.Approval, error)
	// Pending lists open requests, oldest first.
	Pending(ctx context.Context) ([]v0.Approval, error)
	// Vote adds a vote to a pending request. ErrState if it is not pending.
	Vote(ctx context.Context, id string, v v0.Vote) (v0.Approval, error)
	// Close moves a pending request to approved, rejected or expired.
	// ErrState if it is not pending.
	Close(ctx context.Context, id string, status v0.ApprovalStatus, at time.Time, singleUseGrant string) (v0.Approval, error)
}

// Counters are budgets. A key names what a budget belongs to.
type Counters interface {
	// Consume adds amount to the counter at key if the result stays within
	// max, and returns what remains. ErrExhausted otherwise, consuming nothing.
	Consume(ctx context.Context, key string, amount, max float64) (remaining float64, err error)
	// Consumed returns the counter's value, 0 if it does not exist.
	Consumed(ctx context.Context, key string) (float64, error)
}

// SigningKey is one of the box's keys. PrivateEnc is sealed; the store
// never sees the private key in clear.
type SigningKey struct {
	KID        string
	Alg        string
	PublicJWK  []byte
	PrivateEnc []byte
	CreatedAt  time.Time
	RetiredAt  *time.Time
}

// Keys keeps the signing keys.
type Keys interface {
	Create(ctx context.Context, k SigningKey) error
	// Active returns the newest key that is not retired.
	Active(ctx context.Context) (SigningKey, error)
	// List returns every key, newest first, retired ones included.
	List(ctx context.Context) ([]SigningKey, error)
	Retire(ctx context.Context, kid string, at time.Time) error
}

// SecretInfo is what is known about a secret without its value.
type SecretInfo struct {
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}

// Secrets keeps sealed values the gateway presents to upstreams, named by
// a manifest's secret_ref. Values are sealed before they get here.
type Secrets interface {
	Put(ctx context.Context, name string, sealed []byte, by string) error
	Get(ctx context.Context, name string) ([]byte, error)
	List(ctx context.Context) ([]SecretInfo, error)
	Delete(ctx context.Context, name string) error
}

// GrantKey and ConsentKey name a budget. Period is a calendar day
// (2026-10-30) or month (2026-10) in UTC.
func GrantKey(jti, limit string) string          { return "grant:" + jti + ":" + limit }
func ConsentKey(id, limit, period string) string { return "consent:" + id + ":" + limit + ":" + period }
