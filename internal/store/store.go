// Package store is the box's one database: versioned configuration and
// append-only records, behind one interface. The STS, the gateway and the
// decision core read and write through it and never touch SQL.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

var (
	// ErrNotFound is returned when a document or record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a write would repeat an ID.
	ErrConflict = errors.New("already exists")
	// ErrDisabled is returned when the current version of a document is
	// disabled and the caller asked for a usable one.
	ErrDisabled = errors.New("disabled")
	// ErrExhausted is returned when a budget would be overdrawn.
	ErrExhausted = errors.New("limit exhausted")
	// ErrState is returned when a record cannot move to the requested state.
	ErrState = errors.New("invalid state transition")
	// ErrTimeout is returned when the store could not answer within the
	// caller's deadline: a lock was not free in time, or a statement ran
	// out of time. Nothing was written.
	ErrTimeout = errors.New("the store did not answer in time")
)

// Store is everything the box keeps.
type Store interface {
	Config
	Consents() Consents
	Grants() Grants
	Decisions() Decisions
	Approvals() Approvals
	Counters() Counters
	// Allow spends an allowance all at once or not at all: every draw fits
	// its budget and the single-use grant was unspent, or nothing changes
	// and the error says why (an *ExhaustedError, or ErrState for a
	// single-use grant already spent).
	Allow(ctx context.Context, a Allowance) ([]Drawn, error)
	// Settle spends an allowance, when there is one, and appends the
	// decision that results, in one transaction: an allowed call's record
	// is written exactly when its spending is. decide receives what Allow
	// drew, or Allow's refusal (*ExhaustedError, ErrState), after which
	// nothing was drawn; any other error from Allow or decide aborts it all.
	// It returns the decision as appended, chain filled in.
	Settle(ctx context.Context, a *Allowance, decide func(drawn []Drawn, err error) (v0.Decision, error)) (v0.Decision, error)
	Keys() Keys
	// LockConfig runs fn in one transaction holding the configuration lock.
	// No two LockConfig calls run at once, fn reads the configuration as
	// the last of them left it, and its writes commit together or, if it
	// returns an error, not at all. Every change to configuration goes
	// through it, so a change is checked against the configuration it will
	// actually join.
	LockConfig(ctx context.Context, fn func(Config) error) error
	// ConfigVersion is a counter every configuration write bumps: a reader
	// that sees the same value it saw before can keep its copy.
	ConfigVersion(ctx context.Context) (uint64, error)
	Close() error
}

// Config is the part of the store that holds configuration: the documents,
// and the secrets they name.
type Config interface {
	Documents() Documents
	Secrets() Secrets
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
	// PendingFor returns the newest open request for one call: the same
	// agent, mandate, consent ("" for a service agent) and action hash.
	// ErrNotFound if there is none.
	PendingFor(ctx context.Context, agent, mandate, consent, actionHash string) (v0.Approval, error)
	// Vote adds a vote to a pending request. ErrState if it is not pending.
	Vote(ctx context.Context, id string, v v0.Vote) (v0.Approval, error)
	// Close moves a pending request to approved, rejected or expired.
	// ErrState if it is not pending.
	Close(ctx context.Context, id string, status v0.ApprovalStatus, at time.Time, singleUseGrant string) (v0.Approval, error)
}

// Counters are budgets. A key names what a budget belongs to. Amounts are
// exact decimals written as strings ("1200", "0.1"), never floating point,
// so a budget of 0.30 holds exactly three draws of 0.10.
type Counters interface {
	// Consumed returns what the budget at key has drawn, "0" if nothing.
	Consumed(ctx context.Context, key string) (string, error)
}

// Draw is one budget an allowed call draws on.
type Draw struct {
	Key    string
	Amount string // exact decimal, not negative
	Max    string // exact decimal
}

// Drawn is what one draw left. Exhausted marks a best-effort draw that
// did not fit and took nothing.
type Drawn struct {
	Key       string
	Amount    string
	Remaining string
	Exhausted bool
}

// ExhaustedError is a draw refused because the budget has no room for it.
// It matches ErrExhausted.
type ExhaustedError struct {
	Key       string
	Amount    string
	Remaining string
}

func (e *ExhaustedError) Error() string {
	return fmt.Sprintf("budget %s has %s left; the call needs %s", e.Key, e.Remaining, e.Amount)
}

func (e *ExhaustedError) Is(target error) bool { return target == ErrExhausted }

// Allowance is everything allowing one call spends: its budgets and, for a
// single-use grant, the grant itself.
type Allowance struct {
	Draws []Draw
	// SingleUse is the jti of the single-use grant the call runs on.
	SingleUse string
	// BestEffort draws every budget that has room and reports the others as
	// exhausted, instead of drawing nothing: an observed call runs, so what
	// it used counts where it fits. A spent single-use grant still refuses.
	BestEffort bool
	At         time.Time
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
