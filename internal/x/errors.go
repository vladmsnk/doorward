// Package x holds what every other package of doorward shares: the errors
// storage reports, and the small HTTP helpers each API's handlers use.
// Nothing in x knows about any one domain.
package x

import "errors"

var (
	// ErrNotFound is returned when a document or record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a write would repeat an ID.
	ErrConflict = errors.New("already exists")
	// ErrState is returned when a record cannot move to the requested state.
	ErrState = errors.New("invalid state transition")
	// ErrTimeout is returned when the store could not answer within the
	// caller's deadline: a lock was not free in time, or a statement ran
	// out of time. Nothing was written.
	ErrTimeout = errors.New("the store did not answer in time")
)
