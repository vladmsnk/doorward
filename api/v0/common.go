// Package v0 holds the Go types of the v0 schemas: the three documents a
// company writes (the manifest of a resource's operations, the agent, and the
// mandate) and the records the box produces (consent, grant, decision and
// approval).
//
// The JSON Schemas in schema/v0 are the contract. These types mirror them
// field for field; the drift test in package schema fails the build when the
// two disagree on a field name, on whether a field is required, or on the
// members of an enum.
package v0

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// APIVersion is the apiVersion of every v0 configuration document.
const APIVersion = "doorward/v0"

// TypeMeta is the envelope that tells documents of different kinds apart.
type TypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// ObjectMeta names a configuration document.
type ObjectMeta struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// Owner is who answers for an agent.
type Owner struct {
	Team    string `json:"team"`
	Contact string `json:"contact,omitempty"`
}

// SubjectIDFormat is the only RFC 9493 format v0 uses.
const SubjectIDFormat = "iss_sub"

// SubjectID is a person as their identity provider names them. An OIDC sub
// is unique only within its issuer, so the two travel together (RFC 9493).
type SubjectID struct {
	Format string `json:"format"`
	Issuer string `json:"iss"`
	Sub    string `json:"sub"`
}

// Sensitivity is the tier of an operation. read runs on any valid grant;
// write runs too, and the record is kept for review; critical never runs on
// a standing grant: a person approves the exact call first.
type Sensitivity string

const (
	SensitivityRead     Sensitivity = "read"
	SensitivityWrite    Sensitivity = "write"
	SensitivityCritical Sensitivity = "critical"
)

// Permission is what may be called, where, and with which argument values, as
// written in an agent or a mandate.
type Permission struct {
	Locations   []string              `json:"locations"`
	Actions     []string              `json:"actions"`
	Constraints map[string]Constraint `json:"constraints,omitempty"`
}

// AuthorizationDetailType is the RFC 9396 type of every entry the box issues.
const AuthorizationDetailType = "tool_call"

// AuthorizationDetail is one authorization_details entry of a grant
// (RFC 9396).
type AuthorizationDetail struct {
	Type        string                `json:"type"`
	Locations   []string              `json:"locations"`
	Actions     []string              `json:"actions"`
	Constraints map[string]Constraint `json:"constraints,omitempty"`
}

// Constraint bounds one argument, keyed in its permission by the argument's
// JSON Pointer. Every bound that is set must hold.
type Constraint struct {
	Max    *float64 `json:"max,omitempty"`
	Min    *float64 `json:"min,omitempty"`
	OneOf  []any    `json:"one_of,omitempty"`
	Equals any      `json:"equals,omitempty"`
	Prefix *string  `json:"prefix,omitempty"`
}

// LimitKind says what a limit counts.
type LimitKind string

const (
	// LimitCount bounds the number of calls.
	LimitCount LimitKind = "count"
	// LimitSum bounds the total of a numeric argument.
	LimitSum LimitKind = "sum"
)

// LimitPeriod is what a budget runs over.
type LimitPeriod string

const (
	// PerGrant: the budget belongs to one grant.
	PerGrant LimitPeriod = "grant"
	// PerDay and PerMonth: the budget is shared by every grant of one
	// consent within the calendar period.
	PerDay   LimitPeriod = "day"
	PerMonth LimitPeriod = "month"
)

// Limit is a budget.
type Limit struct {
	Name string    `json:"name"`
	Kind LimitKind `json:"kind"`
	Max  float64   `json:"max"`
	// Per is what the budget runs over; empty means PerGrant.
	Per LimitPeriod `json:"per,omitempty"`
	// Field is the argument a sum limit adds up.
	Field string `json:"field,omitempty"`
	// Actions, when set, restricts the operations the limit counts.
	Actions []string `json:"actions,omitempty"`
}

// TimestampLayout is the one way a record writes a time: UTC, millisecond
// precision. Records are hashed into a chain, so a time must have a
// single serialization; RFC 3339 alone allows many.
const TimestampLayout = "2006-01-02T15:04:05.000Z"

// Timestamp is a time.Time that always marshals in TimestampLayout.
type Timestamp struct{ time.Time }

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format(TimestampLayout))
}

func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("timestamp must be a string: %w", err)
	}
	parsed, err := time.Parse(TimestampLayout, raw)
	if err != nil {
		return fmt.Errorf("timestamp %q is not UTC with millisecond precision: %w", raw, err)
	}
	t.Time = parsed
	return nil
}

// Duration is a time.Duration written as a string such as "15m".
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String writes the duration without zero trailing units, so "15m" stays
// "15m" instead of becoming "15m0s".
func (d Duration) String() string {
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("duration must be a string such as \"15m\": %w", err)
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}
