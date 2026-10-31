package grant

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"time"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/store"
	"github.com/vladmsnk/agentbox/schema"
)

// DefaultSkew is how far apart the issuer's clock and the verifier's may be.
const DefaultSkew = 30 * time.Second

// Keys finds the public key a grant names, whether or not it is still
// published. keys.Manager is one.
type Keys interface {
	Public(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

// Status says whether a genuine grant still stands. It returns a non-empty
// refusal when the grant must not be honoured, and an error only when it
// could not find out.
type Status interface {
	Standing(ctx context.Context, g v0.Grant) (refusal string, err error)
}

// Verifier checks grants. Keys, Status and Validator are required.
type Verifier struct {
	Keys      Keys
	Status    Status
	Validator *schema.Validator
	// Issuer, when set, is the only iss accepted.
	Issuer string
	// Skew defaults to DefaultSkew.
	Skew time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Result is what verification established. Checks are the grant's part of a
// decision record, in the record's order; verification stops at the first
// failure and lists nothing after it.
type Result struct {
	// Grant is set once the signature has been checked and the claims have
	// passed the schema.
	Grant  *v0.Grant  `json:"grant,omitempty"`
	Checks []v0.Check `json:"checks"`
	// Reason is set exactly when a check failed.
	Reason *v0.Reason `json:"reason,omitempty"`
}

// OK reports whether every check passed or was skipped.
func (r Result) OK() bool { return r.Reason == nil }

func (r *Result) pass(name v0.CheckName, detail string) {
	r.Checks = append(r.Checks, v0.Check{Name: name, Result: v0.CheckPass, Detail: detail})
}

func (r *Result) skip(name v0.CheckName, detail string) {
	r.Checks = append(r.Checks, v0.Check{Name: name, Result: v0.CheckSkip, Detail: detail})
}

func (r *Result) fail(name v0.CheckName, code v0.ReasonCode, format string, args ...any) Result {
	msg := fmt.Sprintf(format, args...)
	r.Checks = append(r.Checks, v0.Check{Name: name, Result: v0.CheckFail, Detail: msg})
	r.Reason = &v0.Reason{Code: code, Message: msg}
	return *r
}

// Verify runs the grant's checks: signature, status, pop, audience, time.
// audience is the resource the call goes to; an empty one skips the
// audience check, which only a caller that is not deciding a call may do.
//
// The error is non-nil only when a dependency failed (the key table or the
// status source); the result then ends in a failed check with
// internal_error, so the caller can still record a refusal.
func (v *Verifier) Verify(ctx context.Context, tok, audience string) (Result, error) {
	var r Result

	// signature: the token is a well-formed grant this box signed.
	if tok == "" {
		return r.fail(v0.CheckSignature, v0.ReasonGrantMissing, "no grant presented"), nil
	}
	t, err := parse(tok)
	if err != nil {
		return r.fail(v0.CheckSignature, v0.ReasonGrantMalformed, "%v", err), nil
	}
	pub, err := v.Keys.Public(ctx, t.header.Kid)
	if errors.Is(err, store.ErrNotFound) {
		return r.fail(v0.CheckSignature, v0.ReasonGrantSignatureInvalid, "kid %s is not a key of this box", t.header.Kid), nil
	}
	if err != nil {
		return r.fail(v0.CheckSignature, v0.ReasonInternalError, "looking up kid %s failed", t.header.Kid),
			fmt.Errorf("key %s: %w", t.header.Kid, err)
	}
	if !t.verifySignature(pub) {
		return r.fail(v0.CheckSignature, v0.ReasonGrantSignatureInvalid, "signature does not verify with key %s", t.header.Kid), nil
	}
	// Only now are the claims worth reading: schema, strict decoding and
	// the grant's own rules.
	g, err := schema.Decode[v0.Grant](v.Validator, t.payload)
	if err != nil {
		return r.fail(v0.CheckSignature, v0.ReasonGrantMalformed, "claims: %v", err), nil
	}
	if v.Issuer != "" && g.Issuer != v.Issuer {
		return r.fail(v0.CheckSignature, v0.ReasonGrantMalformed, "iss is %s; this box issues as %s", g.Issuer, v.Issuer), nil
	}
	r.Grant = &g
	r.pass(v0.CheckSignature, "key "+t.header.Kid)

	// status: the box issued this grant, has not revoked it, and its
	// agent is not suspended.
	refusal, err := v.Status.Standing(ctx, g)
	if err != nil {
		return r.fail(v0.CheckStatus, v0.ReasonInternalError, "status of %s unknown", g.ID), fmt.Errorf("status of %s: %w", g.ID, err)
	}
	if refusal != "" {
		return r.fail(v0.CheckStatus, v0.ReasonGrantRevoked, "%s", refusal), nil
	}
	r.pass(v0.CheckStatus, "")

	// pop: proof that the caller holds the key in cnf. Recorded as skipped
	// until the sidecar sends DPoP proofs.
	r.skip(v0.CheckPoP, "proof of possession is not checked yet")

	// audience: the grant was issued for the resource being called.
	switch {
	case audience == "":
		r.skip(v0.CheckAudience, "no resource given")
	case !slices.Contains(g.Audience, audience):
		return r.fail(v0.CheckAudience, v0.ReasonAudienceMismatch, "grant is for %v, not %s", g.Audience, audience), nil
	default:
		r.pass(v0.CheckAudience, "")
	}

	// time: inside [iat, exp), give or take the clock skew.
	now := v.now()
	skew := v.Skew
	if skew == 0 {
		skew = DefaultSkew
	}
	iat, exp := time.Unix(g.IssuedAt, 0), time.Unix(g.Expiry, 0)
	switch {
	case now.Before(iat.Add(-skew)):
		return r.fail(v0.CheckTime, v0.ReasonGrantNotYetValid, "issued at %s, which is in the future", iat.UTC().Format(time.RFC3339)), nil
	case !now.Before(exp.Add(skew)):
		return r.fail(v0.CheckTime, v0.ReasonGrantExpired, "expired at %s", exp.UTC().Format(time.RFC3339)), nil
	}
	r.pass(v0.CheckTime, "")
	return r, nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}
