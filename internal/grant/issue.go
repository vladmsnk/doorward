package grant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/consent"
	"github.com/vladmsnk/doorward/internal/core"
	"github.com/vladmsnk/doorward/internal/ids"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/policy"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

// Prepare turns a grant's claims into the grant as the box issues it: a
// fresh ID and lifetime from now, the issuer when one is given, one entry
// per operation carrying all of its bounds, and checked as a verifier will
// check it. The box issues Bearer grants only, so claims with cnf are
// refused.
func Prepare(v *schema.Validator, claims v0.Grant, issuer string, now time.Time, ttl time.Duration) (v0.Grant, error) {
	g := claims
	if g.Confirmation != nil {
		return g, errors.New("claims: cnf binds the grant to a key, but the box does not check proofs of possession yet, so it issues Bearer grants; remove cnf")
	}
	if issuer != "" {
		g.Issuer = issuer
	}
	g.IssuedAt, g.Expiry = now.Unix(), now.Add(ttl).Unix()
	g.ID = ids.At(ids.Grant, now)
	perms, err := policy.OnePerOperation(core.Permissions(g.AuthorizationDetails))
	if err != nil {
		return g, fmt.Errorf("claims: %w", err)
	}
	g.AuthorizationDetails = core.Details(perms)
	doc, err := json.Marshal(g)
	if err != nil {
		return g, err
	}
	if g, err = schema.Decode[v0.Grant](v, doc); err != nil {
		return g, fmt.Errorf("claims: %w", err)
	}
	return g, nil
}

// IssuerRegistry is what issuing a grant needs: the documents and consents
// a grant must lie within, the key ring that signs it, and the grants it is
// recorded among.
type IssuerRegistry interface {
	ManagerProvider
	configuration.ManagerProvider
	consent.ManagerProvider
	jwk.KeyRingProvider
	x.ValidatorProvider
}

// Issuer checks a grant against the box's records, the way the token
// service will before it issues one, then signs and records it. Building
// the grant from a mandate and an agent is the token service's job; the
// Issuer only checks the result.
type Issuer struct {
	r IssuerRegistry
}

// NewIssuer returns an issuer.
func NewIssuer(r IssuerRegistry) *Issuer { return &Issuer{r: r} }

// Admissible refuses what the token service would: an agent that is not
// registered or is suspended, a mandate that does not exist or is
// disabled, a grant wider than the mandate.
func (i *Issuer) Admissible(ctx context.Context, g v0.Grant) error {
	docs := i.r.ConfigurationManager()
	doc, err := docs.Current(ctx, v0.KindAgent, g.Actor.Subject)
	if errors.Is(err, x.ErrNotFound) {
		return fmt.Errorf("agent %s is not registered; PUT it through the Admin API first", g.Actor.Subject)
	}
	if err != nil {
		return err
	}
	var a v0.Agent
	if err := json.Unmarshal(doc.Doc, &a); err != nil {
		return err
	}
	if a.Spec.Status == v0.AgentSuspended {
		return fmt.Errorf("agent %s is suspended", g.Actor.Subject)
	}
	md, err := docs.Current(ctx, v0.KindMandate, g.Mandate)
	if errors.Is(err, x.ErrNotFound) {
		return fmt.Errorf("mandate %s does not exist", g.Mandate)
	}
	if err != nil {
		return err
	}
	if md.Disabled {
		return fmt.Errorf("mandate %s is disabled", g.Mandate)
	}
	return i.within(ctx, g, md, fmt.Sprintf("mandate %s", g.Mandate))
}

// ConsentUntil checks that a user grant rests on a recorded, active,
// unexpired consent given to this agent for this mandate, and lies within
// the mandate as the user saw it when consenting. It returns when the
// consent expires: the grant must not outlive it.
func (i *Issuer) ConsentUntil(ctx context.Context, g v0.Grant, now time.Time) (time.Time, error) {
	c, err := i.r.ConsentManager().Get(ctx, g.Consent)
	if errors.Is(err, x.ErrNotFound) {
		return time.Time{}, fmt.Errorf("consent %s is not recorded; a grant to a user rests on one: pass --consent FILE", g.Consent)
	}
	if err != nil {
		return time.Time{}, err
	}
	switch {
	case c.Agent != g.Actor.Subject:
		return time.Time{}, fmt.Errorf("consent %s was given to agent %s, not %s", c.ID, c.Agent, g.Actor.Subject)
	case c.Mandate != g.Mandate:
		return time.Time{}, fmt.Errorf("consent %s is for mandate %s, not %s", c.ID, c.Mandate, g.Mandate)
	case c.Status != v0.ConsentActive:
		return time.Time{}, fmt.Errorf("consent %s is %s", c.ID, c.Status)
	case !now.Before(c.ExpiresAt.Time):
		return time.Time{}, fmt.Errorf("consent %s expired at %s", c.ID, c.ExpiresAt.UTC().Format(v0.TimestampLayout))
	}
	seen, err := i.r.ConfigurationManager().ByDigest(ctx, v0.KindMandate, g.Mandate, c.MandateVersion)
	if errors.Is(err, x.ErrNotFound) {
		return time.Time{}, fmt.Errorf("consent %s names version %s of mandate %s, which the box does not have", c.ID, c.MandateVersion, g.Mandate)
	}
	if err != nil {
		return time.Time{}, err
	}
	// The mandate may have changed since: the grant must lie within what
	// the user agreed to, as well as within the mandate as it is now.
	who := fmt.Sprintf("mandate %s as consented to in %s (version %d)", g.Mandate, c.ID, seen.Version)
	if err := i.within(ctx, g, seen, who); err != nil {
		return time.Time{}, err
	}
	return c.ExpiresAt.Time, nil
}

// Issue signs a grant with the box's active key, creating the first key on
// a fresh box, and records it. It returns the token and the key's ID.
func (i *Issuer) Issue(ctx context.Context, rec Record) (token, kid string, err error) {
	signer, err := i.r.KeyRing().Ensure(ctx)
	if err != nil {
		return "", "", fmt.Errorf("signing key: %w", err)
	}
	if token, err = Sign(signer, rec.Grant); err != nil {
		return "", "", err
	}
	if err := i.r.GrantManager().Create(ctx, rec); err != nil {
		return "", "", fmt.Errorf("recording %s: %w", rec.Grant.ID, err)
	}
	return token, signer.KID, nil
}

// within checks a grant's permissions and budgets against one version of
// its mandate.
func (i *Issuer) within(ctx context.Context, g v0.Grant, md configuration.Document, who string) error {
	m, err := schema.Decode[v0.Mandate](i.r.Validator(), md.Doc)
	if err != nil {
		return fmt.Errorf("%s: %w", who, err)
	}
	declared, err := i.declaredParams(ctx)
	if err != nil {
		return err
	}
	problems := policy.Within(core.Permissions(g.AuthorizationDetails), "the grant", m.Spec.Permissions, who, declared)
	for _, ml := range m.Spec.Limits {
		found := false
		for _, gl := range g.Limits {
			if gl.Name != ml.Name {
				continue
			}
			found = true
			if gl.Kind != ml.Kind || gl.Field != ml.Field || gl.Max > ml.Max {
				problems = append(problems, fmt.Sprintf("the grant's limit %s is looser than %s's", gl.Name, who))
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("the grant lacks limit %s, which %s sets", ml.Name, who))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the grant goes beyond %s: %s", who, strings.Join(problems, "; "))
	}
	return nil
}

// declaredParams says which arguments each operation has, from the enabled
// manifests.
func (i *Issuer) declaredParams(ctx context.Context) (policy.Declared, error) {
	docs, err := i.r.ConfigurationManager().List(ctx, v0.KindManifest)
	if err != nil {
		return nil, err
	}
	byAud := make(map[string]v0.Manifest)
	for _, d := range docs {
		if d.Disabled {
			continue
		}
		m, err := schema.Decode[v0.Manifest](i.r.Validator(), d.Doc)
		if err != nil {
			return nil, fmt.Errorf("manifest %s: %w", d.Name, err)
		}
		byAud[m.Spec.Audience] = m
	}
	return func(location, action, field string) bool {
		op := core.Operation(byAud[location], action)
		if op == nil {
			return true // an unknown operation: treat every bound as applying
		}
		_, ok := op.Params[field]
		return ok
	}, nil
}
