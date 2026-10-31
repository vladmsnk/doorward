package v0

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// The schemas check each document's shape. The Check methods add the rules
// JSON Schema cannot express: fields that must agree with each other, times
// that must come in order, names that must be unique. They assume the
// document has already passed its schema. Rules that need a second document,
// such as a mandate lying within an agent's permissions, belong to the
// features that load both.

type problems []error

func (p *problems) add(format string, a ...any) { *p = append(*p, fmt.Errorf(format, a...)) }

func (p problems) err() error { return errors.Join(p...) }

// Check enforces the rules of a grant that span fields.
func (g Grant) Check() error {
	var p problems
	if g.Expiry <= g.IssuedAt {
		p.add("exp must be after iat")
	}
	// Under a user mandate the grant names the user, their identity provider
	// and the consent it rests on; under a service mandate it is issued to
	// the agent itself and rests on nothing.
	user := g.Subject != g.ClientID
	if user && g.SubjectID == nil {
		p.add("sub is a user, so sub_id must say which identity provider named them")
	}
	if user && g.Consent == "" {
		p.add("sub is a user, so consent must name what the grant rests on")
	}
	if !user && g.SubjectID != nil {
		p.add("sub equals client_id, so the agent acts for itself and carries no sub_id")
	}
	if !user && g.Consent != "" {
		p.add("sub equals client_id, so the agent acts for itself and rests on no consent")
	}
	if !sameSet(g.Audience, detailLocations(g.AuthorizationDetails)) {
		p.add("aud must list exactly the locations of authorization_details")
	}
	p.checkDetails(g.AuthorizationDetails)
	p.checkLimits(g.Limits)
	return p.err()
}

// Check enforces the rules of a consent record that span fields.
func (c Consent) Check() error {
	var p problems
	if !c.ExpiresAt.After(c.GrantedAt.Time) {
		p.add("expires_at must be after granted_at")
	}
	if c.RevokedAt != nil && (c.RevokedAt.Before(c.GrantedAt.Time) || c.RevokedAt.After(c.ExpiresAt.Time)) {
		p.add("revoked_at must lie between granted_at and expires_at")
	}
	if c.Auth != nil && c.Auth.AuthTime.After(c.GrantedAt.Time) {
		p.add("auth.auth_time is after granted_at: the user cannot sign in after consenting")
	}
	return p.err()
}

// Check enforces the rules of a decision record that span fields.
func (d Decision) Check() error {
	var p problems
	seen := make(map[CheckName]bool)
	var failed []CheckName
	for _, c := range d.Checks {
		if seen[c.Name] {
			p.add("check %q is listed twice", c.Name)
		}
		seen[c.Name] = true
		if c.Result == CheckFail {
			failed = append(failed, c.Name)
		}
	}
	switch d.Outcome {
	case OutcomeAllow:
		if len(failed) > 0 {
			p.add("an allowed call cannot have failed checks %v", failed)
		}
	case OutcomeDeny:
		if len(failed) == 0 {
			p.add("a denied call must have a failed check")
		}
	case OutcomeApprovalRequired:
		if !slices.Equal(failed, []CheckName{CheckSensitivity}) {
			p.add("a held call fails the sensitivity check and nothing else, not %v", failed)
		}
	}
	if d.Principal != nil && d.Grant != nil {
		if d.Principal.User != "" && d.Grant.Consent == "" {
			p.add("a call for a user rests on a consent; grant.consent is missing")
		}
		if d.Principal.Owner != "" && d.Grant.Consent != "" {
			p.add("a service agent's call rests on no consent")
		}
	}
	return p.err()
}

var pathParam = regexp.MustCompile(`\{([^{}/]+)\}`)

// Check enforces the rules of a manifest that span fields.
func (m Manifest) Check() error {
	var p problems
	names := make(map[string]bool)
	for _, op := range m.Spec.Operations {
		if names[op.Name] {
			p.add("operation %q is declared twice", op.Name)
		}
		names[op.Name] = true
		if op.HTTP == nil {
			continue
		}
		inPath := make(map[string]bool)
		for _, match := range pathParam.FindAllStringSubmatch(op.HTTP.Path, -1) {
			inPath["/"+match[1]] = true
		}
		for _, ptr := range sortedKeys(op.Params) {
			if op.Params[ptr].In == ParamInPath && !inPath[ptr] {
				p.add("%s: param %s is in the path, but %s has no {%s}", op.Name, ptr, op.HTTP.Path, ptr[1:])
			}
		}
		for _, ptr := range sortedKeys(inPath) {
			if param, ok := op.Params[ptr]; !ok || param.In != ParamInPath {
				p.add("%s: path segment {%s} has no param %s with in: path", op.Name, ptr[1:], ptr)
			}
		}
	}
	return p.err()
}

// Check enforces the rules of an agent that span fields.
func (a Agent) Check() error {
	var p problems
	seen := make(map[string]bool)
	for i, id := range a.Spec.Identities {
		key := fmt.Sprintf("%s|%s|%s|%s", id.Type, id.Issuer, id.Subject, id.ClientID)
		if seen[key] {
			p.add("identity %d is listed twice", i)
		}
		seen[key] = true
	}
	p.checkPermissions(a.Spec.Permissions)
	p.checkLimits(a.Spec.Limits)
	return p.err()
}

// Check enforces the rules of a mandate that span fields.
func (m Mandate) Check() error {
	var p problems
	if m.Spec.Consent != nil && m.Spec.TTL.D() > m.Spec.Consent.MaxDuration.D() {
		p.add("ttl %s is longer than the consent's max_duration %s", m.Spec.TTL, m.Spec.Consent.MaxDuration)
	}
	for _, l := range m.Spec.Limits {
		if m.Spec.Principal == PrincipalService && l.Per != "" && l.Per != PerGrant {
			p.add("limit %q runs per %s, but a service mandate has no consent to share it across", l.Name, l.Per)
		}
	}
	p.checkPermissions(m.Spec.Permissions)
	p.checkLimits(m.Spec.Limits)
	return p.err()
}

// Check enforces the rules of an approval record that span fields.
func (a Approval) Check() error {
	var p problems
	if a.Closed != nil && a.Closed.Before(a.Created.Time) {
		p.add("closed is before created")
	}
	voted := make(map[SubjectID]bool)
	approvals, rejections := 0, 0
	for i, v := range a.Votes {
		switch a.Route.Kind {
		case ApproverUser:
			if a.User == nil || v.Approver != *a.User {
				p.add("vote %d: on a user route only the user the agent acts for votes", i)
			}
		case ApproverGroup:
			if a.User != nil && v.Approver == *a.User {
				p.add("vote %d: the user the agent acts for cannot approve the call on a group route", i)
			}
		}
		if voted[v.Approver] {
			p.add("vote %d: %s voted twice", i, v.Approver.Sub)
		}
		voted[v.Approver] = true
		if v.Time.Before(a.Created.Time) || (a.Closed != nil && v.Time.After(a.Closed.Time)) {
			p.add("vote %d was cast while the request was not open", i)
		}
		if v.AuthTime.After(v.Time.Time) {
			p.add("vote %d: auth_time is after the vote", i)
		}
		if v.Verdict == VerdictApprove {
			approvals++
		} else {
			rejections++
		}
	}
	if a.Route.Kind == ApproverUser && a.Required != 1 {
		p.add("a user route needs exactly 1 approval, not %d", a.Required)
	}
	switch a.Status {
	case ApprovalApproved:
		if rejections > 0 || approvals < a.Required {
			p.add("approved needs %d approvals and no rejection, not %d and %d", a.Required, approvals, rejections)
		}
	case ApprovalRejected:
		if rejections == 0 {
			p.add("rejected needs at least one rejection")
		}
	}
	return p.err()
}

func (p *problems) checkDetails(details []AuthorizationDetail) {
	for i, d := range details {
		for _, ptr := range sortedKeys(d.Constraints) {
			p.checkBounds(fmt.Sprintf("authorization_details[%d] %s", i, ptr), d.Constraints[ptr])
		}
	}
}

func (p *problems) checkPermissions(perms []Permission) {
	for i, perm := range perms {
		for _, ptr := range sortedKeys(perm.Constraints) {
			p.checkBounds(fmt.Sprintf("permissions[%d] %s", i, ptr), perm.Constraints[ptr])
		}
	}
}

func (p *problems) checkBounds(at string, c Constraint) {
	if c.Min != nil && c.Max != nil && *c.Min > *c.Max {
		p.add("%s: min %v is above max %v", at, *c.Min, *c.Max)
	}
}

func (p *problems) checkLimits(limits []Limit) {
	seen := make(map[string]bool)
	for _, l := range limits {
		if seen[l.Name] {
			p.add("limit %q is defined twice", l.Name)
		}
		seen[l.Name] = true
	}
}

func detailLocations(details []AuthorizationDetail) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range details {
		for _, l := range d.Locations {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
