package v0

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// The schemas check each document's shape. The Check methods add the rules
// JSON Schema cannot express: fields that must agree with each other, times
// that must come in order, names that must be unique. They assume the
// document has already passed its schema. Rules that need a second document,
// such as a task type lying within a boundary, belong to the features that
// load both.

type problems []error

func (p *problems) add(format string, a ...any) { *p = append(*p, fmt.Errorf(format, a...)) }

func (p problems) err() error { return errors.Join(p...) }

// Check enforces the rules of a grant that span fields.
func (g Grant) Check() error {
	var p problems
	if g.Expiry <= g.IssuedAt {
		p.add("exp must be after iat")
	}
	if g.NotBefore != 0 && (g.NotBefore < g.IssuedAt || g.NotBefore >= g.Expiry) {
		p.add("nbf must lie between iat and exp")
	}
	if g.AuthTime > g.IssuedAt {
		p.add("auth_time is after iat: the user cannot sign in after the grant was issued")
	}
	if g.Depth == 0 && g.Root != g.ID {
		p.add("a root grant (depth 0) must name itself as root")
	}
	if g.Depth > 0 && (g.Root == g.ID || g.Parent == g.ID) {
		p.add("a grant at depth %d cannot be its own root or parent", g.Depth)
	}
	if n := g.Actor.chainLength(); n > g.Depth+1 {
		p.add("act nests %d agents, more than depth %d allows", n, g.Depth)
	}
	locations, actions := detailSets(g.AuthorizationDetails)
	if !sameSet(g.Audience, locations) {
		p.add("aud must list exactly the locations of authorization_details")
	}
	for _, s := range strings.Fields(g.Scope) {
		if !actions[s] {
			p.add("scope %q names an operation authorization_details does not", s)
		}
	}
	p.checkDetails(g.AuthorizationDetails)
	p.checkLimits(g.Limits)
	return p.err()
}

func (a Actor) chainLength() int {
	n := 1
	for next := a.Actor; next != nil; next = next.Actor {
		n++
	}
	return n
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
	if g := d.Grant; g != nil {
		if g.Depth == 0 && (g.Parent != "" || g.Root != g.ID) {
			p.add("grant: at depth 0 it is its own root and has no parent")
		}
		if g.Depth > 0 && g.Parent == "" {
			p.add("grant: at depth %d it needs a parent", g.Depth)
		}
		if d.Principal != nil && len(d.Principal.Actors) > g.Depth {
			p.add("principal lists %d earlier agents but the grant is at depth %d", len(d.Principal.Actors), g.Depth)
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

// Check enforces the rules of a boundary that span fields.
func (b Boundary) Check() error {
	var p problems
	seen := make(map[AgentIdentity]bool)
	for _, id := range b.Spec.Identities {
		if seen[id] {
			p.add("identity %+v is listed twice", id)
		}
		seen[id] = true
	}
	p.checkPermissions(b.Spec.Permissions)
	p.checkLimits(b.Spec.Limits)
	return p.err()
}

// Check enforces the rules of a task type that span fields.
func (t TaskType) Check() error {
	var p problems
	p.checkPermissions(t.Spec.Permissions)
	p.checkLimits(t.Spec.Limits)
	return p.err()
}

// Check enforces the rules of an offer that span fields.
func (o Offer) Check() error {
	var p problems
	if o.Expiry <= o.IssuedAt {
		p.add("exp must be after iat")
	}
	if o.Redeemed != 0 && (o.Redeemed < o.IssuedAt || o.Redeemed > o.Expiry) {
		p.add("redeemed must lie between iat and exp")
	}
	if o.From == o.To {
		p.add("an agent cannot make an offer to itself")
	}
	p.checkDetails(o.AuthorizationDetails)
	p.checkLimits(o.Limits)
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
		if v.Approver == a.User {
			p.add("vote %d: the user the agent acts for cannot approve the call", i)
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
			p.checkBounds(fmt.Sprintf("permissions[%d] %s", i, ptr), perm.Constraints[ptr].Constraint)
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

func detailSets(details []AuthorizationDetail) (locations []string, actions map[string]bool) {
	seen := make(map[string]bool)
	actions = make(map[string]bool)
	for _, d := range details {
		for _, l := range d.Locations {
			if !seen[l] {
				seen[l] = true
				locations = append(locations, l)
			}
		}
		for _, a := range d.Actions {
			actions[a] = true
		}
	}
	return locations, actions
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
