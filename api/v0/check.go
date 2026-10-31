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
// such as a task type lying within an agent's permissions, belong to the
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
	if c := g.Task.Started.ConfirmedAt; c != 0 && c > g.IssuedAt {
		p.add("task.started.confirmed_at is after iat: the user cannot confirm a task after its grant was issued")
	}
	// A user task names the user and where that identity came from; a
	// service task is issued to the agent itself.
	if g.Subject == g.ClientID && g.SubjectID != nil {
		p.add("sub equals client_id, so this is a service task and carries no sub_id")
	}
	if g.Subject != g.ClientID && g.SubjectID == nil {
		p.add("sub is a user, so sub_id must say which identity provider named them")
	}
	switch g.Task.Started.Trigger {
	case TriggerUI, TriggerChat:
		if g.Task.Initiator == "" {
			p.add("a task a user started names the application that started it")
		}
	default:
		if g.Task.Initiator != "" {
			p.add("a %s task has no initiator: the agent started it", g.Task.Started.Trigger)
		}
		if g.Task.Started.ConfirmedAt != 0 {
			p.add("a %s task has nobody to confirm it", g.Task.Started.Trigger)
		}
	}
	if !sameSet(g.Audience, detailLocations(g.AuthorizationDetails)) {
		p.add("aud must list exactly the locations of authorization_details")
	}
	p.checkDetails(g.AuthorizationDetails)
	p.checkLimits(g.Limits)
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
	seen := make(map[AgentIdentity]bool)
	for _, id := range a.Spec.Identities {
		if seen[id] {
			p.add("identity %+v is listed twice", id)
		}
		seen[id] = true
	}
	p.checkPermissions(a.Spec.Permissions)
	p.checkLimits(a.Spec.Limits)
	return p.err()
}

// Check enforces the rules of a task type that span fields.
func (t TaskType) Check() error {
	var p problems
	p.checkPermissions(t.Spec.Permissions)
	p.checkLimits(t.Spec.Limits)
	return p.err()
}

// Check enforces the rules of a task request that span fields.
func (r TaskRequest) Check() error {
	var p problems
	for _, t := range r.AuthorizationDetails {
		switch t.Trigger {
		case TriggerUI, TriggerChat:
			if r.RequestedTokenType != TokenTypeTaskTicket {
				p.add("an application starting a user task asks for a ticket, not %s", r.RequestedTokenType)
			}
		default:
			if r.RequestedTokenType != TokenTypeAccessToken {
				p.add("an agent starting a %s task asks for the grant itself", t.Trigger)
			}
			if r.Confirmation != "" {
				p.add("a %s task has nobody to confirm it", t.Trigger)
			}
			if r.SubjectTokenType != TokenTypeJWT {
				p.add("a %s task is started with the agent's own token, type jwt", t.Trigger)
			}
		}
	}
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
				p.add("vote %d: on a user route only the task's user votes", i)
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
