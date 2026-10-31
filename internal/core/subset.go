package core

import (
	"errors"
	"fmt"
	"math"
	"sort"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/policy"
)

// Subset is the subset check (B2): the call lies inside the grant. The
// grant must allow the operation at the resource, and every bound it sets
// on the operation's arguments must hold.
//
// Several entries of a grant may name the same operation; every bound of
// every one of them applies, as policy.Effective has it. A bound on an
// argument is checked whenever the call carries that argument. When the
// call does not, the bound applies only if the operation declares the
// argument: an entry can bound /amount for several operations, and it
// means nothing for the ones that take no amount.
//
// op is the operation as the resource's manifest declares it, or nil when
// the manifest has no operation of that name.
func Subset(g v0.Grant, op *v0.Operation, call Call) (v0.Check, *v0.Reason) {
	perms := Permissions(g.AuthorizationDetails)
	if !policy.Allows(perms, call.Resource, call.Action) {
		return failAction(fmt.Sprintf("the grant does not allow %s at %s", call.Action, call.Resource))
	}
	if op == nil {
		return failAction(fmt.Sprintf("the manifest of %s declares no operation %s", call.Resource, call.Action))
	}
	bounds, err := policy.Effective(perms, call.Resource, call.Action)
	var u *policy.Unsatisfiable
	if errors.As(err, &u) {
		// Bounds that contradict each other allow no call, whatever the
		// arguments.
		return failField(v0.ReasonConstraintViolated, u.Field, u.Error())
	}
	if err != nil {
		return failAction(err.Error())
	}
	fields := make([]string, 0, len(bounds))
	for f := range bounds {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, field := range fields {
		param, declared := op.Params[field]
		value, present := lookup(call.Arguments, field)
		if !present || value == nil {
			if !declared {
				continue
			}
			return failField(v0.ReasonFieldMissing, field, fmt.Sprintf("%s is bounded by the grant but missing from the call", field))
		}
		if declared {
			if msg := wrongType(param.Type, value); msg != "" {
				return failField(v0.ReasonConstraintViolated, field, msg)
			}
		}
		if msg := violation(bounds[field], value); msg != "" {
			return failField(v0.ReasonConstraintViolated, field, msg)
		}
	}
	return v0.Check{Name: v0.CheckSubset, Result: v0.CheckPass}, nil
}

// Permissions reads a grant's authorization_details as permissions, the
// form package policy compares.
func Permissions(details []v0.AuthorizationDetail) []v0.Permission {
	out := make([]v0.Permission, len(details))
	for i, d := range details {
		out[i] = v0.Permission{Locations: d.Locations, Actions: d.Actions, Constraints: d.Constraints}
	}
	return out
}

func failAction(msg string) (v0.Check, *v0.Reason) {
	return v0.Check{Name: v0.CheckSubset, Result: v0.CheckFail, Detail: msg},
		&v0.Reason{Code: v0.ReasonActionNotGranted, Message: msg}
}

func failField(code v0.ReasonCode, field, msg string) (v0.Check, *v0.Reason) {
	return v0.Check{Name: v0.CheckSubset, Result: v0.CheckFail, Detail: field},
		&v0.Reason{Code: code, Field: field, Message: msg}
}

// wrongType says how a value differs from the type the manifest declares,
// or returns "" when it matches.
func wrongType(t v0.ParamType, value any) string {
	var ok bool
	switch t {
	case v0.ParamString:
		_, ok = value.(string)
	case v0.ParamBoolean:
		_, ok = value.(bool)
	case v0.ParamNumber:
		_, ok = value.(float64)
	case v0.ParamInteger:
		f, isNum := value.(float64)
		ok = isNum && f == math.Trunc(f)
	default:
		return ""
	}
	if ok {
		return ""
	}
	return fmt.Sprintf("%s is %s, but the manifest declares %s", jsonText(value), jsonType(value), t)
}

// violation names the first bound of c that value breaks, in the grant's
// words, or returns "" when value meets them all.
func violation(c v0.Constraint, value any) string {
	if policy.Satisfies(c, value) == nil {
		return ""
	}
	v := jsonText(value)
	switch {
	case c.Max != nil && policy.Satisfies(v0.Constraint{Max: c.Max}, value) != nil:
		return fmt.Sprintf("%s is above the grant's max of %v", v, *c.Max)
	case c.Min != nil && policy.Satisfies(v0.Constraint{Min: c.Min}, value) != nil:
		return fmt.Sprintf("%s is below the grant's min of %v", v, *c.Min)
	case c.OneOf != nil && policy.Satisfies(v0.Constraint{OneOf: c.OneOf}, value) != nil:
		return fmt.Sprintf("%s is not one of the grant's %s", v, jsonText(c.OneOf))
	case c.Equals != nil && policy.Satisfies(v0.Constraint{Equals: c.Equals}, value) != nil:
		return fmt.Sprintf("%s is not the grant's %s", v, jsonText(c.Equals))
	case c.Prefix != nil:
		return fmt.Sprintf("%s does not start with the grant's %q", v, *c.Prefix)
	}
	return v + " is outside the grant"
}

// Details writes permissions as a grant's authorization_details.
func Details(perms []v0.Permission) []v0.AuthorizationDetail {
	out := make([]v0.AuthorizationDetail, len(perms))
	for i, p := range perms {
		out[i] = v0.AuthorizationDetail{Type: v0.AuthorizationDetailType, Locations: p.Locations, Actions: p.Actions, Constraints: p.Constraints}
	}
	return out
}
