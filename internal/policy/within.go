// Package policy compares permissions: whether one set lies within another,
// and what bounds apply to one operation. The Admin API uses it to refuse a
// mandate wider than an agent's ceiling; the STS uses it to build grants.
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	v0 "github.com/vladmsnk/agentbox/api/v0"
)

// Tier orders sensitivity tiers: read < write < critical.
func Tier(s v0.Sensitivity) int {
	switch s {
	case v0.SensitivityRead:
		return 0
	case v0.SensitivityWrite:
		return 1
	default:
		return 2
	}
}

// Allows reports whether perms let action be called at location, ignoring
// constraints.
func Allows(perms []v0.Permission, location, action string) bool {
	for _, p := range perms {
		if slices.Contains(p.Locations, location) && slices.Contains(p.Actions, action) {
			return true
		}
	}
	return false
}

// Effective returns the bounds perms put on each argument of action at
// location. Several entries may cover the same operation; every bound of
// every entry applies, so the result is the tightest of them.
func Effective(perms []v0.Permission, location, action string) map[string]v0.Constraint {
	out := make(map[string]v0.Constraint)
	for _, p := range perms {
		if !slices.Contains(p.Locations, location) || !slices.Contains(p.Actions, action) {
			continue
		}
		for field, c := range p.Constraints {
			out[field] = Tighten(out[field], c)
		}
	}
	return out
}

// Tighten combines two constraints on one field into the one that holds
// exactly when both do. Where they cannot both hold the result is whichever
// came second; callers that care validate that separately.
func Tighten(a, b v0.Constraint) v0.Constraint {
	out := a
	if b.Max != nil && (out.Max == nil || *b.Max < *out.Max) {
		out.Max = b.Max
	}
	if b.Min != nil && (out.Min == nil || *b.Min > *out.Min) {
		out.Min = b.Min
	}
	if b.OneOf != nil {
		if out.OneOf == nil {
			out.OneOf = b.OneOf
		} else {
			var both []any
			for _, v := range out.OneOf {
				if containsScalar(b.OneOf, v) {
					both = append(both, v)
				}
			}
			out.OneOf = both
		}
	}
	if b.Equals != nil {
		out.Equals = b.Equals
	}
	if b.Prefix != nil && (out.Prefix == nil || len(*b.Prefix) > len(*out.Prefix)) {
		out.Prefix = b.Prefix
	}
	return out
}

// Declared says whether an operation at a location has an argument. A
// bound on an argument the operation does not have does not apply to it: an
// agent may write "/amount at most 10000" once for several operations, and
// it means something only where there is an amount.
type Declared func(location, action, field string) bool

// Within reports every way inner is not inside outer: an operation outer
// does not allow, or an argument bound outer sets that inner does not meet.
// It is what makes a mandate's consent text true: what the user reads is
// never wider than what the agent may be granted. The names label the two
// sides in the messages. A nil declared treats every argument as declared.
func Within(inner []v0.Permission, innerName string, outer []v0.Permission, outerName string, declared Declared) []string {
	if declared == nil {
		declared = func(string, string, string) bool { return true }
	}
	var problems []string
	seen := make(map[string]bool)
	for _, p := range inner {
		for _, loc := range p.Locations {
			for _, act := range p.Actions {
				key := loc + " " + act
				if seen[key] {
					continue
				}
				seen[key] = true
				if !Allows(outer, loc, act) {
					problems = append(problems, fmt.Sprintf("%s allows %s at %s, which %s does not", innerName, act, loc, outerName))
					continue
				}
				in, out := Effective(inner, loc, act), Effective(outer, loc, act)
				for _, field := range sortedKeys(out) {
					if !declared(loc, act, field) {
						continue
					}
					ic, ok := in[field]
					if !ok {
						problems = append(problems, fmt.Sprintf("%s leaves %s of %s unbounded, but %s bounds it", innerName, field, act, outerName))
						continue
					}
					if err := Tighter(ic, out[field]); err != nil {
						problems = append(problems, fmt.Sprintf("%s: %s of %s: %v", innerName, field, act, err))
					}
				}
			}
		}
	}
	return problems
}

// Tighter returns nil when every value inner accepts, outer accepts too.
func Tighter(inner, outer v0.Constraint) error {
	if outer.Max != nil {
		switch {
		case inner.Max != nil && *inner.Max <= *outer.Max:
		case inner.Equals != nil && numberLE(inner.Equals, *outer.Max):
		case inner.OneOf != nil && allNumbers(inner.OneOf, func(f float64) bool { return f <= *outer.Max }):
		default:
			return fmt.Errorf("must stay at or below %v", *outer.Max)
		}
	}
	if outer.Min != nil {
		switch {
		case inner.Min != nil && *inner.Min >= *outer.Min:
		case inner.Equals != nil && numberGE(inner.Equals, *outer.Min):
		case inner.OneOf != nil && allNumbers(inner.OneOf, func(f float64) bool { return f >= *outer.Min }):
		default:
			return fmt.Errorf("must stay at or above %v", *outer.Min)
		}
	}
	if outer.OneOf != nil {
		switch {
		case inner.Equals != nil && containsScalar(outer.OneOf, inner.Equals):
		case inner.OneOf != nil && subset(inner.OneOf, outer.OneOf):
		default:
			return fmt.Errorf("must be one of %v", outer.OneOf)
		}
	}
	if outer.Equals != nil {
		if inner.Equals == nil || !scalarEqual(inner.Equals, outer.Equals) {
			return fmt.Errorf("must equal %v", outer.Equals)
		}
	}
	if outer.Prefix != nil {
		switch {
		case inner.Prefix != nil && strings.HasPrefix(*inner.Prefix, *outer.Prefix):
		case inner.Equals != nil && hasPrefix(inner.Equals, *outer.Prefix):
		case inner.OneOf != nil && allStrings(inner.OneOf, func(s string) bool { return strings.HasPrefix(s, *outer.Prefix) }):
		default:
			return fmt.Errorf("must start with %q", *outer.Prefix)
		}
	}
	return nil
}

// Satisfies reports whether value meets every bound of c. A missing value
// (nil) never does: a constrained argument has to be present.
func Satisfies(c v0.Constraint, value any) error {
	if value == nil {
		return fmt.Errorf("is required")
	}
	if c.Max != nil && !numberLE(value, *c.Max) {
		return fmt.Errorf("%v is above the maximum %v", value, *c.Max)
	}
	if c.Min != nil && !numberGE(value, *c.Min) {
		return fmt.Errorf("%v is below the minimum %v", value, *c.Min)
	}
	if c.OneOf != nil && !containsScalar(c.OneOf, value) {
		return fmt.Errorf("%v is not one of %v", value, c.OneOf)
	}
	if c.Equals != nil && !scalarEqual(value, c.Equals) {
		return fmt.Errorf("%v is not %v", value, c.Equals)
	}
	if c.Prefix != nil && !hasPrefix(value, *c.Prefix) {
		return fmt.Errorf("%v does not start with %q", value, *c.Prefix)
	}
	return nil
}

// ---------------------------------------------------------------- scalars

// Scalars arrive from JSON as float64, string or bool. Integers that came
// through other decoders are accepted too.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	}
	return 0, false
}

func numberLE(v any, max float64) bool { f, ok := number(v); return ok && f <= max }
func numberGE(v any, min float64) bool { f, ok := number(v); return ok && f >= min }

func hasPrefix(v any, p string) bool { s, ok := v.(string); return ok && strings.HasPrefix(s, p) }

func scalarEqual(a, b any) bool {
	if fa, ok := number(a); ok {
		fb, ok := number(b)
		return ok && fa == fb
	}
	return a == b
}

func containsScalar(list []any, v any) bool {
	for _, x := range list {
		if scalarEqual(x, v) {
			return true
		}
	}
	return false
}

func subset(inner, outer []any) bool {
	for _, v := range inner {
		if !containsScalar(outer, v) {
			return false
		}
	}
	return true
}

func allNumbers(list []any, ok func(float64) bool) bool {
	for _, v := range list {
		f, isNum := number(v)
		if !isNum || !ok(f) {
			return false
		}
	}
	return true
}

func allStrings(list []any, ok func(string) bool) bool {
	for _, v := range list {
		s, isStr := v.(string)
		if !isStr || !ok(s) {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]v0.Constraint) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
