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

// Unsatisfiable reports bounds on one argument that no value can meet. An
// operation under such bounds allows no call at all: it is refused, never
// read as unbounded.
type Unsatisfiable struct {
	Field string
	Why   string
}

func (u *Unsatisfiable) Error() string {
	if u.Field == "" {
		return u.Why
	}
	return "the bounds on " + u.Field + " cannot all hold: " + u.Why
}

// Effective returns the bounds perms put on each argument of action at
// location. Several entries may cover the same operation; every bound of
// every entry applies, so the result is their conjunction. When the bounds
// on an argument cannot all hold, it returns an *Unsatisfiable naming the
// argument, and the operation allows nothing.
func Effective(perms []v0.Permission, location, action string) (map[string]v0.Constraint, error) {
	out := make(map[string]v0.Constraint)
	for _, p := range perms {
		if !slices.Contains(p.Locations, location) || !slices.Contains(p.Actions, action) {
			continue
		}
		for _, field := range sortedKeys(p.Constraints) {
			c := p.Constraints[field]
			prev, seen := out[field]
			var err error
			if seen {
				c, err = Tighten(prev, c)
			} else {
				err = Admits(c)
			}
			if err != nil {
				return nil, &Unsatisfiable{Field: field, Why: err.Error()}
			}
			out[field] = c
		}
	}
	return out, nil
}

// Coherent reports every operation in perms whose bounds cannot all hold,
// so a document that allows an operation under contradictory bounds is
// refused before anyone relies on it.
func Coherent(perms []v0.Permission, who string) []string {
	var problems []string
	seen := make(map[string]bool)
	for _, p := range perms {
		for _, loc := range p.Locations {
			for _, act := range p.Actions {
				key := loc + " " + act
				if seen[key] {
					continue
				}
				seen[key] = true
				if _, err := Effective(perms, loc, act); err != nil {
					problems = append(problems, fmt.Sprintf("%s allows %s at %s, but %v", who, act, loc, err))
				}
			}
		}
	}
	return problems
}

// Tighten combines two constraints on one field into the one that holds
// exactly when both do. It returns an error, and no constraint, when no
// value can meet both: two one_of lists with nothing in common, two
// different equals, prefixes that diverge, a min above the max.
func Tighten(a, b v0.Constraint) (v0.Constraint, error) {
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
			both := []any{}
			for _, v := range out.OneOf {
				if containsScalar(b.OneOf, v) {
					both = append(both, v)
				}
			}
			if len(both) == 0 {
				return v0.Constraint{}, fmt.Errorf("one_of %v and one_of %v have no value in common", out.OneOf, b.OneOf)
			}
			out.OneOf = both
		}
	}
	if b.Equals != nil {
		if out.Equals != nil && !scalarEqual(out.Equals, b.Equals) {
			return v0.Constraint{}, fmt.Errorf("equals %v and equals %v", out.Equals, b.Equals)
		}
		out.Equals = b.Equals
	}
	if b.Prefix != nil {
		switch {
		case out.Prefix == nil || strings.HasPrefix(*b.Prefix, *out.Prefix):
			out.Prefix = b.Prefix
		case strings.HasPrefix(*out.Prefix, *b.Prefix):
			// out's prefix is the longer one, and implies b's.
		default:
			return v0.Constraint{}, fmt.Errorf("prefix %q and prefix %q diverge", *out.Prefix, *b.Prefix)
		}
	}
	if err := Admits(out); err != nil {
		return v0.Constraint{}, err
	}
	return out, nil
}

// Admits returns nil when at least one value meets every bound of c, and
// says why not otherwise.
func Admits(c v0.Constraint) error {
	if (c.Max != nil || c.Min != nil) && c.Prefix != nil {
		return fmt.Errorf("min and max bound a number and prefix a string; no value is both")
	}
	if c.Min != nil && c.Max != nil && *c.Min > *c.Max {
		return fmt.Errorf("min %v is above max %v", *c.Min, *c.Max)
	}
	if c.OneOf != nil && len(c.OneOf) == 0 {
		return fmt.Errorf("one_of is empty")
	}
	if c.Equals != nil {
		if err := Satisfies(c, c.Equals); err != nil {
			return fmt.Errorf("equals %v does not meet the other bounds: %w", c.Equals, err)
		}
		return nil
	}
	if c.OneOf != nil {
		for _, v := range c.OneOf {
			if Satisfies(c, v) == nil {
				return nil
			}
		}
		return fmt.Errorf("no value of one_of %v meets the other bounds", c.OneOf)
	}
	return nil
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
				out, err := Effective(outer, loc, act)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s allows %s at %s under bounds that cannot all hold, so nothing can lie within it: %v", outerName, act, loc, err))
					continue
				}
				in, err := Effective(inner, loc, act)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s allows %s at %s, but %v", innerName, act, loc, err))
					continue
				}
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
