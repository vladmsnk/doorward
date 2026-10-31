package policy

import (
	"encoding/json"
	"sort"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// OnePerOperation rewrites permissions so that each operation at each
// location appears in exactly one entry, carrying the conjunction of every
// bound the input put on it. Operations at one location with the same
// bounds share an entry. The result allows exactly what the input allows,
// and can be read one entry at a time, as a grant must be.
//
// It fails when an operation's bounds cannot all hold: such an operation
// allows nothing, and a grant should not list it.
func OnePerOperation(perms []v0.Permission) ([]v0.Permission, error) {
	type op struct{ loc, act string }
	var ops []op
	seen := make(map[op]bool)
	for _, p := range perms {
		for _, loc := range p.Locations {
			for _, act := range p.Actions {
				if o := (op{loc, act}); !seen[o] {
					seen[o] = true
					ops = append(ops, o)
				}
			}
		}
	}
	type group struct {
		loc     string
		actions []string
		bounds  map[string]v0.Constraint
	}
	groups := make(map[string]*group)
	for _, o := range ops {
		bounds, err := Effective(perms, o.loc, o.act)
		if err != nil {
			return nil, err
		}
		key, err := json.Marshal(bounds)
		if err != nil {
			return nil, err
		}
		k := o.loc + "\x00" + string(key)
		g, ok := groups[k]
		if !ok {
			g = &group{loc: o.loc, bounds: bounds}
			groups[k] = g
		}
		g.actions = append(g.actions, o.act)
	}
	out := make([]v0.Permission, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.actions)
		p := v0.Permission{Locations: []string{g.loc}, Actions: g.actions}
		if len(g.bounds) > 0 {
			p.Constraints = g.bounds
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Locations[0] != out[j].Locations[0] {
			return out[i].Locations[0] < out[j].Locations[0]
		}
		return out[i].Actions[0] < out[j].Actions[0]
	})
	return out, nil
}
