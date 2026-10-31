// Package core is the decision core: given a verified grant and a call, it
// answers allow, deny or approval_required and says why. Each step is a
// pure function over the grant, the call and the manifest; the HTTP
// endpoint that runs them in order and writes the record comes last (B5).
package core

import v0 "github.com/vladmsnk/agentbox/api/v0"

// Call is what an agent asks to do: one operation of a resource, with its
// arguments, as the point of enforcement read them from the request.
type Call struct {
	// Resource is the resource's audience, as in the grant's aud.
	Resource string
	// Action is the operation's name in the resource's manifest.
	Action string
	// Arguments are the call's arguments as decoded JSON: objects are
	// map[string]any, numbers float64. Constraints address them by JSON
	// Pointer.
	Arguments map[string]any
}

// Operation returns the manifest's operation of that name, or nil.
func Operation(m v0.Manifest, name string) *v0.Operation {
	for i := range m.Spec.Operations {
		if m.Spec.Operations[i].Name == name {
			return &m.Spec.Operations[i]
		}
	}
	return nil
}

// Hash is the call's action hash: the digest of its canonical form, as an
// approval and a single-use grant name it.
func (c Call) Hash() (string, error) {
	return v0.ApprovedAction{Name: c.Action, Location: c.Resource, Arguments: c.Arguments}.Hash()
}
