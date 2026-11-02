package configuration

import (
	"slices"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// MayRequest reports whether an agent may ask for a mandate: an open one,
// whoever it is, or one it lists once it is verified. A suspended agent
// may ask for nothing. Whether the grant it would get lies within the
// agent is for the issuer to check.
func MayRequest(a v0.Agent, m v0.Mandate) bool {
	switch {
	case a.Spec.Status == v0.AgentSuspended:
		return false
	case m.Spec.Open:
		return true
	}
	return a.Spec.Status == v0.AgentVerified && slices.Contains(a.Spec.Mandates, m.Metadata.Name)
}
