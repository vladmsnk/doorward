package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/core"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/policy"
)

// refuseGrant answers a request whose grant did not verify: 401 for a bad
// or expired grant, as the protocol requires.
func (h *Handler) refuseGrant(w http.ResponseWriter, res grant.Result, snap *configuration.Snapshot, man configuration.Manifest) {
	desc := ""
	if res.Reason != nil {
		desc = res.Reason.Message
	}
	h.challenge(w, http.StatusUnauthorized, "invalid_token", desc, scopesFor(snap, man.Spec.Audience))
}

// challenge writes a bearer challenge (RFC 6750). Scopes are the mandates
// that would help, named so a client can ask the user for them.
func (h *Handler) challenge(w http.ResponseWriter, status int, errCode, desc string, scopes []string) {
	parts := []string{`realm="doorward"`}
	if errCode != "" {
		parts = append(parts, fmt.Sprintf("error=%q", errCode))
	}
	if desc != "" {
		parts = append(parts, fmt.Sprintf("error_description=%q", strings.ReplaceAll(desc, `"`, "'")))
	}
	if len(scopes) > 0 {
		parts = append(parts, fmt.Sprintf("scope=%q", strings.Join(scopes, " ")))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": firstNonEmpty(errCode, "unauthorized"), "error_description": desc})
}

// scopesFor names the enabled mandates that allow anything at the
// audience: what a client without a grant should ask for.
func scopesFor(snap *configuration.Snapshot, audience string) []string {
	return snap.MandatesWhere(func(m v0.Mandate) bool {
		for _, p := range m.Spec.Permissions {
			for _, loc := range p.Locations {
				if loc == audience {
					return true
				}
			}
		}
		return false
	})
}

// scopesAllowing names the mandates that would let the caller run tool if
// it asked for them: enabled, for the same kind of principal as its grant,
// ones its agent may request, and only when the agent's own ceiling allows
// the tool. A caller that could obtain none gets a plain refusal instead
// of an invitation to a step-up that can only fail.
func scopesAllowing(snap *configuration.Snapshot, man configuration.Manifest, tool string, p *v0.Principal) []string {
	if p == nil {
		return nil
	}
	op := core.Operation(man.Manifest, tool)
	agent, err := snap.Agent(p.Agent)
	if op == nil || err != nil {
		return nil
	}
	if !policy.Allows(agent.Spec.Permissions, man.Spec.Audience, tool) || policy.Tier(op.Sensitivity) > policy.Tier(agent.Spec.MaxSensitivity) {
		return nil
	}
	principal := v0.PrincipalService
	if p.User != "" {
		principal = v0.PrincipalUser
	}
	return snap.MandatesWhere(func(m v0.Mandate) bool {
		return m.Spec.Principal == principal && configuration.MayRequest(agent.Agent, m) && policy.Allows(m.Spec.Permissions, man.Spec.Audience, tool)
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
