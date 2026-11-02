package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/x"
)

// toolsCall has the decision point decide the call, then forwards it or
// answers for it.
func (h *Handler) toolsCall(w http.ResponseWriter, r *http.Request, snap *configuration.Snapshot, man configuration.Manifest, token string, msg rpcMessage, body []byte) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		writeRPCError(w, http.StatusOK, msg.ID, -32602, "tools/call needs params.name")
		return
	}
	req := v0.EvaluationRequest{
		Subject:  v0.Entity{Type: "agent", ID: agentOf(token)},
		Action:   v0.Action{Name: params.Name},
		Resource: v0.Entity{Type: pdp.ResourceType, ID: man.Spec.Audience},
		Context:  map[string]any{pdp.TokenKey: token},
	}
	if params.Arguments != nil {
		req.Resource.Properties = map[string]any{"arguments": params.Arguments}
	}
	d, err := h.r.Evaluator().Evaluate(r.Context(), req, v0.PEP{ID: h.r.Config().GatewayID, Kind: v0.PEPGateway}, traceID(r))
	if err != nil {
		h.r.Logger().Error("gateway: decision failed", "tool", params.Name, "err", err)
		status := http.StatusInternalServerError
		if errors.Is(err, pdp.ErrTimeout) {
			status = http.StatusServiceUnavailable
		}
		writeRPCError(w, status, msg.ID, -32000, "doorward could not decide this call; it was not made")
		return
	}
	switch d.Outcome {
	case v0.OutcomeAllow:
		h.proxy(w, r, snap, man, &rewrite{body: body})
	case v0.OutcomeApprovalRequired:
		text := fmt.Sprintf("doorward holds this call for approval: %s is a critical operation. Approval request %s. Retry the exact same call once a person has approved it.",
			params.Name, d.Approval.Request)
		writeToolError(w, msg.ID, text, d)
	default:
		if failed := firstFailed(d); failed == v0.CheckSignature || failed == v0.CheckStatus || failed == v0.CheckTime || failed == v0.CheckAudience || failed == v0.CheckPoP {
			h.challenge(w, http.StatusUnauthorized, "invalid_token", reasonText(d), nil)
			return
		}
		if len(d.Reasons) > 0 && d.Reasons[0].Code == v0.ReasonActionNotGranted {
			// Another mandate may allow the tool: say which, so a client
			// acting for a user can ask for it.
			if scopes := scopesAllowing(snap, man.Spec.Audience, params.Name); len(scopes) > 0 {
				h.challenge(w, http.StatusForbidden, "insufficient_scope", reasonText(d), scopes)
				return
			}
		}
		writeToolError(w, msg.ID, "doorward refused this call: "+reasonText(d), d)
	}
}

func firstFailed(d v0.Decision) v0.CheckName {
	for _, c := range d.Checks {
		if c.Result == v0.CheckFail {
			return c.Name
		}
	}
	return ""
}

func reasonText(d v0.Decision) string {
	if len(d.Reasons) == 0 {
		return string(d.Outcome)
	}
	r := d.Reasons[0]
	if r.Message != "" {
		return fmt.Sprintf("%s (%s)", r.Message, r.Code)
	}
	return string(r.Code)
}

// agentOf reads the agent's name from a grant without verifying it: the
// record's request names who asked, and verification follows.
func agentOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "unknown"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "unknown"
	}
	var claims struct {
		Act struct {
			Sub string `json:"sub"`
		} `json:"act"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Act.Sub == "" {
		return "unknown"
	}
	return claims.Act.Sub
}

// traceID is the trace the caller is in, from its traceparent header, or ""
// when it sent none: the gateway starts no trace of its own.
func traceID(r *http.Request) string {
	tid, _ := x.TraceParent(r)
	return tid
}
