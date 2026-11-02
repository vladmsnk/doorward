// Package gateway is doorward's thin MCP gateway (C1): one address per MCP
// manifest, in front of the real server. It takes the agent's grant,
// filters the tool list to it, has the decision point decide every tool
// call, forwards allowed calls with the server's own credential, and
// answers refusals and holds inside the protocol. It passes the protocol's
// own housekeeping through, and refuses what a manifest cannot describe.
package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/core"
	"github.com/vladmsnk/doorward/internal/policy"
	"github.com/vladmsnk/doorward/internal/x"
)

// Prefix is where the gateway serves manifests: /mcp/{manifest name}.
const Prefix = "/mcp/"

// Handler serves the MCP endpoints, one per MCP manifest. It keeps the
// upstream credentials it has opened, per configuration version.
type Handler struct {
	r InternalRegistry

	mu     sync.Mutex
	creds  map[string]cachedCred
	ckVers uint64
}

// NewHandler returns the gateway.
func NewHandler(r InternalRegistry) *Handler { return &Handler{r: r} }

type cachedCred struct {
	header, value string
}

// SetPublicRoutes serves every MCP manifest at Prefix + its name.
func (h *Handler) SetPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc(Prefix+"{name}", h.serve)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	snap, err := h.r.ConfigurationCache().Current(r.Context())
	if err != nil {
		h.r.Logger().Error("gateway: configuration", "err", err)
		http.Error(w, "the gateway cannot read its configuration", http.StatusInternalServerError)
		return
	}
	man, ok := snap.ManifestByName(r.PathValue("name"))
	if !ok || man.Spec.Protocol != v0.ProtocolMCP {
		http.NotFound(w, r)
		return
	}
	if !h.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	token, ok := x.BearerToken(r)
	if !ok {
		h.challenge(w, http.StatusUnauthorized, "", "", scopesFor(snap, man.Spec.Audience))
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.post(w, r, snap, man, token)
	case http.MethodGet, http.MethodDelete:
		// A listening stream, or the end of a session: the grant must be
		// good, and the rest is the server's.
		res, err := h.r.GrantVerifier().Verify(r.Context(), token, man.Spec.Audience)
		if err != nil {
			h.r.Logger().Error("gateway: verifying a grant", "err", err)
		}
		if !res.OK() {
			h.refuseGrant(w, res, snap, man)
			return
		}
		h.proxy(w, r, snap, man, nil)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) post(w http.ResponseWriter, r *http.Request, snap *configuration.Snapshot, man configuration.Manifest, token string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		writeRPCError(w, http.StatusBadRequest, nil, -32600, "the gateway takes one JSON-RPC message per request, not a batch")
		return
	}
	// The gateway decides on its own reading of the message and forwards
	// the same bytes to the server. Go's JSON decoder matches member names
	// case-insensitively and keeps the last of any duplicates, so a message
	// that carries, say, both "method" and "Method", or "arguments" and
	// "Arguments", could be read one way here and another by the server.
	// Any such message is refused, so the two readings cannot diverge.
	if err := ensureUnambiguous(body); err != nil {
		writeRPCError(w, http.StatusBadRequest, nil, -32600, "the message is ambiguous: "+err.Error())
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err != nil || msg.JSONRPC != "2.0" {
		writeRPCError(w, http.StatusBadRequest, nil, -32700, "the body is not a JSON-RPC message")
		return
	}
	modern, err := checkHeaders(r.Header, msg)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, msg.ID, codeHeaderMismatch, "Header mismatch: "+err.Error())
		return
	}
	switch msg.Method {
	case "tools/call":
		h.toolsCall(w, r, snap, man, token, msg, body, modern)
	case "tools/list":
		res, err := h.r.GrantVerifier().Verify(r.Context(), token, man.Spec.Audience)
		if err != nil {
			h.r.Logger().Error("gateway: verifying a grant", "err", err)
		}
		if !res.OK() {
			h.refuseGrant(w, res, snap, man)
			return
		}
		allowed := func(tool string) bool {
			return policy.Allows(core.Permissions(res.Grant.AuthorizationDetails), man.Spec.Audience, tool) && core.Operation(man.Manifest, tool) != nil
		}
		h.proxy(w, r, snap, man, &rewrite{id: msg.ID, filter: allowed, body: body, private: modern})
	default:
		// The manifest describes tools, nothing else, so the gateway can
		// decide only on tools. It passes through the protocol's own
		// housekeeping (initialize or server/discover, ping, the
		// subscription stream, notifications, and a client's response to a
		// server-initiated request) and refuses everything else it cannot
		// reason about, rather than forward it undecided: resources,
		// prompts, logging, sampling, completion.
		if !passthrough(msg.Method) {
			if len(msg.ID) == 0 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// A modern revision answers an unknown method with 404.
			status := http.StatusOK
			if modern {
				status = http.StatusNotFound
			}
			writeRPCError(w, status, msg.ID, -32601, fmt.Sprintf("doorward exposes only the tools this manifest describes; %q is not available through the gateway", msg.Method))
			return
		}
		res, err := h.r.GrantVerifier().Verify(r.Context(), token, man.Spec.Audience)
		if err != nil {
			h.r.Logger().Error("gateway: verifying a grant", "err", err)
		}
		if !res.OK() {
			h.refuseGrant(w, res, snap, man)
			return
		}
		h.proxy(w, r, snap, man, &rewrite{body: body})
	}
}

// passthrough is the set of methods that carry no decision of their own
// and may be forwarded once the grant verifies: the protocol's lifecycle,
// the stream of change notifications, and a client's response (no method)
// to a server-initiated request.
func passthrough(method string) bool {
	switch method {
	case "initialize", "server/discover", "ping", "subscriptions/listen", "":
		return true
	default:
		return strings.HasPrefix(method, "notifications/")
	}
}

func (h *Handler) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, o := range h.r.Config().Origins() {
		if strings.EqualFold(strings.TrimRight(o, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}
