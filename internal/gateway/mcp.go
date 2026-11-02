// Package gateway is doorward's thin MCP gateway (C1): one address per MCP
// manifest, in front of the real server. It takes the agent's grant,
// filters the tool list to it, has the decision point decide every tool
// call, forwards allowed calls with the server's own credential, and
// answers refusals and holds inside the protocol. Everything else the
// protocol carries passes through unchanged.
package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/admin"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/policy"
	"github.com/vladmsnk/doorward/internal/sealer"
)

// Prefix is where the gateway serves manifests: /mcp/{manifest name}.
const Prefix = "/mcp/"

// MaxBody bounds one JSON-RPC message from a client.
const MaxBody = 4 << 20

// MetaKey is the _meta key doorward sets on the tool results it writes
// itself (refusals and holds): the decision's ID, outcome and reasons.
const MetaKey = "dev.doorward/decision"

// Gateway serves the MCP endpoints. Config, PDP, Verifier, Secrets and
// Sealer are required.
type Gateway struct {
	Config   *configuration.Cache
	PDP      *pdp.PDP
	Verifier *grant.Verifier
	Secrets  configuration.SecretManager
	Sealer   *sealer.Sealer
	// ID names this gateway as the point of enforcement in records.
	ID  string
	Log *slog.Logger
	// Transport reaches upstream servers; nil means the default.
	Transport http.RoundTripper
	// Origins are the browser origins allowed to connect, besides the
	// gateway's own host. A request with another Origin gets 403.
	Origins []string

	mu     sync.Mutex
	creds  map[string]cachedCred
	ckVers uint64
}

type cachedCred struct {
	header, value string
}

// Handler serves Prefix.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(Prefix+"{name}", g.serve)
	return mux
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	snap, err := g.Config.Current(r.Context())
	if err != nil {
		g.log().Error("gateway: configuration", "err", err)
		http.Error(w, "the gateway cannot read its configuration", http.StatusInternalServerError)
		return
	}
	man, ok := snap.ManifestByName(r.PathValue("name"))
	if !ok || man.Spec.Protocol != v0.ProtocolMCP {
		http.NotFound(w, r)
		return
	}
	if !g.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		g.challenge(w, http.StatusUnauthorized, "", "", scopesFor(snap, man.Spec.Audience))
		return
	}
	switch r.Method {
	case http.MethodPost:
		g.post(w, r, snap, man, token)
	case http.MethodGet, http.MethodDelete:
		// A listening stream, or the end of a session: the grant must be
		// good, and the rest is the server's.
		res, err := g.Verifier.Verify(r.Context(), token, man.Spec.Audience)
		if err != nil {
			g.log().Error("gateway: verifying a grant", "err", err)
		}
		if !res.OK() {
			g.refuseGrant(w, res, snap, man)
			return
		}
		g.proxy(w, r, man, nil)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) post(w http.ResponseWriter, r *http.Request, snap *configuration.Snapshot, man configuration.Manifest, token string) {
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
	switch msg.Method {
	case "tools/call":
		g.toolsCall(w, r, snap, man, token, msg, body)
	case "tools/list":
		res, err := g.Verifier.Verify(r.Context(), token, man.Spec.Audience)
		if err != nil {
			g.log().Error("gateway: verifying a grant", "err", err)
		}
		if !res.OK() {
			g.refuseGrant(w, res, snap, man)
			return
		}
		allowed := func(tool string) bool {
			return policy.Allows(toPermissions(res.Grant.AuthorizationDetails), man.Spec.Audience, tool) && opDeclared(man, tool)
		}
		g.proxy(w, r, man, &rewrite{id: msg.ID, filter: allowed, body: body})
	default:
		// The manifest describes tools, nothing else, so the gateway can
		// decide only on tools. It passes through the protocol's own
		// housekeeping (initialize, ping, notifications, and a client's
		// response to a server-initiated request) and refuses everything
		// else it cannot reason about, rather than forward it undecided:
		// resources, prompts, logging, sampling, completion.
		if !passthrough(msg.Method) {
			if len(msg.ID) == 0 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			writeRPCError(w, http.StatusOK, msg.ID, -32601, fmt.Sprintf("doorward exposes only the tools this manifest describes; %q is not available through the gateway", msg.Method))
			return
		}
		res, err := g.Verifier.Verify(r.Context(), token, man.Spec.Audience)
		if err != nil {
			g.log().Error("gateway: verifying a grant", "err", err)
		}
		if !res.OK() {
			g.refuseGrant(w, res, snap, man)
			return
		}
		g.proxy(w, r, man, &rewrite{body: body})
	}
}

// passthrough is the set of methods that carry no decision of their own
// and may be forwarded once the grant verifies: the protocol's lifecycle
// and a client's response (no method) to a server-initiated request.
func passthrough(method string) bool {
	switch method {
	case "initialize", "ping", "":
		return true
	default:
		return strings.HasPrefix(method, "notifications/")
	}
}

// ensureUnambiguous refuses a JSON message in which any object has two
// member names that are equal ignoring case, since the decoder here would
// silently collapse them while a case-sensitive server would not.
func ensureUnambiguous(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkUnambiguous(dec)
}

func walkUnambiguous(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, _ := key.(string)
			folded := strings.ToLower(name)
			if seen[folded] {
				return fmt.Errorf("member %q appears more than once", name)
			}
			seen[folded] = true
			if err := walkUnambiguous(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // the closing brace
		return err
	case '[':
		for dec.More() {
			if err := walkUnambiguous(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // the closing bracket
		return err
	}
	return nil
}

// toolsCall has the decision point decide the call, then forwards it or
// answers for it.
func (g *Gateway) toolsCall(w http.ResponseWriter, r *http.Request, snap *configuration.Snapshot, man configuration.Manifest, token string, msg rpcMessage, body []byte) {
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
	d, err := g.PDP.Evaluate(r.Context(), req, v0.PEP{ID: g.ID, Kind: v0.PEPGateway}, traceID(r))
	if err != nil {
		g.log().Error("gateway: decision failed", "tool", params.Name, "err", err)
		status := http.StatusInternalServerError
		if errors.Is(err, pdp.ErrTimeout) {
			status = http.StatusServiceUnavailable
		}
		writeRPCError(w, status, msg.ID, -32000, "doorward could not decide this call; it was not made")
		return
	}
	switch d.Outcome {
	case v0.OutcomeAllow:
		g.proxy(w, r, man, &rewrite{body: body})
	case v0.OutcomeApprovalRequired:
		text := fmt.Sprintf("doorward holds this call for approval: %s is a critical operation. Approval request %s. Retry the exact same call once a person has approved it.",
			params.Name, d.Approval.Request)
		writeToolError(w, msg.ID, text, d)
	default:
		if failed := firstFailed(d); failed == v0.CheckSignature || failed == v0.CheckStatus || failed == v0.CheckTime || failed == v0.CheckAudience || failed == v0.CheckPoP {
			g.challenge(w, http.StatusUnauthorized, "invalid_token", reasonText(d), nil)
			return
		}
		if len(d.Reasons) > 0 && d.Reasons[0].Code == v0.ReasonActionNotGranted {
			// Another mandate may allow the tool: say which, so a client
			// acting for a user can ask for it.
			if scopes := scopesAllowing(snap, man.Spec.Audience, params.Name); len(scopes) > 0 {
				g.challenge(w, http.StatusForbidden, "insufficient_scope", reasonText(d), scopes)
				return
			}
		}
		writeToolError(w, msg.ID, "doorward refused this call: "+reasonText(d), d)
	}
}

// rewrite is what the proxy does to one forwarded POST: the body to send,
// and for tools/list, the tools to keep.
type rewrite struct {
	body   []byte
	id     json.RawMessage
	filter func(tool string) bool
}

// proxy forwards the request to the manifest's upstream with the server's
// credential, and streams the answer back, rewriting a tool list on the
// way when asked.
func (g *Gateway) proxy(w http.ResponseWriter, r *http.Request, man configuration.Manifest, rw *rewrite) {
	target, err := url.Parse(man.Spec.Upstream.URL)
	if err != nil {
		http.Error(w, "the manifest's upstream URL is invalid", http.StatusBadGateway)
		return
	}
	header, value, err := g.credential(r.Context(), man)
	if err != nil {
		g.log().Error("gateway: upstream credential", "manifest", man.Metadata.Name, "err", err)
		http.Error(w, "the gateway cannot read the upstream credential", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Transport:     g.Transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = target
			pr.Out.Host = target.Host
			// Forward only the protocol's own transport and tracing
			// headers, never the client's. The agent's grant, cookies and
			// anything a server might mistake for an identity signal (an
			// X-Forwarded-* header, say) are dropped; the upstream
			// credential is set in their place.
			pr.Out.Header = forwardHeaders(pr.In.Header)
			if header != "" {
				pr.Out.Header.Set(header, value)
			}
			if rw != nil && rw.body != nil {
				pr.Out.Body = io.NopCloser(bytes.NewReader(rw.body))
				pr.Out.ContentLength = int64(len(rw.body))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log().Error("gateway: upstream", "manifest", man.Metadata.Name, "err", err)
			http.Error(w, "the server behind the gateway did not answer", http.StatusBadGateway)
		},
	}
	if rw != nil && rw.filter != nil {
		rp.ModifyResponse = func(res *http.Response) error { return filterTools(res, rw) }
	}
	rp.ServeHTTP(w, r)
}

// credential returns the header the upstream wants, opened from the secret
// store; cached per configuration version.
func (g *Gateway) credential(ctx context.Context, man configuration.Manifest) (string, string, error) {
	auth := man.Spec.Upstream.Auth
	if auth == nil {
		return "", "", nil
	}
	version, err := g.Config.Store.ConfigVersion(ctx)
	if err != nil {
		return "", "", err
	}
	g.mu.Lock()
	if g.ckVers != version {
		g.creds, g.ckVers = map[string]cachedCred{}, version
	}
	c, ok := g.creds[auth.SecretRef]
	g.mu.Unlock()
	if ok {
		return c.header, c.value, nil
	}
	sealed, err := g.Secrets.Get(ctx, auth.SecretRef)
	if err != nil {
		return "", "", fmt.Errorf("secret %s: %w", auth.SecretRef, err)
	}
	plain, err := g.Sealer.Open(sealed, admin.SecretPurpose(auth.SecretRef))
	if err != nil {
		return "", "", fmt.Errorf("secret %s: %w", auth.SecretRef, err)
	}
	c = cachedCred{header: auth.Header, value: auth.Prefix + string(plain)}
	g.mu.Lock()
	g.creds[auth.SecretRef] = c
	g.mu.Unlock()
	return c.header, c.value, nil
}

// refuseGrant answers a request whose grant did not verify: 401 for a bad
// or expired grant, as the protocol requires.
func (g *Gateway) refuseGrant(w http.ResponseWriter, res grant.Result, snap *configuration.Snapshot, man configuration.Manifest) {
	desc := ""
	if res.Reason != nil {
		desc = res.Reason.Message
	}
	g.challenge(w, http.StatusUnauthorized, "invalid_token", desc, scopesFor(snap, man.Spec.Audience))
}

// challenge writes a bearer challenge (RFC 6750). Scopes are the mandates
// that would help, named so a client can ask the user for them.
func (g *Gateway) challenge(w http.ResponseWriter, status int, errCode, desc string, scopes []string) {
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

// forwardHeaders keeps only the headers the MCP transport defines and the
// tracing headers, dropping everything else the client sent. The upstream
// credential is added by the caller.
func forwardHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for name, values := range in {
		if ck := http.CanonicalHeaderKey(name); forwardable(ck) {
			out[ck] = values
		}
	}
	return out
}

func forwardable(canonical string) bool {
	switch canonical {
	case "Accept", "Content-Type", "Traceparent", "Tracestate", "Baggage", "Last-Event-Id":
		return true
	default:
		// MCP-Protocol-Version, Mcp-Session-Id, Mcp-Method, Mcp-Name and
		// the Mcp-Param-* request-metadata headers.
		return strings.HasPrefix(canonical, "Mcp-")
	}
}

func (g *Gateway) originAllowed(r *http.Request) bool {
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
	for _, o := range g.Origins {
		if strings.EqualFold(strings.TrimRight(o, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

func (g *Gateway) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

// ---------------------------------------------------------------- helpers

// writeToolError answers a tools/call with a tool execution error, which
// the protocol says is how a refused or invalid call is reported so the
// model can correct itself, with the decision under _meta.
func writeToolError(w http.ResponseWriter, id json.RawMessage, text string, d v0.Decision) {
	meta := map[string]any{"decision": d.ID, "outcome": d.Outcome, "action_hash": d.ActionHash}
	if len(d.Reasons) > 0 {
		meta["reasons"] = d.Reasons
	}
	if d.Approval != nil {
		meta["approval"] = d.Approval.Request
	}
	result := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": true,
		"_meta":   map[string]any{MetaKey: meta},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	msg := map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": message}}
	if id != nil {
		msg["id"] = id
	}
	_ = json.NewEncoder(w).Encode(msg)
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

func toPermissions(details []v0.AuthorizationDetail) []v0.Permission {
	out := make([]v0.Permission, len(details))
	for i, d := range details {
		out[i] = v0.Permission{Locations: d.Locations, Actions: d.Actions, Constraints: d.Constraints}
	}
	return out
}

func opDeclared(man configuration.Manifest, tool string) bool {
	for _, op := range man.Spec.Operations {
		if op.Name == tool {
			return true
		}
	}
	return false
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

// scopesAllowing names the enabled mandates that allow one tool.
func scopesAllowing(snap *configuration.Snapshot, audience, tool string) []string {
	return snap.MandatesWhere(func(m v0.Mandate) bool { return policy.Allows(m.Spec.Permissions, audience, tool) })
}

func traceID(r *http.Request) string {
	if tp := r.Header.Get("traceparent"); len(tp) >= 35 && tp[2] == '-' {
		return tp[3:35]
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
