// Package demoledger is a small MCP server over Streamable HTTP, for trying
// doorward's gateway: a ledger with three tools, one of each tier. It wants
// an API key, which the gateway adds from its secret store, and it logs
// which credential each request carried, so the demo shows the key arriving
// and the agent's grant never doing so.
package demoledger

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
)

// Protocol versions the server speaks, newest first: 2026-07-28, where
// every request carries its version, and the handshake-based ones before.
var versions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}

// modern is the first version without the handshake.
const modern = "2026-07-28"

// Server is the demo ledger.
type Server struct {
	// APIKey is the bearer token every request must carry.
	APIKey string
	// SSE answers requests as event streams instead of plain JSON, as
	// many servers do.
	SSE bool
	// PageSize, when set, has tools/list answer that many tools a page,
	// with a cursor to the next page.
	PageSize int
	Log      *slog.Logger

	mu      sync.Mutex
	entries []Entry
	seen    []Seen
}

// Entry is one posted ledger entry.
type Entry struct {
	ID        string  `json:"id"`
	AccountID string  `json:"account_id"`
	Amount    float64 `json:"amount"`
	Memo      string  `json:"memo"`
}

// Seen is what one request carried, for the demo's log and for tests.
type Seen struct {
	Method     string
	Credential string // "api key", "other bearer", "none"
	Tool       string
	// Version is the MCP-Protocol-Version header, if any.
	Version string
	// Extra holds headers the gateway should never forward, so a test can
	// confirm they were stripped. Empty when none arrived.
	Extra map[string]string
}

// Entries returns what was posted so far.
func (s *Server) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Entry(nil), s.entries...)
}

// Requests returns what each request carried.
func (s *Server) Requests() []Seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Seen(nil), s.seen...)
}

type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

var tools = []map[string]any{
	{
		"name": "list_unmatched", "title": "Unmatched payments",
		"description": "Payments of one day that no invoice matches yet.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"day": map[string]any{"type": "string"}}, "required": []string{"day"}},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name": "post_entry", "title": "Post a ledger entry",
		"description": "Posts one entry to an account.",
		// A 2026-07-28 client mirrors the account in Mcp-Param-Account.
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"account_id": map[string]any{"type": "string", "x-mcp-header": "Account"}, "amount": map[string]any{"type": "number"}, "memo": map[string]any{"type": "string"}},
			"required": []string{"account_id", "amount"}},
	},
	{
		"name": "write_off", "title": "Write off a payment",
		"description": "Writes a payment off the books.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"payment_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "reason": map[string]any{"type": "string"}},
			"required": []string{"payment_id", "amount", "reason"}},
		"annotations": map[string]any{"destructiveHint": true},
	},
	{
		// Not in doorward's manifest: the gateway hides it.
		"name": "export_everything", "description": "Dumps the whole ledger.",
		"inputSchema": map[string]any{"type": "object", "additionalProperties": false},
	},
}

// ServeHTTP is the MCP endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cred := "none"
	if auth := r.Header.Get("Authorization"); auth != "" {
		if auth == "Bearer "+s.APIKey {
			cred = "api key"
		} else {
			cred = "other bearer"
		}
	}
	// Headers a gateway in front of this server should strip. If any reach
	// here, the gateway let a client header through.
	var extra map[string]string
	for _, h := range []string{"X-Forwarded-User", "Cookie", "X-Real-Ip"} {
		if v := r.Header.Get(h); v != "" {
			if extra == nil {
				extra = map[string]string{}
			}
			extra[h] = v
		}
	}
	if r.Method != http.MethodPost {
		s.note(Seen{Method: r.Method, Credential: cred})
		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			http.Error(w, "this server keeps no sessions and opens no streams", http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cred != "api key" {
		s.note(Seen{Method: "POST", Credential: cred})
		w.Header().Set("WWW-Authenticate", `Bearer realm="demo-ledger"`)
		http.Error(w, "the ledger wants its API key", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var msg rpc
	if err := json.Unmarshal(body, &msg); err != nil || msg.JSONRPC != "2.0" {
		s.respond(w, nil, nil, &rpcError{-32700, "parse error"})
		return
	}
	seen := Seen{Method: msg.Method, Credential: cred, Extra: extra, Version: r.Header.Get("MCP-Protocol-Version")}
	isModern := seen.Version >= modern
	if len(msg.ID) == 0 { // a notification or a response: accepted
		s.note(seen)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		// The handshake belongs to the versions before 2026-07-28.
		v := versions[1]
		for _, known := range versions[1:] {
			if known == p.ProtocolVersion {
				v = known
			}
		}
		w.Header().Set("MCP-Session-Id", randomID())
		s.note(seen)
		s.respond(w, msg.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "demo-ledger", "version": "0.1"},
		}, nil)
	case "server/discover":
		s.note(seen)
		s.respond(w, msg.ID, complete(map[string]any{
			"supportedVersions": versions,
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"_meta":             map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "demo-ledger", "version": "0.1"}},
			"ttlMs":             300000, "cacheScope": "public",
		}), nil)
	case "ping":
		s.note(seen)
		s.respond(w, msg.ID, map[string]any{}, nil)
	case "tools/list":
		s.note(seen)
		page, rerr := s.toolPage(msg.Params)
		if page != nil && isModern {
			page["ttlMs"], page["cacheScope"] = 300000, "public"
			page = complete(page)
		}
		s.respond(w, msg.ID, page, rerr)
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &p); err != nil {
			s.respond(w, msg.ID, nil, &rpcError{-32602, "invalid params"})
			return
		}
		seen.Tool = p.Name
		s.note(seen)
		result, rerr := s.call(p.Name, p.Arguments)
		if result != nil && isModern {
			result = complete(result)
		}
		s.respond(w, msg.ID, result, rerr)
	default:
		s.note(seen)
		s.respond(w, msg.ID, nil, &rpcError{-32601, "method not found: " + msg.Method})
	}
}

// complete marks a result as final, as every result is from 2026-07-28.
func complete(result map[string]any) map[string]any {
	result["resultType"] = "complete"
	return result
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolPage is one page of the tool list: the whole list, or PageSize tools
// from the cursor, which is the index of the page's first tool.
func (s *Server) toolPage(params json.RawMessage) (map[string]any, *rpcError) {
	if s.PageSize <= 0 {
		return map[string]any{"tools": tools}, nil
	}
	var p struct {
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(params, &p)
	start := 0
	if p.Cursor != "" {
		n, err := strconv.Atoi(p.Cursor)
		if err != nil || n <= 0 || n >= len(tools) {
			return nil, &rpcError{-32602, "invalid cursor"}
		}
		start = n
	}
	end := min(start+s.PageSize, len(tools))
	page := map[string]any{"tools": tools[start:end]}
	if end < len(tools) {
		page["nextCursor"] = strconv.Itoa(end)
	}
	return page, nil
}

func (s *Server) call(name string, args map[string]any) (map[string]any, *rpcError) {
	text := func(format string, a ...any) map[string]any {
		t := fmt.Sprintf(format, a...)
		return map[string]any{"content": []map[string]any{{"type": "text", "text": t}}}
	}
	switch name {
	case "list_unmatched":
		return map[string]any{
			"content":           []map[string]any{{"type": "text", "text": `[{"payment_id":"pmt_8K2","amount":240.5,"currency":"EUR"}]`}},
			"structuredContent": map[string]any{"payments": []map[string]any{{"payment_id": "pmt_8K2", "amount": 240.5, "currency": "EUR"}}},
		}, nil
	case "post_entry":
		amount, _ := args["amount"].(float64)
		account, _ := args["account_id"].(string)
		memo, _ := args["memo"].(string)
		e := Entry{ID: "ent_" + randomID()[:8], AccountID: account, Amount: amount, Memo: memo}
		s.mu.Lock()
		s.entries = append(s.entries, e)
		s.mu.Unlock()
		return text("posted %s: %.2f to %s", e.ID, e.Amount, e.AccountID), nil
	case "write_off":
		amount, _ := args["amount"].(float64)
		payment, _ := args["payment_id"].(string)
		return text("wrote off %.2f of %s", amount, payment), nil
	case "export_everything":
		return text("the whole ledger: %d entries", len(s.Entries())), nil
	}
	return nil, &rpcError{-32602, "Unknown tool: " + name}
}

// respond writes one JSON-RPC response, as JSON or as an SSE stream.
func (s *Server) respond(w http.ResponseWriter, id json.RawMessage, result any, rerr *rpcError) {
	msg := map[string]any{"jsonrpc": "2.0"}
	if id != nil {
		msg["id"] = id
	}
	if rerr != nil {
		msg["error"] = rerr
	} else {
		msg["result"] = result
	}
	body, _ := json.Marshal(msg)
	if !s.SSE {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	// A priming event, then the response, as the transport describes.
	_, _ = fmt.Fprintf(w, "id: %s\ndata: \n\n", randomID()[:8])
	_, _ = fmt.Fprintf(w, "event: message\nid: %s\ndata: %s\n\n", randomID()[:8], body)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) note(seen Seen) {
	s.mu.Lock()
	s.seen = append(s.seen, seen)
	s.mu.Unlock()
	if s.Log != nil {
		s.Log.Info("demo-ledger request", "method", seen.Method, "tool", seen.Tool, "credential", seen.Credential)
	}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
