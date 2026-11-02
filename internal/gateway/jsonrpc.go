package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// MaxBody bounds one JSON-RPC message from a client.
const MaxBody = 4 << 20

// MetaKey is the _meta key doorward sets on the tool results it writes
// itself (refusals and holds): the decision's ID, outcome and reasons.
const MetaKey = "dev.doorward/decision"

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
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
