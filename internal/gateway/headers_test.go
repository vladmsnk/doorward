package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCheckHeaders(t *testing.T) {
	modern := func(extra ...string) http.Header {
		h := http.Header{"Mcp-Protocol-Version": {"2026-07-28"}}
		for i := 0; i+1 < len(extra); i += 2 {
			h.Add(extra[i], extra[i+1])
		}
		return h
	}
	body := `{"name":"post_entry","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`
	for _, tc := range []struct {
		name   string
		h      http.Header
		method string
		params string
		modern bool
		want   string // "" for no error
	}{
		{"modern, all agree", modern("Mcp-Method", "tools/call", "Mcp-Name", "post_entry"), "tools/call", body, true, ""},
		{"modern, base64 name", modern("Mcp-Method", "tools/call", "Mcp-Name", "=?base64?cG9zdF9lbnRyeQ==?="), "tools/call", body, true, ""},
		{"modern, a list", modern("Mcp-Method", "tools/list"), "tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`, true, ""},
		{"older, no headers", http.Header{"Mcp-Protocol-Version": {"2025-11-25"}}, "tools/call", `{"name":"post_entry"}`, false, ""},
		{"no version at all", http.Header{}, "tools/call", `{"name":"post_entry"}`, false, ""},
		{"a notification", modern("Mcp-Method", "notifications/cancelled"), "notifications/cancelled", `{}`, true, ""},
		{"a name twice", modern("Mcp-Method", "tools/call", "Mcp-Name", "post_entry", "Mcp-Name", "write_off"), "tools/call", body, true, "given 2 times"},
		{"bad base64", modern("Mcp-Method", "tools/call", "Mcp-Name", "=?base64?***?="), "tools/call", body, true, "not base64"},
		{"a name for a list", modern("Mcp-Method", "tools/list", "Mcp-Name", "post_entry"), "tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`, true, "names nothing"},
		{"a name without one in the body", modern("Mcp-Method", "tools/call", "Mcp-Name", "post_entry"), "tools/call", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`, true, `does not match body value ""`},
		{"the body's version not a string", modern("Mcp-Method", "tools/list"), "tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":20260728}}`, true, "not a string"},
		{"a later revision is modern too", http.Header{"Mcp-Protocol-Version": {"2027-03-01"}}, "tools/list", `{}`, true, "Mcp-Method header is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkHeaders(tc.h, rpcMessage{JSONRPC: "2.0", Method: tc.method, Params: json.RawMessage(tc.params)})
			switch {
			case got != tc.modern:
				t.Errorf("modern = %v", got)
			case tc.want == "" && err != nil:
				t.Errorf("err = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
