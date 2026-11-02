package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
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

func TestCheckParamHeaders(t *testing.T) {
	op := &v0.Operation{Name: "query", Params: map[string]v0.Param{
		"/region": {Type: v0.ParamString, Header: "Region"},
		"/limit":  {Type: v0.ParamInteger, Header: "Limit"},
		"/dry":    {Type: v0.ParamBoolean, Header: "Dry-Run"},
		"/text":   {Type: v0.ParamString},
	}}
	args := map[string]any{"region": "us-west1", "limit": 42.0, "dry": true, "text": "SELECT 1"}
	all := http.Header{"Mcp-Param-Region": {"us-west1"}, "Mcp-Param-Limit": {"42"}, "Mcp-Param-Dry-Run": {"true"}}
	with := func(edit func(http.Header)) http.Header {
		h := all.Clone()
		edit(h)
		return h
	}
	for _, tc := range []struct {
		name   string
		h      http.Header
		args   map[string]any
		modern bool
		want   string
	}{
		{"all mirrored", all, args, true, ""},
		{"an integer written as a float", with(func(h http.Header) { h.Set("Mcp-Param-Limit", "42.0") }), args, true, ""},
		{"base64", with(func(h http.Header) { h.Set("Mcp-Param-Region", "=?base64?dXMtd2VzdDE=?=") }), args, true, ""},
		{"an older client sends none", http.Header{}, args, false, ""},
		{"a null argument needs no header", http.Header{}, map[string]any{"region": nil}, true, ""},
		{"a modern client leaves one out", with(func(h http.Header) { h.Del("Mcp-Param-Dry-Run") }), args, true, "Mcp-Param-Dry-Run header is missing"},
		{"another region", with(func(h http.Header) { h.Set("Mcp-Param-Region", "eu-west1") }), args, true, "does not match argument /region"},
		{"another number", with(func(h http.Header) { h.Set("Mcp-Param-Limit", "43") }), args, true, "does not match argument /limit"},
		{"a boolean in capitals", with(func(h http.Header) { h.Set("Mcp-Param-Dry-Run", "TRUE") }), args, true, "does not match argument /dry"},
		{"a header for an argument not given", http.Header{"Mcp-Param-Region": {"us-west1"}}, map[string]any{}, false, "the arguments have no /region"},
		{"a header the manifest does not declare", with(func(h http.Header) { h.Set("Mcp-Param-Text", "SELECT 1") }), args, true, "not declared for query"},
		{"a header twice", with(func(h http.Header) { h.Add("Mcp-Param-Region", "eu-west1") }), args, true, "given 2 times"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkParamHeaders(tc.h, op, tc.args, tc.modern)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("err = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
