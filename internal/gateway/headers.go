package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/core"
)

// From revision 2026-07-28 on, a Streamable HTTP request mirrors parts of
// its body into headers, so that intermediaries can route on them:
// MCP-Protocol-Version the version in the body's _meta, Mcp-Method the
// method, Mcp-Name the tool's name. The gateway decides on the body and
// forwards the headers, so a header that says something else is the same
// parser differential as an ambiguous body: one reading here, another
// wherever the header is read. Every server that reads the body must
// refuse such a request, and so does the gateway.

// modernVersion is the first revision whose requests carry their own
// protocol version and mirror the body in headers.
const modernVersion = "2026-07-28"

// metaVersion is the _meta key a modern request names its version under.
const metaVersion = "io.modelcontextprotocol/protocolVersion"

// codeHeaderMismatch is the JSON-RPC error for headers that do not match
// the body, or required ones that are missing.
const codeHeaderMismatch = -32020

// named are the methods whose params name what they act on, and where.
var named = map[string]string{"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

// checkHeaders compares the mirrored headers with the body and reports
// whether the request is of a modern revision. A modern request must carry
// them; an older one may, and when it does they must agree too, since the
// gateway forwards them.
func checkHeaders(h http.Header, msg rpcMessage) (modern bool, err error) {
	var params struct {
		Name *string                    `json:"name"`
		URI  *string                    `json:"uri"`
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(msg.Params) > 0 {
		_ = json.Unmarshal(msg.Params, &params)
	}
	header := func(name string) (string, bool, error) {
		values := h.Values(name)
		switch len(values) {
		case 0:
			return "", false, nil
		case 1:
			return values[0], true, nil
		}
		return "", false, fmt.Errorf("the %s header is given %d times", name, len(values))
	}

	version, hasVersion, err := header("MCP-Protocol-Version")
	if err != nil {
		return false, err
	}
	modern = hasVersion && version >= modernVersion
	if raw, ok := params.Meta[metaVersion]; ok {
		var inBody string
		if json.Unmarshal(raw, &inBody) != nil {
			return modern, fmt.Errorf("_meta %s is not a string", metaVersion)
		}
		switch {
		case !hasVersion:
			return inBody >= modernVersion, fmt.Errorf("the MCP-Protocol-Version header is missing; the body names %s", quote(inBody))
		case version != inBody:
			return modern, fmt.Errorf("MCP-Protocol-Version header value %s does not match body value %s", quote(version), quote(inBody))
		}
	}

	method, hasMethod, err := header("Mcp-Method")
	switch {
	case err != nil:
		return modern, err
	case hasMethod && method != msg.Method:
		return modern, fmt.Errorf("Mcp-Method header value %s does not match body value %s", quote(method), quote(msg.Method))
	case !hasMethod && modern && msg.Method != "":
		return modern, fmt.Errorf("the Mcp-Method header is missing; the body's method is %s", quote(msg.Method))
	}

	name, hasName, err := header("Mcp-Name")
	if err != nil {
		return modern, err
	}
	field, names := named[msg.Method]
	var inBody *string
	switch field {
	case "name":
		inBody = params.Name
	case "uri":
		inBody = params.URI
	}
	switch {
	case hasName && !names:
		return modern, fmt.Errorf("the Mcp-Name header is given for %s, which names nothing", quote(msg.Method))
	case !hasName && modern && names:
		return modern, fmt.Errorf("the Mcp-Name header is missing for %s", quote(msg.Method))
	case hasName:
		decoded, err := decodeHeader(name)
		if err != nil {
			return modern, fmt.Errorf("Mcp-Name: %w", err)
		}
		if inBody == nil || decoded != *inBody {
			body := ""
			if inBody != nil {
				body = *inBody
			}
			return modern, fmt.Errorf("Mcp-Name header value %s does not match body value %s", quote(decoded), quote(body))
		}
	}
	return modern, nil
}

// decodeHeader reads a mirrored value: as it is, or, between "=?base64?"
// and "?=", the UTF-8 text that standard base64 encodes.
func decodeHeader(v string) (string, error) {
	inner, ok := strings.CutPrefix(v, "=?base64?")
	if !ok {
		return v, nil
	}
	inner, ok = strings.CutSuffix(inner, "?=")
	if !ok {
		return v, nil
	}
	b, err := base64.StdEncoding.DecodeString(inner)
	if err != nil || !utf8.Valid(b) {
		return "", fmt.Errorf("%s is not base64 of UTF-8 text", quote(v))
	}
	return string(b), nil
}

// quote shows a value in an error, cut to a readable length.
func quote(s string) string {
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return fmt.Sprintf("%q", s)
}

// checkParamHeaders compares a tools/call's Mcp-Param-* headers with its
// arguments, through the manifest's record of which argument each header
// mirrors. A header the manifest does not declare cannot be checked, so it
// is refused rather than forwarded unchecked. Under 2026-07-28 a declared
// argument given without its header is refused too, as the revision asks
// of every server that reads the body. op is nil for a tool the manifest
// does not declare, which the decision point refuses anyway.
func checkParamHeaders(h http.Header, op *v0.Operation, args map[string]any, modern bool) error {
	if op == nil {
		return nil
	}
	declared := make(map[string]string) // header name in lower case, pointer
	for ptr, p := range op.Params {
		if p.Header != "" {
			declared[strings.ToLower(p.Header)] = ptr
		}
	}
	seen := make(map[string]bool)
	for name, values := range h {
		key, ok := strings.CutPrefix(strings.ToLower(name), "mcp-param-")
		if !ok {
			continue
		}
		ptr, ok := declared[key]
		if !ok {
			return fmt.Errorf("%s is not declared for %s in the manifest, so doorward cannot check it against the arguments", name, op.Name)
		}
		if len(values) != 1 {
			return fmt.Errorf("the %s header is given %d times", name, len(values))
		}
		got, err := decodeHeader(values[0])
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		want, present := core.Lookup(args, ptr)
		if !present || want == nil {
			return fmt.Errorf("%s is given, but the arguments have no %s", name, ptr)
		}
		if !sameValue(got, want, op.Params[ptr].Type) {
			return fmt.Errorf("%s header value %s does not match argument %s", name, quote(got), ptr)
		}
		seen[key] = true
	}
	if modern {
		for _, key := range slices.Sorted(maps.Keys(declared)) {
			ptr := declared[key]
			if v, present := core.Lookup(args, ptr); present && v != nil && !seen[key] {
				return fmt.Errorf("the Mcp-Param-%s header is missing; the arguments give %s", op.Params[ptr].Header, ptr)
			}
		}
	}
	return nil
}

// sameValue compares a header's text with the argument it mirrors, as the
// transport writes one: a string as it is, an integer in decimal (compared
// as a number), a boolean as true or false.
func sameValue(header string, arg any, t v0.ParamType) bool {
	switch t {
	case v0.ParamString:
		s, ok := arg.(string)
		return ok && s == header
	case v0.ParamInteger:
		n, ok := arg.(float64)
		f, err := strconv.ParseFloat(header, 64)
		return ok && err == nil && !math.IsInf(f, 0) && f == n
	case v0.ParamBoolean:
		b, ok := arg.(bool)
		return ok && header == strconv.FormatBool(b)
	}
	return false
}
