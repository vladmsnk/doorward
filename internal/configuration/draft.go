package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/mcp"
)

// Drafting a manifest from an MCP server's tool list (C2). A tool's name
// becomes an operation's, the scalar properties of its input schema become
// params, and its annotations suggest a tier. The annotations are the
// server's own claims, which nothing checks, so what comes out is a draft:
// merged into the manifest as it stands, keeping every tier a person set,
// and listed as changes for a person to review before applying it.

// Bounds on what is read from one tool's input schema.
const (
	maxParams = 64
	maxDepth  = 8
	maxHops   = 16
)

// operationName is the contract's pattern for an operation name, which an
// MCP tool name must match to be put under control.
var operationName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// maxDescription is the contract's bound on an operation's description,
// in characters.
const maxDescription = 1024

// Draft is a manifest drafted from a server's tools: the document, how it
// differs from the manifest it was merged into, and what a person should
// check before applying it.
type Draft struct {
	Manifest v0.Manifest `json:"document"`
	Changes  []Change    `json:"changes"`
	Notes    []Note      `json:"notes"`
}

// Kinds of change.
const (
	// ChangeAdded is a tool the server lists that the manifest did not
	// declare; Detail is the tier it was drafted with.
	ChangeAdded = "added"
	// ChangeRemoved is an operation whose tool the server no longer lists.
	ChangeRemoved = "removed"
	// ChangeParams is an argument added, removed or retyped in a tool's
	// input schema; Detail says which.
	ChangeParams = "params"
)

// Change is one difference between a draft and the manifest it was merged
// into.
type Change struct {
	Operation string `json:"operation"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail,omitempty"`
}

// Note is something about a tool the draft could not carry over, or a
// guess a person should check. Tool is empty when the tool's name is not
// one the manifest can hold; the message then quotes it.
type Note struct {
	Tool    string `json:"tool,omitempty"`
	Message string `json:"message"`
}

// DraftManifest merges a server's tools into base, the manifest as it
// stands, or one without operations for a first import:
//
//   - an operation base declares keeps its tier and description, and takes
//     its params from the tool's input schema as the server lists it now;
//   - a tool base does not declare is added, with the tier its annotations
//     suggest;
//   - an operation whose tool the server no longer lists is removed;
//   - the tools skip names are left out, as ones the manifest leaves out on
//     purpose.
//
// Everything else in base, its name, audience and upstream, stays as it is.
func DraftManifest(base v0.Manifest, tools []mcp.Tool, skip []string) Draft {
	d := Draft{Manifest: base, Changes: []Change{}, Notes: []Note{}}
	offered := map[string]v0.Operation{}
	var order []mcp.Tool
	for _, t := range tools {
		if slices.Contains(skip, t.Name) {
			continue
		}
		op, notes, ok := DraftOperation(t)
		d.Notes = append(d.Notes, notes...)
		if ok {
			offered[op.Name] = op
			order = append(order, t)
		}
	}
	var ops []v0.Operation
	declared := map[string]bool{}
	for _, was := range base.Spec.Operations {
		declared[was.Name] = true
		now, ok := offered[was.Name]
		if !ok {
			d.Changes = append(d.Changes, Change{Operation: was.Name, Kind: ChangeRemoved})
			continue
		}
		for _, detail := range paramChanges(was.Params, now.Params) {
			d.Changes = append(d.Changes, Change{Operation: was.Name, Kind: ChangeParams, Detail: detail})
		}
		if now.Sensitivity == v0.SensitivityCritical && was.Sensitivity != v0.SensitivityCritical {
			d.Notes = append(d.Notes, Note{Tool: was.Name, Message: fmt.Sprintf("the server marks it destructive; the manifest keeps it %s", was.Sensitivity)})
		}
		was.Params = now.Params
		ops = append(ops, was)
	}
	for _, t := range order {
		if declared[t.Name] {
			continue
		}
		op := offered[t.Name]
		ops = append(ops, op)
		d.Changes = append(d.Changes, Change{Operation: op.Name, Kind: ChangeAdded, Detail: string(op.Sensitivity)})
		if _, why := TierOf(t.Annotations); why != "" {
			d.Notes = append(d.Notes, Note{Tool: op.Name, Message: why})
		}
	}
	d.Manifest.Spec.Operations = ops
	return d
}

// DraftOperation drafts one tool as an operation, with the tier its
// annotations suggest. It returns false for a tool whose name the manifest
// cannot hold; the gateway hides such a tool. The notes say what of the
// tool's description and input schema could not be carried over; why the
// tier is a guess, TierOf says.
func DraftOperation(t mcp.Tool) (v0.Operation, []Note, bool) {
	if !operationName.MatchString(t.Name) {
		name := t.Name
		if len(name) > 140 {
			name = name[:140]
		}
		msg := fmt.Sprintf("tool %q is left out: an operation's name is 1 to 128 letters, digits, '_', '.' and '-', so the gateway hides the tool", name)
		return v0.Operation{}, []Note{{Message: msg}}, false
	}
	var notes []Note
	note := func(msg string) { notes = append(notes, Note{Tool: t.Name, Message: msg}) }
	tier, _ := TierOf(t.Annotations)
	desc, cut := description(t)
	if cut {
		note(fmt.Sprintf("its description is cut to %d characters", maxDescription))
	}
	params, skipped := ParamsOf(t.InputSchema)
	for _, s := range skipped {
		note(s)
	}
	return v0.Operation{Name: t.Name, Description: desc, Sensitivity: tier, Params: params}, notes, true
}

// TierOf is the tier a tool's annotations suggest, and why when the
// suggestion is a guess. readOnlyHint gives read and destructiveHint gives
// critical; anything else is write. A hint the server does not give counts
// for nothing, so a tool that does not say it only reads is never read.
func TierOf(a *mcp.Annotations) (v0.Sensitivity, string) {
	readOnly := a != nil && a.ReadOnlyHint != nil && *a.ReadOnlyHint
	destructive := a != nil && a.DestructiveHint != nil && *a.DestructiveHint
	switch {
	case readOnly && destructive:
		return v0.SensitivityCritical, "it says it only reads and that it is destructive; drafted as critical"
	case readOnly:
		return v0.SensitivityRead, ""
	case destructive:
		return v0.SensitivityCritical, ""
	case a == nil || a.DestructiveHint == nil:
		return v0.SensitivityWrite, "it does not say whether it is destructive; drafted as write, though the protocol takes such a tool to be destructive: decide whether it is critical"
	}
	return v0.SensitivityWrite, ""
}

// description is the tool's description, or its title when it has none,
// cut to the contract's length.
func description(t mcp.Tool) (string, bool) {
	s := t.Description
	if s == "" {
		s = t.Title
	}
	if s == "" && t.Annotations != nil {
		s = t.Annotations.Title
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxDescription {
		return s, false
	}
	return string([]rune(s)[:maxDescription-1]) + "…", true
}

// paramChanges lists how an operation's params differ, by pointer.
func paramChanges(was, now map[string]v0.Param) []string {
	pointers := map[string]bool{}
	for ptr := range was {
		pointers[ptr] = true
	}
	for ptr := range now {
		pointers[ptr] = true
	}
	var out []string
	for _, ptr := range slices.Sorted(maps.Keys(pointers)) {
		w, inWas := was[ptr]
		n, inNow := now[ptr]
		switch {
		case !inWas:
			out = append(out, fmt.Sprintf("%s added (%s)", ptr, n.Type))
		case !inNow:
			out = append(out, fmt.Sprintf("%s removed", ptr))
		case w.Type != n.Type:
			out = append(out, fmt.Sprintf("%s is now %s, was %s", ptr, n.Type, w.Type))
		case w.Header != n.Header && n.Header == "":
			out = append(out, fmt.Sprintf("%s is no longer mirrored in a header", ptr))
		case w.Header != n.Header:
			out = append(out, fmt.Sprintf("%s is now mirrored in Mcp-Param-%s", ptr, n.Header))
		}
	}
	return out
}

// ParamsOf finds the arguments constraints can refer to in a tool's input
// schema: every property of one scalar type (string, number, integer or
// boolean), in nested objects too, keyed by its JSON Pointer. A type given
// together with null, by an enum or a const, through a local $ref, or by
// alternatives of one type counts as that type. What cannot be a param (an
// array, a value of several types, a reference outside the schema) is left
// out, and said why.
//
// A property's x-mcp-header becomes the param's header. MCP clients drop a
// tool whose annotation breaks the protocol's rules (a name that is not a
// header token, one used twice, one on a number or a non-scalar, one not
// reachable through properties alone), so such an annotation is left out
// with a note.
func ParamsOf(raw json.RawMessage) (map[string]v0.Param, []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, []string{"its input schema is not JSON, so it has no params"}
	}
	w := &schemaWalk{root: root, params: map[string]v0.Param{}, headers: map[string]string{}}
	s, err := w.resolve(root)
	if err != nil {
		return nil, []string{fmt.Sprintf("its input schema cannot be read (%v), so it has no params", err)}
	}
	w.object(s, "", 0, direct(root))
	if len(w.params) == 0 {
		w.params = nil
	}
	return w.params, w.skipped
}

type schemaWalk struct {
	root    any
	params  map[string]v0.Param
	skipped []string
	full    bool
	// headers are the x-mcp-header names taken so far, by lower case.
	headers map[string]string
}

// object walks an object schema's properties, in name order. static says
// the object was reached through properties alone, as x-mcp-header must be.
func (w *schemaWalk) object(s map[string]any, at string, depth int, static bool) {
	props, _ := s["properties"].(map[string]any)
	for _, name := range slices.Sorted(maps.Keys(props)) {
		ptr := at + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name)
		t, obj, why := w.property(props[name])
		header, annotated := mcpHeader(props[name])
		if annotated && (t == "" || t == "object") {
			w.badHeader(ptr, "it is on an argument that is not a string, an integer or a boolean")
		}
		switch {
		case t == "":
			w.skipped = append(w.skipped, fmt.Sprintf("argument %s is not a param: %s", ptr, why))
		case t == "object" && depth+1 >= maxDepth:
			w.skipped = append(w.skipped, fmt.Sprintf("argument %s is not a param: objects nest deeper than %d", ptr, maxDepth))
		case t == "object":
			w.object(obj, ptr, depth+1, static && direct(props[name]))
		case len(w.params) >= maxParams:
			if !w.full {
				w.skipped = append(w.skipped, fmt.Sprintf("it has more than %d arguments; the rest are not params", maxParams))
				w.full = true
			}
		default:
			p := v0.Param{Type: v0.ParamType(t)}
			if annotated {
				p.Header = w.header(ptr, header, t, static)
			}
			w.params[ptr] = p
		}
	}
}

// headerToken is an HTTP field name (RFC 9110 token), as x-mcp-header and
// the manifest's header must be.
var headerToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

// mcpHeader reads a property's x-mcp-header annotation, if it has one.
func mcpHeader(v any) (string, bool) {
	m, _ := v.(map[string]any)
	h, ok := m["x-mcp-header"]
	if !ok {
		return "", false
	}
	name, _ := h.(string)
	return name, true
}

// header checks one x-mcp-header and returns the name the param keeps, or
// "" when the annotation breaks the protocol's rules.
func (w *schemaWalk) header(ptr, name, typ string, static bool) string {
	switch {
	case !headerToken.MatchString(name):
		w.badHeader(ptr, fmt.Sprintf("%q is not a header name", name))
	case !static:
		w.badHeader(ptr, "the argument is not reachable through properties alone")
	case typ == "number":
		w.badHeader(ptr, "it is on a number, which may not be mirrored")
	case w.headers[strings.ToLower(name)] != "":
		w.badHeader(ptr, fmt.Sprintf("%s mirrors %s already", name, w.headers[strings.ToLower(name)]))
	default:
		w.headers[strings.ToLower(name)] = ptr
		return name
	}
	return ""
}

func (w *schemaWalk) badHeader(ptr, why string) {
	w.skipped = append(w.skipped, fmt.Sprintf("argument %s: its x-mcp-header is invalid, so MCP clients leave the tool out: %s", ptr, why))
}

// direct reports whether a schema is reached as it is, not through a
// reference or a combination of schemas.
func direct(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"$ref", "allOf", "anyOf", "oneOf"} {
		if _, has := m[k]; has {
			return false
		}
	}
	return true
}

func (w *schemaWalk) property(v any) (string, map[string]any, string) {
	s, err := w.resolve(v)
	if err != nil {
		return "", nil, err.Error()
	}
	return w.kindOf(s, 0)
}

// kindOf is what a schema allows besides null: a param type, or "object"
// with the object's schema, or nothing and why.
func (w *schemaWalk) kindOf(s map[string]any, depth int) (string, map[string]any, string) {
	if depth > maxDepth {
		return "", nil, "its alternatives nest too deep"
	}
	alts, _ := s["anyOf"].([]any)
	if alts == nil {
		alts, _ = s["oneOf"].([]any)
	}
	if alts != nil && s["type"] == nil {
		var others []map[string]any
		for _, alt := range alts {
			as, err := w.resolve(alt)
			if err != nil {
				return "", nil, err.Error()
			}
			if as["type"] != "null" {
				others = append(others, as)
			}
		}
		switch len(others) {
		case 0:
			return "", nil, "it is always null"
		case 1:
			return w.kindOf(others[0], depth+1)
		}
		var types []string
		for _, as := range others {
			t, _, why := w.kindOf(as, depth+1)
			if t == "" {
				return "", nil, why
			}
			types = append(types, t)
		}
		t, why := oneType(types)
		if t == "object" {
			return "", nil, "it is one of several objects"
		}
		return t, nil, why
	}
	var types []string
	switch t := s["type"].(type) {
	case string:
		types = []string{t}
	case []any:
		for _, v := range t {
			if name, ok := v.(string); ok {
				types = append(types, name)
			}
		}
	case nil:
		switch {
		case s["properties"] != nil:
			types = []string{"object"}
		case s["const"] != nil:
			types = valueTypes([]any{s["const"]})
		case s["enum"] != nil:
			values, _ := s["enum"].([]any)
			types = valueTypes(values)
		default:
			return "", nil, "its schema gives no type"
		}
	}
	t, why := oneType(types)
	if t == "object" {
		return t, s, ""
	}
	return t, nil, why
}

// oneType reduces a list of JSON types to the one that is not null.
func oneType(types []string) (string, string) {
	set := map[string]bool{}
	for _, t := range types {
		if t != "null" {
			set[t] = true
		}
	}
	if set["integer"] && set["number"] {
		delete(set, "integer")
	}
	switch len(set) {
	case 0:
		if len(types) > 0 {
			return "", "it is always null"
		}
		return "", "its schema gives no type"
	case 1:
		for t := range set {
			switch t {
			case "string", "number", "integer", "boolean", "object":
				return t, ""
			case "array":
				return "", "it is an array, and constraints cannot refer into one"
			}
			return "", fmt.Sprintf("its type %q is not a JSON type", t)
		}
	}
	return "", fmt.Sprintf("it takes several types (%s)", strings.Join(slices.Sorted(maps.Keys(set)), ", "))
}

// valueTypes are the JSON types of an enum's or a const's values.
func valueTypes(values []any) []string {
	var out []string
	for _, v := range values {
		switch n := v.(type) {
		case string:
			out = append(out, "string")
		case bool:
			out = append(out, "boolean")
		case float64:
			if n == float64(int64(n)) {
				out = append(out, "integer")
			} else {
				out = append(out, "number")
			}
		case nil:
			out = append(out, "null")
		default:
			out = append(out, "object")
		}
	}
	return out
}

// resolve follows a schema's local $ref, and an allOf of one schema, to the
// schema that says what the value is.
func (w *schemaWalk) resolve(v any) (map[string]any, error) {
	for range maxHops {
		s, ok := v.(map[string]any)
		if !ok {
			if b, isBool := v.(bool); isBool && b {
				return nil, errors.New("its schema accepts any value")
			}
			return nil, errors.New("its schema is not an object")
		}
		ref, hasRef := s["$ref"].(string)
		all, _ := s["allOf"].([]any)
		switch {
		case hasRef:
			target, err := w.pointer(ref)
			if err != nil {
				return nil, err
			}
			v = target
		case s["type"] == nil && s["properties"] == nil && len(all) == 1:
			v = all[0]
		default:
			return s, nil
		}
	}
	return nil, errors.New("its references go round in circles")
}

// pointer finds what a local $ref ("#/$defs/name") points to in the root
// schema.
func (w *schemaWalk) pointer(ref string) (any, error) {
	rest, ok := strings.CutPrefix(ref, "#")
	if !ok {
		return nil, fmt.Errorf("it refers outside the input schema (%q)", ref)
	}
	v := w.root
	if rest == "" {
		return v, nil
	}
	if !strings.HasPrefix(rest, "/") {
		return nil, fmt.Errorf("it refers to an anchor (%q), which is not followed", ref)
	}
	for _, token := range strings.Split(rest[1:], "/") {
		token = strings.NewReplacer("~1", "/", "~0", "~").Replace(token)
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("its reference %q points nowhere", ref)
		}
		if v, ok = m[token]; !ok {
			return nil, fmt.Errorf("its reference %q points nowhere", ref)
		}
	}
	return v, nil
}
