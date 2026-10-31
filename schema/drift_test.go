package schema_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/schema"
)

// The schemas and the Go types are written by hand, side by side. These tests
// are what keeps them one contract: they walk each Go type next to its schema
// and fail on any field the other side does not have, and on any field whose
// omitempty disagrees with the schema's required list. A required field with
// omitempty would vanish from the output at its zero value (depth 0, seq 0);
// an optional one without it would be written as an empty value the schema
// may reject.

func TestTypesMatchSchemas(t *testing.T) {
	r := newResolver(t)
	types := map[schema.Kind]reflect.Type{
		schema.Manifest: reflect.TypeFor[v0.Manifest](),
		schema.Agent:    reflect.TypeFor[v0.Agent](),
		schema.Mandate:  reflect.TypeFor[v0.Mandate](),
		schema.Consent:  reflect.TypeFor[v0.Consent](),
		schema.Grant:    reflect.TypeFor[v0.Grant](),
		schema.Decision: reflect.TypeFor[v0.Decision](),
		schema.Approval: reflect.TypeFor[v0.Approval](),
	}
	for kind, typ := range types {
		t.Run(string(kind), func(t *testing.T) {
			root := r.expand(node{file: kind.File(), schema: r.files[kind.File()]}, false)
			r.compare(t, typ, root, string(kind), map[reflect.Type]bool{})
		})
	}
}

func TestEnumsMatchSchemas(t *testing.T) {
	r := newResolver(t)
	cases := []struct {
		ref  string
		want []string
	}{
		{"common.schema.json#/$defs/sensitivity", strs(v0.SensitivityRead, v0.SensitivityWrite, v0.SensitivityCritical)},
		{"common.schema.json#/$defs/limit/properties/kind", strs(v0.LimitCount, v0.LimitSum)},
		{"common.schema.json#/$defs/limit/properties/per", strs(v0.PerGrant, v0.PerDay, v0.PerMonth)},
		{"common.schema.json#/$defs/authorizationDetail/properties/type", []string{v0.AuthorizationDetailType}},
		{"common.schema.json#/$defs/apiVersion", []string{v0.APIVersion}},
		{"common.schema.json#/$defs/subjectId/properties/format", []string{v0.SubjectIDFormat}},
		{"common.schema.json#/$defs/approvers/properties/kind", strs(v0.ApproverUser, v0.ApproverGroup)},
		{"manifest.schema.json#/properties/kind", []string{v0.KindManifest}},
		{"manifest.schema.json#/properties/spec/properties/protocol", strs(v0.ProtocolHTTP, v0.ProtocolMCP)},
		{"manifest.schema.json#/$defs/param/properties/type", strs(v0.ParamString, v0.ParamNumber, v0.ParamInteger, v0.ParamBoolean)},
		{"manifest.schema.json#/$defs/param/properties/in", strs(v0.ParamInPath, v0.ParamInQuery, v0.ParamInBody)},
		{"agent.schema.json#/properties/kind", []string{v0.KindAgent}},
		{"agent.schema.json#/properties/spec/properties/status", strs(v0.AgentUnverified, v0.AgentVerified, v0.AgentSuspended)},
		{"agent.schema.json#/$defs/identity/properties/type", strs(v0.IdentityRegistration, v0.IdentityJWT, v0.IdentityOAuthClient)},
		{"mandate.schema.json#/properties/kind", []string{v0.KindMandate}},
		{"mandate.schema.json#/properties/spec/properties/principal", strs(v0.PrincipalUser, v0.PrincipalService)},
		{"consent.schema.json#/properties/status", strs(v0.ConsentActive, v0.ConsentExpired, v0.ConsentRevoked)},
		{"consent.schema.json#/properties/revoked_by", strs(v0.RevokedByUser, v0.RevokedByAdmin, v0.RevokedByIdP)},
		{"decision.schema.json#/properties/outcome", strs(v0.OutcomeAllow, v0.OutcomeDeny, v0.OutcomeApprovalRequired)},
		{"decision.schema.json#/properties/pep/properties/kind", strs(v0.PEPGateway, v0.PEPExtAuthz, v0.PEPSDK, v0.PEPBroker)},
		{"decision.schema.json#/$defs/check/properties/name", strs(
			v0.CheckRequest, v0.CheckSignature, v0.CheckStatus, v0.CheckPoP, v0.CheckAudience, v0.CheckTime,
			v0.CheckSubset, v0.CheckSensitivity, v0.CheckPolicy, v0.CheckLimits)},
		{"decision.schema.json#/$defs/check/properties/result", strs(v0.CheckPass, v0.CheckFail, v0.CheckSkip)},
		{"decision.schema.json#/$defs/reason/properties/code/anyOf/0", strs(
			v0.ReasonRequestMalformed, v0.ReasonGrantMissing, v0.ReasonGrantMalformed, v0.ReasonGrantSignatureInvalid,
			v0.ReasonGrantExpired, v0.ReasonGrantNotYetValid, v0.ReasonGrantRevoked, v0.ReasonPoPMissing,
			v0.ReasonPoPInvalid, v0.ReasonPoPReplayed, v0.ReasonAudienceMismatch, v0.ReasonActionNotGranted,
			v0.ReasonFieldMissing, v0.ReasonConstraintViolated, v0.ReasonSensitivityExceeded,
			v0.ReasonPolicyDenied, v0.ReasonLimitExceeded, v0.ReasonTimeUntrusted, v0.ReasonInternalError)},
		{"approval.schema.json#/properties/status", strs(v0.ApprovalPending, v0.ApprovalApproved, v0.ApprovalRejected, v0.ApprovalExpired)},
		{"approval.schema.json#/$defs/vote/properties/verdict", strs(v0.VerdictApprove, v0.VerdictReject)},
	}
	for _, tc := range cases {
		file, frag, _ := strings.Cut(tc.ref, "#")
		n := r.resolve(file, "#"+frag)
		var got []string
		if c, ok := n.schema["const"].(string); ok {
			got = []string{c}
		}
		for _, e := range asSlice(n.schema["enum"]) {
			got = append(got, e.(string))
		}
		sort.Strings(got)
		want := slices.Clone(tc.want)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s\n schema: %v\n go:     %v", tc.ref, got, want)
		}
	}
}

func strs[T ~string](vs ...T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

// node is one schema object and the file its $refs resolve against.
type node struct {
	file   string
	schema map[string]any
	// conditional is set for schemas reached through if/then/else, anyOf or
	// oneOf: their properties exist, but their required lists apply only
	// sometimes.
	conditional bool
}

type resolver struct {
	files map[string]map[string]any
}

func newResolver(t *testing.T) *resolver {
	t.Helper()
	r := &resolver{files: map[string]map[string]any{}}
	for name, data := range schema.Files() {
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r.files[name] = doc
	}
	return r
}

func (r *resolver) resolve(file, ref string) node {
	target, frag, _ := strings.Cut(ref, "#")
	if target == "" {
		target = file
	}
	cur := r.files[target]
	if cur == nil {
		panic("unknown schema file " + target)
	}
	for _, part := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		if part == "" {
			continue
		}
		next := cur[part]
		if arr, ok := next.([]any); ok { // anyOf/0 and the like
			cur = map[string]any{}
			for i, item := range arr {
				cur[string(rune('0'+i))] = item
			}
			continue
		}
		cur = next.(map[string]any)
	}
	return node{file: target, schema: cur}
}

// expand returns n and every schema that applies at the same place through
// $ref, allOf, anyOf, oneOf, then and else. if and not are conditions, not
// shapes, and are left out.
func (r *resolver) expand(n node, conditional bool) []node {
	n.conditional = n.conditional || conditional
	out := []node{n}
	if ref, ok := n.schema["$ref"].(string); ok {
		out = append(out, r.expand(r.resolve(n.file, ref), n.conditional)...)
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		for _, sub := range asSlice(n.schema[key]) {
			if m, ok := sub.(map[string]any); ok {
				out = append(out, r.expand(node{file: n.file, schema: m}, n.conditional || key != "allOf")...)
			}
		}
	}
	for _, key := range []string{"then", "else"} {
		if m, ok := n.schema[key].(map[string]any); ok {
			out = append(out, r.expand(node{file: n.file, schema: m}, true)...)
		}
	}
	return out
}

// child collects the schemas for one property, the items of an array, or the
// values of a map, across every schema in set.
func (r *resolver) child(set []node, keyword, property string) []node {
	var out []node
	for _, n := range set {
		sub := n.schema[keyword]
		if property != "" {
			props, _ := sub.(map[string]any)
			sub = props[property]
		}
		if m, ok := sub.(map[string]any); ok { // a false schema forbids, it adds nothing
			out = append(out, r.expand(node{file: n.file, schema: m}, n.conditional)...)
		}
	}
	return out
}

func (r *resolver) compare(t *testing.T, typ reflect.Type, set []node, at string, onStack map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	// A type with its own JSON encoding is a leaf: its shape is the schema's
	// type and pattern, not a set of properties.
	if onStack[typ] || typ.Implements(marshaler) || reflect.PointerTo(typ).Implements(marshaler) {
		return
	}
	switch typ.Kind() {
	case reflect.Slice:
		r.compare(t, typ.Elem(), r.child(set, "items", ""), at+"[]", onStack)
		return
	case reflect.Map:
		r.compare(t, typ.Elem(), r.child(set, "additionalProperties", ""), at+"{}", onStack)
		return
	case reflect.Struct:
	default:
		return
	}
	if len(set) == 0 {
		t.Errorf("%s: Go struct %s has no schema", at, typ)
		return
	}
	onStack[typ] = true
	defer delete(onStack, typ)

	inSchema := map[string]bool{}
	required := map[string]bool{}
	for _, n := range set {
		props, _ := n.schema["properties"].(map[string]any)
		for name, sub := range props {
			if _, ok := sub.(map[string]any); ok {
				inSchema[name] = true
			}
		}
		if !n.conditional {
			for _, name := range asSlice(n.schema["required"]) {
				required[name.(string)] = true
			}
		}
	}

	fields := jsonFields(typ)
	for name, f := range fields {
		path := at + "." + name
		if !inSchema[name] {
			t.Errorf("%s: Go field %s.%s is not in the schema", path, typ.Name(), f.goName)
			continue
		}
		if required[name] && f.omitempty {
			t.Errorf("%s: required by the schema but omitempty in Go", path)
		}
		if !required[name] && !f.omitempty {
			t.Errorf("%s: optional in the schema but always written by Go", path)
		}
		r.compare(t, f.typ, r.child(set, "properties", name), path, onStack)
	}
	for name := range inSchema {
		if _, ok := fields[name]; !ok {
			t.Errorf("%s.%s: in the schema but not in Go type %s", at, name, typ.Name())
		}
	}
}

var marshaler = reflect.TypeFor[json.Marshaler]()

type field struct {
	goName    string
	typ       reflect.Type
	omitempty bool
}

// jsonFields lists the members encoding/json writes for a struct, with the
// fields of embedded structs promoted as encoding/json promotes them.
func jsonFields(typ reflect.Type) map[string]field {
	out := map[string]field{}
	for i := range typ.NumField() {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		if f.Anonymous && tag == "" {
			for k, v := range jsonFields(f.Type) {
				out[k] = v
			}
			continue
		}
		if !f.IsExported() || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		out[name] = field{goName: f.Name, typ: f.Type, omitempty: strings.Contains(opts, "omitempty")}
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
