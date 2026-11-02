package pdp

import (
	"fmt"
	"maps"
	"net/url"

	v0 "github.com/vladmsnk/doorward/api/v0"
)

// TokenKey is the request context member that carries the grant. The record
// never keeps it: once the grant is verified, its ID takes its place, under
// GrantKey.
const (
	TokenKey = "token"
	GrantKey = "grant"
)

// ResourceType is the AuthZEN resource type of a tool call.
const ResourceType = "tool_call"

// malformed says what is wrong with a request the box cannot decide on, or
// returns "".
func malformed(req v0.EvaluationRequest) string {
	if req.Resource.Type != ResourceType {
		return fmt.Sprintf("resource.type is %q; doorward decides %q resources", req.Resource.Type, ResourceType)
	}
	if u, err := url.Parse(req.Resource.ID); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Sprintf("resource.id %q is not the resource's audience URL", req.Resource.ID)
	}
	if a, ok := req.Resource.Properties["arguments"]; ok && a != nil {
		if _, isObject := a.(map[string]any); !isObject {
			return "resource.properties.arguments is not an object"
		}
	}
	if t, ok := req.Context[TokenKey]; ok {
		if _, isString := t.(string); !isString {
			return "context.token is not a string"
		}
	}
	if _, ok := req.Context[GrantKey]; ok {
		return "context.grant is set by the decision point, not sent to it"
	}
	return ""
}

// withoutToken copies a request for the record, without the grant: a
// record never holds a credential.
func withoutToken(req v0.EvaluationRequest) v0.EvaluationRequest {
	out := req
	out.Context = maps.Clone(req.Context)
	if out.Context == nil {
		out.Context = map[string]any{}
	}
	delete(out.Context, TokenKey)
	return out
}
