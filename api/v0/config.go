package v0

// Kinds of the configuration documents, as their kind field spells them.
const (
	KindManifest = "Manifest"
	KindAgent    = "Agent"
	KindMandate  = "Mandate"
)

// Agent is one agent the box knows: how it presented itself, how it proves
// who it is, who answers for it, and the most it may ever be granted.
// Metadata.Name is the agent's name.
type Agent struct {
	TypeMeta
	Metadata ObjectMeta `json:"metadata"`
	Spec     AgentSpec  `json:"spec"`
}

// AgentStatus is where an agent stands with the box.
type AgentStatus string

const (
	// AgentUnverified registered itself and has not been reviewed: it may
	// request only open mandates, under the ceiling every unverified agent
	// gets.
	AgentUnverified AgentStatus = "unverified"
	// AgentVerified was reviewed by an administrator, who named its owner.
	AgentVerified AgentStatus = "verified"
	// AgentSuspended has every call refused.
	AgentSuspended AgentStatus = "suspended"
)

type AgentSpec struct {
	Status AgentStatus `json:"status"`
	// Publisher is who the agent says made it, from its registration.
	Publisher *Publisher `json:"publisher,omitempty"`
	// Owner is the team that answers for the agent; set once it is verified.
	Owner *Owner `json:"owner,omitempty"`
	// Identities are the ways the agent may authenticate; the STS issues a
	// grant only to a caller that presents one of them.
	Identities []AgentIdentity `json:"identities"`
	// Mandates the agent may request beyond the open ones.
	Mandates []string `json:"mandates,omitempty"`
	// MaxSensitivity is the highest tier of operation the agent may be granted.
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	// MaxTTL caps the lifetime of every grant to the agent.
	MaxTTL Duration `json:"max_ttl"`
	// Permissions are the most the agent may ever call.
	Permissions []Permission `json:"permissions"`
	// Limits cap a mandate's limits of the same name.
	Limits []Limit `json:"limits,omitempty"`
}

// Publisher is who an agent says made it.
type Publisher struct {
	Name string `json:"name"`
	URI  string `json:"uri,omitempty"`
}

// IdentityType is how an agent authenticates.
type IdentityType string

const (
	// IdentityRegistration is the box's own one-time token at deploy, with the
	// key made in the sidecar.
	IdentityRegistration IdentityType = "registration"
	// IdentityJWT is a token with an issuer and a subject: a Kubernetes
	// service account, a cloud workload identity, a JWT-SVID.
	IdentityJWT IdentityType = "jwt"
	// IdentityOAuthClient is an OAuth client of the box itself, as any MCP
	// client is. With keys it authenticates by private_key_jwt; without, it
	// is a public client bound to its DPoP key alone.
	IdentityOAuthClient IdentityType = "oauth_client"
)

// AgentIdentity is one way an agent may authenticate. Which fields are set
// depends on Type.
type AgentIdentity struct {
	Type         IdentityType `json:"type"`
	Issuer       string       `json:"issuer,omitempty"`
	Subject      string       `json:"subject,omitempty"`
	ClientID     string       `json:"client_id,omitempty"`
	JWKSURI      string       `json:"jwks_uri,omitempty"`
	JWKS         *JWKSet      `json:"jwks,omitempty"`
	RedirectURIs []string     `json:"redirect_uris,omitempty"`
}

// JWKSet is a JSON Web Key Set (RFC 7517). Keys are kept as parsed JSON;
// the STS reads them with a JOSE library.
type JWKSet struct {
	Keys []map[string]any `json:"keys"`
}

// Mandate is what an agent may do for a principal, and on what terms.
type Mandate struct {
	TypeMeta
	Metadata ObjectMeta  `json:"metadata"`
	Spec     MandateSpec `json:"spec"`
}

// Principal says whom an agent acts for under a mandate.
type Principal_ string

const (
	// PrincipalUser is a person who consented; they are the grant's sub.
	PrincipalUser Principal_ = "user"
	// PrincipalService is the agent's owner; the agent is its own sub.
	PrincipalService Principal_ = "service"
)

type MandateSpec struct {
	Principal Principal_ `json:"principal"`
	// Open lets any registered agent request the mandate, unverified ones
	// included.
	Open bool `json:"open,omitempty"`
	// Consent holds the terms a user agrees to; user mandates only.
	Consent *ConsentTerms `json:"consent,omitempty"`
	// TTL is the lifetime of one grant, capped by the agent's MaxTTL.
	TTL         Duration     `json:"ttl"`
	Permissions []Permission `json:"permissions"`
	Limits      []Limit      `json:"limits,omitempty"`
	// Approval says who approves the mandate's critical calls. Without it,
	// a critical call is refused.
	Approval *ApprovalPolicy `json:"approval,omitempty"`
}

// ConsentTerms is what the consent page shows and how long consent stands.
type ConsentTerms struct {
	Text        string   `json:"text"`
	MaxDuration Duration `json:"max_duration"`
}

// ApprovalPolicy says who approves critical calls, how many of them, and how
// fresh their sign-in must be.
type ApprovalPolicy struct {
	// Required is the number of distinct approvals: 1 on a user route, at
	// least 2 on a group route.
	Required  int       `json:"required"`
	Approvers Approvers `json:"approvers"`
	// MaxAuthAge is how recently an approver must have signed in.
	MaxAuthAge   Duration `json:"max_auth_age"`
	ExpiresAfter Duration `json:"expires_after"`
}

// ApproverKind is who may approve.
type ApproverKind string

const (
	// ApproverUser is the user the agent acts for.
	ApproverUser ApproverKind = "user"
	// ApproverGroup is any member of Groups at Issuer.
	ApproverGroup ApproverKind = "group"
)

// Approvers is an approval route. Issuer and Groups are set for
// ApproverGroup only.
type Approvers struct {
	Kind   ApproverKind `json:"kind"`
	Issuer string       `json:"issuer,omitempty"`
	Groups []string     `json:"groups,omitempty"`
}

// Manifest lists the operations one resource exposes through the box's points
// of enforcement, with their tiers and constrainable arguments.
type Manifest struct {
	TypeMeta
	Metadata ObjectMeta   `json:"metadata"`
	Spec     ManifestSpec `json:"spec"`
}

// Protocol is how a resource is called.
type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolMCP  Protocol = "mcp"
)

type ManifestSpec struct {
	Audience   string      `json:"audience"`
	Protocol   Protocol    `json:"protocol"`
	Operations []Operation `json:"operations"`
}

// Operation is one MCP tool or one HTTP route.
type Operation struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Sensitivity Sensitivity `json:"sensitivity"`
	// HTTP is set exactly when the manifest's protocol is http.
	HTTP *HTTPRoute `json:"http,omitempty"`
	// Params are the arguments constraints may refer to, keyed by JSON Pointer.
	Params map[string]Param `json:"params,omitempty"`
}

// HTTPRoute is where an HTTP operation lives.
type HTTPRoute struct {
	Method string `json:"method"`
	// Path is a template; {name} segments are path parameters.
	Path string `json:"path"`
}

// ParamType is the JSON type of an argument.
type ParamType string

const (
	ParamString  ParamType = "string"
	ParamNumber  ParamType = "number"
	ParamInteger ParamType = "integer"
	ParamBoolean ParamType = "boolean"
)

// ParamIn is where an HTTP argument comes from.
type ParamIn string

const (
	ParamInPath  ParamIn = "path"
	ParamInQuery ParamIn = "query"
	ParamInBody  ParamIn = "body"
)

// Param describes one argument.
type Param struct {
	Type ParamType `json:"type"`
	// In is set for HTTP operations only.
	In ParamIn `json:"in,omitempty"`
}
