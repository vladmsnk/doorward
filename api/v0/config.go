package v0

// Kinds of the configuration documents, as their kind field spells them.
const (
	KindBoundary = "Boundary"
	KindTaskType = "TaskType"
	KindManifest = "Manifest"
)

// Boundary is one agent: how it proves who it is, who owns it, and the most
// it may ever be granted. Metadata.Name is the agent's name.
type Boundary struct {
	TypeMeta
	Metadata ObjectMeta   `json:"metadata"`
	Spec     BoundarySpec `json:"spec"`
}

type BoundarySpec struct {
	Owner Owner `json:"owner"`
	// Identities are the ways the agent may authenticate; the STS issues a
	// grant only to a caller that presents one of them.
	Identities []AgentIdentity `json:"identities"`
	// TaskTypes the agent may be started for.
	TaskTypes []string `json:"task_types"`
	// MaxSensitivity is the highest tier of operation the agent may be granted.
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	// MaxTTL caps the lifetime of every grant to the agent.
	MaxTTL      Duration     `json:"max_ttl"`
	Permissions []Permission `json:"permissions"`
	// Limits cap the task type's limits of the same name.
	Limits     []Limit     `json:"limits,omitempty"`
	Delegation *Delegation `json:"delegation,omitempty"`
}

// IdentityType is how an agent authenticates.
type IdentityType string

const (
	// IdentityRegistration is the box's own one-time token at deploy, with the
	// key made in the sidecar.
	IdentityRegistration IdentityType = "registration"
	// IdentityOAuthClient is a client at an identity provider.
	IdentityOAuthClient IdentityType = "oauth_client"
	// IdentityJWT is a workload token with an issuer and a subject: a
	// Kubernetes service account, a cloud workload identity, a JWT-SVID.
	IdentityJWT IdentityType = "jwt"
	// IdentitySPIFFE is a SPIFFE ID presented as an X.509 certificate.
	IdentitySPIFFE IdentityType = "spiffe"
)

// AgentIdentity is one way an agent may authenticate. Which fields are set
// depends on Type.
type AgentIdentity struct {
	Type     IdentityType `json:"type"`
	Issuer   string       `json:"issuer,omitempty"`
	ClientID string       `json:"client_id,omitempty"`
	Subject  string       `json:"subject,omitempty"`
	// ID is a SPIFFE ID.
	ID string `json:"id,omitempty"`
}

// TaskType is a kind of task an application may start. The application
// sends only the type and the object's ID; the scope comes from here.
type TaskType struct {
	TypeMeta
	Metadata ObjectMeta   `json:"metadata"`
	Spec     TaskTypeSpec `json:"spec"`
}

type TaskTypeSpec struct {
	Object TaskObjectSpec `json:"object"`
	// Initiators are the applications allowed to start the task.
	Initiators []string `json:"initiators"`
	// TTL is the lifetime of the root grant, capped by each agent's MaxTTL.
	TTL         Duration     `json:"ttl"`
	Permissions []Permission `json:"permissions"`
	Limits      []Limit      `json:"limits,omitempty"`
	Delegation  *Delegation  `json:"delegation,omitempty"`
	// Approval says who approves the task's calls that need approval.
	Approval *ApprovalPolicy `json:"approval,omitempty"`
}

// ApprovalPolicy says who approves, how many of them, and how fresh their
// sign-in must be. Approvers are distinct people and never the task's user.
type ApprovalPolicy struct {
	// Required is the number of distinct approvals; a critical operation
	// always needs at least 2.
	Required  int       `json:"required"`
	Approvers Approvers `json:"approvers"`
	// MaxAuthAge is how recently an approver must have signed in.
	MaxAuthAge Duration `json:"max_auth_age"`
	// ACRValues are the sign-in strengths an approver must have (OIDC acr).
	ACRValues    []string `json:"acr_values,omitempty"`
	ExpiresAfter Duration `json:"expires_after"`
}

// Approvers are the members of these groups at this identity provider.
type Approvers struct {
	Issuer string   `json:"issuer"`
	Groups []string `json:"groups"`
}

// TaskObjectSpec says what a task is about.
type TaskObjectSpec struct {
	Type string `json:"type"`
	// IDPattern is an anchored regular expression the object's ID must match.
	IDPattern string `json:"id_pattern"`
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

// KindApplication is the kind of an Application document.
const KindApplication = "Application"

// Application is an application that may start tasks for its users.
// Metadata.Name is the name task types list as initiators.
type Application struct {
	TypeMeta
	Metadata ObjectMeta      `json:"metadata"`
	Spec     ApplicationSpec `json:"spec"`
}

type ApplicationSpec struct {
	Owner          Owner             `json:"owner"`
	Authentication AppAuthentication `json:"authentication"`
	Users          UserSources       `json:"users"`
}

// AuthMethod is how an application authenticates to the STS.
type AuthMethod string

const (
	// AuthPrivateKeyJWT is a JWT the application signs with its own key
	// (RFC 7523), checked against JWKSURI or JWKS.
	AuthPrivateKeyJWT AuthMethod = "private_key_jwt"
	// AuthOAuthClient is a client at an identity provider.
	AuthOAuthClient AuthMethod = "oauth_client"
)

// AppAuthentication says how an application proves who it is. Which fields
// are set depends on Method.
type AppAuthentication struct {
	Method   AuthMethod `json:"method"`
	JWKSURI  string     `json:"jwks_uri,omitempty"`
	JWKS     *JWKSet    `json:"jwks,omitempty"`
	Issuer   string     `json:"issuer,omitempty"`
	ClientID string     `json:"client_id,omitempty"`
}

// JWKSet is a JSON Web Key Set (RFC 7517). Keys are kept as parsed JSON;
// the STS reads them with a JOSE library.
type JWKSet struct {
	Keys []map[string]any `json:"keys"`
}

// UserSources says whose word the STS takes for who the user is.
type UserSources struct {
	// IdPs are identity providers whose ID tokens the application may pass.
	IdPs []string `json:"idps,omitempty"`
	// SelfAsserted lets the application's own signed statement name the
	// user, for companies whose identity provider issues no usable tokens.
	SelfAsserted bool `json:"self_asserted,omitempty"`
}
