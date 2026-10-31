package v0

// GrantJWTType is the typ header of a grant: a JWT access token (RFC 9068).
const GrantJWTType = "at+jwt"

// Grant is the claims set of an agent grant: a short-lived JWT access token
// for one task, bound to the sidecar's key and placed in the task's grant
// tree.
type Grant struct {
	Issuer string `json:"iss"`
	// Subject is the user on whose behalf the agent acts, unique across every
	// identity provider the box trusts.
	Subject string `json:"sub"`
	// SubjectID is where the user's identity came from.
	SubjectID SubjectID `json:"sub_id"`
	// Audience is exactly the locations of AuthorizationDetails.
	Audience []string `json:"aud"`
	// ClientID is the OAuth client the grant was issued to: the agent.
	ClientID string `json:"client_id"`
	// Scope repeats operation names as OAuth scopes, for resource servers
	// that read only scope.
	Scope     string `json:"scope,omitempty"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf,omitempty"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`
	// AuthTime, ACR and AMR say when and how the user signed in, from the
	// identity token the task started with.
	AuthTime int64    `json:"auth_time,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	// SessionID is the user's session at the identity provider; ending it
	// revokes the task's grant tree.
	SessionID string `json:"sid,omitempty"`
	// Actor is the agent acting now; earlier agents of a delegation chain are
	// nested inside it (RFC 8693 §4.1).
	Actor                Actor                 `json:"act"`
	Confirmation         *Confirmation         `json:"cnf,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	Task                 Task                  `json:"task"`
	// Root is the jti of the task's root grant; the root names itself.
	// Revoking it revokes the tree, and a chain from another task cannot be
	// spliced in because its root differs.
	Root string `json:"root"`
	// Parent is the jti of the grant this one was narrowed from. It is set
	// exactly when Depth > 0.
	Parent string       `json:"parent,omitempty"`
	Depth  int          `json:"depth"`
	Limits []Limit      `json:"limits,omitempty"`
	Status *StatusClaim `json:"status,omitempty"`
}

// Actor is an act claim (RFC 8693 §4.1).
type Actor struct {
	// Subject is the agent's name in this box, or, when Issuer is set, the
	// identifier the agent's own trust domain gives it.
	Subject string `json:"sub"`
	// Issuer is the actor's trust domain when it is not this box's own.
	Issuer string `json:"iss,omitempty"`
	Actor  *Actor `json:"act,omitempty"`
}

// Confirmation binds the grant to a DPoP key (RFC 9449) or to a TLS client
// certificate (RFC 8705). Exactly one field is set.
type Confirmation struct {
	// JKT is the DPoP key's JWK SHA-256 thumbprint (RFC 7638), base64url.
	JKT string `json:"jkt,omitempty"`
	// X5TS256 is the client certificate's SHA-256 thumbprint, base64url.
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// Task is the task a grant serves, as the initiating application declared it.
type Task struct {
	ID     string    `json:"id"`
	Type   string    `json:"type"`
	Object ObjectRef `json:"object"`
	// Initiator is the application that started the task.
	Initiator string `json:"initiator"`
}

// ObjectRef names the object a task is about.
type ObjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// StatusClaim says where to check a grant's revocation (Token Status List).
type StatusClaim struct {
	StatusList StatusListRef `json:"status_list"`
}

type StatusListRef struct {
	Index int64  `json:"idx"`
	URI   string `json:"uri"`
}
