package v0

// Grant is the claims set of an agent grant: a short-lived JWT for one task,
// bound to the sidecar's key and placed in the task's grant tree.
type Grant struct {
	Issuer string `json:"iss"`
	// Subject is the user on whose behalf the agent acts.
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	Expiry    int64    `json:"exp"`
	ID        string   `json:"jti"`
	// Actor is the agent acting now; earlier agents of a delegation chain are
	// nested inside it (RFC 8693 §4.1).
	Actor                Actor                 `json:"act"`
	Confirmation         *Confirmation         `json:"cnf,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	Task                 Task                  `json:"task"`
	// Root is the jti of the task's root grant; revoking it revokes the tree.
	Root string `json:"root"`
	// Parent is the jti of the grant this one was narrowed from. It is set
	// exactly when Depth > 0.
	Parent string `json:"parent,omitempty"`
	Depth  int    `json:"depth"`
	// Flow binds the grant to one delegation flow, so two chains cannot be
	// spliced together.
	Flow   string       `json:"flow"`
	Limits []Limit      `json:"limits,omitempty"`
	Status *StatusClaim `json:"status,omitempty"`
}

// Actor is an act claim (RFC 8693 §4.1).
type Actor struct {
	Subject string `json:"sub"`
	// Issuer is the actor's trust domain when it is not this box's own.
	Issuer string `json:"iss,omitempty"`
	Actor  *Actor `json:"act,omitempty"`
}

// Confirmation binds the grant to a key (RFC 9449 §6.1).
type Confirmation struct {
	// JKT is the key's JWK SHA-256 thumbprint (RFC 7638), base64url.
	JKT string `json:"jkt"`
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
