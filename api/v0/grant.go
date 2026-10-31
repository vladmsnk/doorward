package v0

// GrantJWTType is the typ header of a grant: a JWT access token (RFC 9068).
const GrantJWTType = "at+jwt"

// Grant is the claims set of an agent grant: a short-lived JWT access token
// for one task, bound to the sidecar's key. For a user task Subject is the
// user and Actor the agent; for a service task the agent is both, so Subject
// equals ClientID.
type Grant struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	// SubjectID is where the user's identity came from. It is set exactly
	// when Subject is a user.
	SubjectID *SubjectID `json:"sub_id,omitempty"`
	// Audience is exactly the locations of AuthorizationDetails.
	Audience []string `json:"aud"`
	// ClientID is the OAuth client the grant was issued to: the agent.
	ClientID             string                `json:"client_id"`
	IssuedAt             int64                 `json:"iat"`
	Expiry               int64                 `json:"exp"`
	ID                   string                `json:"jti"`
	Actor                Actor                 `json:"act"`
	Confirmation         *Confirmation_        `json:"cnf,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	Task                 Task                  `json:"task"`
	Limits               []Limit               `json:"limits,omitempty"`
	Status               *StatusClaim          `json:"status,omitempty"`
}

// Actor is the act claim: the agent (RFC 8693 §4.1).
type Actor struct {
	Subject string `json:"sub"`
}

// Confirmation_ is the cnf claim: the DPoP key the grant is bound to
// (RFC 9449 §6.1). The trailing underscore keeps it apart from the
// Confirmation start policy.
type Confirmation_ struct {
	// JKT is the key's JWK SHA-256 thumbprint (RFC 7638), base64url.
	JKT string `json:"jkt"`
}

// Task is the task a grant serves, as it was started.
type Task struct {
	ID     string    `json:"id"`
	Type   string    `json:"type"`
	Object ObjectRef `json:"object"`
	// Initiator is the application that started a user task.
	Initiator string    `json:"initiator,omitempty"`
	Started   TaskStart `json:"started"`
}

// TaskStart says how a task began.
type TaskStart struct {
	Trigger Trigger `json:"trigger"`
	// ConfirmedAt is when the user confirmed this exact task.
	ConfirmedAt int64 `json:"confirmed_at,omitempty"`
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
