package v0

// GrantJWTType is the typ header of a grant: a JWT access token (RFC 9068).
const GrantJWTType = "at+jwt"

// Grant is the claims set of an agent grant: a short-lived JWT access token
// issued under a mandate, bound to the agent's key. Under a user mandate
// Subject is the user and Consent names what it rests on; under a service
// mandate the agent is its own subject, so Subject equals ClientID.
type Grant struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	// SubjectID is where the user's identity came from. It is set exactly
	// when Subject is a user.
	SubjectID *SubjectID `json:"sub_id,omitempty"`
	// Audience is exactly the locations of AuthorizationDetails.
	Audience []string `json:"aud"`
	// ClientID is the OAuth client the grant was issued to: the agent.
	ClientID     string         `json:"client_id"`
	IssuedAt     int64          `json:"iat"`
	Expiry       int64          `json:"exp"`
	ID           string         `json:"jti"`
	Actor        Actor          `json:"act"`
	Confirmation *Confirmation_ `json:"cnf,omitempty"`
	Mandate      string         `json:"mandate"`
	// Consent is set exactly when Subject is a user.
	Consent              string                `json:"consent,omitempty"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	Limits               []Limit               `json:"limits,omitempty"`
	Status               *StatusClaim          `json:"status,omitempty"`
}

// Actor is the act claim: the agent (RFC 8693 §4.1).
type Actor struct {
	Subject string `json:"sub"`
}

// Confirmation_ is the cnf claim: the DPoP key the grant is bound to
// (RFC 9449 §6.1). The trailing underscore keeps it apart from the
// consent-related names.
type Confirmation_ struct {
	// JKT is the key's JWK SHA-256 thumbprint (RFC 7638), base64url.
	JKT string `json:"jkt"`
}

// StatusClaim says where to check a grant's revocation (Token Status List).
type StatusClaim struct {
	StatusList StatusListRef `json:"status_list"`
}

type StatusListRef struct {
	Index int64  `json:"idx"`
	URI   string `json:"uri"`
}
