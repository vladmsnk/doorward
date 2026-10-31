package v0

// ConsentStatus is whether a consent still stands.
type ConsentStatus string

const (
	ConsentActive  ConsentStatus = "active"
	ConsentExpired ConsentStatus = "expired"
	ConsentRevoked ConsentStatus = "revoked"
)

// Revoker is who ended a consent.
type Revoker string

const (
	RevokedByUser  Revoker = "user"
	RevokedByAdmin Revoker = "admin"
	RevokedByIdP   Revoker = "idp"
)

// Consent is the record of one person allowing one agent one mandate.
type Consent struct {
	ID      string    `json:"id"`
	User    SubjectID `json:"user"`
	Agent   string    `json:"agent"`
	Mandate string    `json:"mandate"`
	// MandateVersion is the digest of the mandate as the user saw it.
	MandateVersion string        `json:"mandate_version"`
	Status         ConsentStatus `json:"status"`
	GrantedAt      Timestamp     `json:"granted_at"`
	ExpiresAt      Timestamp     `json:"expires_at"`
	RevokedAt      *Timestamp    `json:"revoked_at,omitempty"`
	RevokedBy      Revoker       `json:"revoked_by,omitempty"`
	// Auth is how the user signed in to consent.
	Auth *ConsentAuth `json:"auth,omitempty"`
}

// ConsentAuth is how a user signed in to consent.
type ConsentAuth struct {
	AuthTime Timestamp `json:"auth_time"`
	ACR      string    `json:"acr,omitempty"`
	// SessionID is the user's session at the identity provider.
	SessionID string `json:"sid,omitempty"`
}

// ApprovalStatus is where an approval request stands.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

// Approval is the record of one approval request for one exact call.
type Approval struct {
	ID      string         `json:"id"`
	Created Timestamp      `json:"created"`
	Status  ApprovalStatus `json:"status"`
	// Closed is set once the request is no longer pending.
	Closed  *Timestamp `json:"closed,omitempty"`
	Mandate string     `json:"mandate"`
	// Consent is the consent the grant rests on, for a user mandate.
	Consent string `json:"consent,omitempty"`
	// Grant is the grant the call was made under.
	Grant string `json:"grant"`
	Agent string `json:"agent"`
	// User is the user the agent acts for: the only voter on a user route,
	// never a voter on a group route.
	User *SubjectID `json:"user,omitempty"`
	// Route is who was asked, from the mandate.
	Route Approvers `json:"route"`
	// Action is the call in canonical form, as the approvers saw it.
	Action        ApprovedAction `json:"action"`
	ActionHash    string         `json:"action_hash"`
	PolicyVersion string         `json:"policy_version"`
	Required      int            `json:"required"`
	// Votes lists every vote cast, in order. It is never nil.
	Votes []Vote `json:"votes"`
	// SingleUseGrant is the grant issued once the request was approved.
	SingleUseGrant string `json:"single_use_grant,omitempty"`
}

// ApprovedAction is a call as approvers see it.
type ApprovedAction struct {
	Name      string         `json:"name"`
	Location  string         `json:"location"`
	Arguments map[string]any `json:"arguments"`
}

// Verdict is one approver's answer.
type Verdict string

const (
	VerdictApprove Verdict = "approve"
	VerdictReject  Verdict = "reject"
)

// Vote is one approver's answer and how they signed in to give it.
type Vote struct {
	Approver SubjectID `json:"approver"`
	Verdict  Verdict   `json:"verdict"`
	Time     Timestamp `json:"time"`
	AuthTime Timestamp `json:"auth_time"`
	ACR      string    `json:"acr,omitempty"`
}
