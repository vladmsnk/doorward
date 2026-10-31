package v0

// URIs of the token exchange that starts a task.
//
//nolint:gosec // G101: registered OAuth URNs, not credentials.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeTaskTicket    = "urn:agentbox:params:oauth:token-type:task-ticket"
	ClientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	AgentTaskType          = "agent_task"
)

// TaskRequest is what an application sends the STS to start a task: an
// OAuth 2.0 token exchange (RFC 8693). On the wire it is form-encoded, with
// AuthorizationDetails as a JSON string (RFC 9396). The user's identity,
// sign-in strength and session come from SubjectToken.
type TaskRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	RequestedTokenType string `json:"requested_token_type"`
	// AuthorizationDetails holds exactly one entry.
	AuthorizationDetails []AgentTask `json:"authorization_details"`
	ClientAssertionType  string      `json:"client_assertion_type,omitempty"`
	ClientAssertion      string      `json:"client_assertion,omitempty"`
}

// AgentTask names the task to start. Its scope comes from the task type,
// never from the request.
type AgentTask struct {
	Type     string `json:"type"`
	TaskType string `json:"task_type"`
	ObjectID string `json:"object_id"`
	// Agent is the agent the ticket is for.
	Agent string `json:"agent"`
}

// Offer is a delegation offer as the STS records it: an agent proposes a
// narrower grant for one named recipient. The offering agent fills To, TTL,
// AuthorizationDetails, Limits and MaxDepth; the STS fills the rest.
type Offer struct {
	ID       string `json:"id"`
	IssuedAt int64  `json:"iat"`
	// Expiry is when the offer lapses if nobody redeems it.
	Expiry int64 `json:"exp"`
	// Parent is the offering agent's grant, the child's parent.
	Parent string `json:"parent"`
	From   string `json:"from"`
	To     string `json:"to"`
	// TTL is the child grant's lifetime from redemption, cut short at the
	// parent's expiry.
	TTL                  Duration              `json:"ttl"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	Limits               []Limit               `json:"limits,omitempty"`
	// MaxDepth is how many further delegation steps the child may take.
	MaxDepth int `json:"max_depth,omitempty"`
	// Redeemed is when the recipient redeemed the offer; at most once.
	Redeemed int64 `json:"redeemed,omitempty"`
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
	Closed *Timestamp `json:"closed,omitempty"`
	Task   TaskRef    `json:"task"`
	// Grant is the grant the call was made under.
	Grant string `json:"grant"`
	Agent string `json:"agent"`
	// User is the user the agent acts for; never an approver.
	User SubjectID `json:"user"`
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
	AMR      []string  `json:"amr,omitempty"`
}
