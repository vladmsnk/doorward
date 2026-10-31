package v0

// URIs of the token exchange that starts a task.
//
//nolint:gosec // G101: registered OAuth URNs, not credentials.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeTaskTicket    = "urn:agentbox:params:oauth:token-type:task-ticket"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	ClientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	AgentTaskType          = "agent_task"
)

// TaskRequest starts a task: an OAuth 2.0 token exchange (RFC 8693). On the
// wire it is form-encoded, with AuthorizationDetails as a JSON string
// (RFC 9396). An application sends it for a user task and gets a ticket; an
// agent's sidecar sends it for a service task and gets the grant.
type TaskRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	RequestedTokenType string `json:"requested_token_type"`
	// AuthorizationDetails holds exactly one entry.
	AuthorizationDetails []AgentTask `json:"authorization_details"`
	// Confirmation proves the user confirmed this exact task; required when
	// the task type says so.
	Confirmation        string `json:"confirmation,omitempty"`
	ClientAssertionType string `json:"client_assertion_type,omitempty"`
	ClientAssertion     string `json:"client_assertion,omitempty"`
}

// AgentTask names the task to start. Its scope comes from the task type,
// never from the request.
type AgentTask struct {
	Type     string  `json:"type"`
	TaskType string  `json:"task_type"`
	ObjectID string  `json:"object_id"`
	Agent    string  `json:"agent"`
	Trigger  Trigger `json:"trigger"`
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
	// User is the user of a user task: the only voter on a user route, never
	// a voter on a group route.
	User *SubjectID `json:"user,omitempty"`
	// Route is who was asked, from the task type.
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
