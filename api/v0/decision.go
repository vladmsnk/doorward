package v0

// Decision is the record of one authorization decision. It carries every
// element level L1 asks for: who acts (Principal.Agent), on whose behalf
// (Principal.User), where the decision was made (PDP), where it was enforced
// (PEP), and what was asked (Request). Request is the agent's input and
// Principal is what the verified grant established; the two are kept apart
// because a request is not an authorization.
type Decision struct {
	ID          string            `json:"id"`
	Time        Timestamp         `json:"time"`
	Request     EvaluationRequest `json:"request"`
	Principal   *Principal        `json:"principal,omitempty"`
	Grant       *GrantRef         `json:"grant,omitempty"`
	ActionHash  string            `json:"action_hash,omitempty"`
	Sensitivity Sensitivity       `json:"sensitivity,omitempty"`
	Outcome     Outcome           `json:"outcome"`
	Reasons     []Reason          `json:"reasons,omitempty"`
	// Checks lists every check the core ran, in order.
	Checks []Check `json:"checks"`
	PDP    PDP     `json:"pdp"`
	PEP    PEP     `json:"pep"`
	// Limits is what an allowed call drew from each budget. It is empty for
	// any other outcome: budget is drawn last, so a refusal spends nothing.
	Limits   []LimitUse   `json:"limits,omitempty"`
	Approval *ApprovalRef `json:"approval,omitempty"`
	Chain    *ChainLink   `json:"chain,omitempty"`
}

// EvaluationRequest is an AuthZEN 1.0 access evaluation request.
type EvaluationRequest struct {
	Subject  Entity         `json:"subject"`
	Action   Action         `json:"action"`
	Resource Entity         `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// Entity is an AuthZEN subject or resource.
type Entity struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is an AuthZEN action.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Principal is who acted and for whom, from the verified grant.
type Principal struct {
	User  string `json:"user"`
	Agent string `json:"agent"`
	// Actors are the agents earlier in the delegation chain, nearest first.
	Actors []string `json:"actors,omitempty"`
}

// GrantRef points at the grant a decision was made against, copied at
// decision time so the record reads on its own.
type GrantRef struct {
	ID     string  `json:"id"`
	Root   string  `json:"root"`
	Parent string  `json:"parent,omitempty"`
	Depth  int     `json:"depth"`
	Task   TaskRef `json:"task"`
}

// TaskRef names a task.
type TaskRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Outcome is one of the three answers of the decision core.
type Outcome string

const (
	OutcomeAllow            Outcome = "allow"
	OutcomeDeny             Outcome = "deny"
	OutcomeApprovalRequired Outcome = "approval_required"
)

// Reason explains a refusal or a hold.
type Reason struct {
	Code    ReasonCode `json:"code"`
	Message string     `json:"message,omitempty"`
	// Field is the argument that did not match the grant.
	Field string `json:"field,omitempty"`
}

// ReasonCode is a stable code negative tests assert on. Codes outside this
// list start with "x-".
type ReasonCode string

const (
	ReasonRequestMalformed      ReasonCode = "request_malformed"
	ReasonGrantMissing          ReasonCode = "grant_missing"
	ReasonGrantMalformed        ReasonCode = "grant_malformed"
	ReasonGrantSignatureInvalid ReasonCode = "grant_signature_invalid"
	ReasonGrantExpired          ReasonCode = "grant_expired"
	ReasonGrantNotYetValid      ReasonCode = "grant_not_yet_valid"
	ReasonGrantRevoked          ReasonCode = "grant_revoked"
	ReasonPoPMissing            ReasonCode = "pop_missing"
	ReasonPoPInvalid            ReasonCode = "pop_invalid"
	ReasonPoPReplayed           ReasonCode = "pop_replayed"
	ReasonAudienceMismatch      ReasonCode = "audience_mismatch"
	ReasonActionNotGranted      ReasonCode = "action_not_granted"
	ReasonFieldMissing          ReasonCode = "field_missing"
	ReasonConstraintViolated    ReasonCode = "constraint_violated"
	ReasonSensitivityExceeded   ReasonCode = "sensitivity_exceeded"
	ReasonDelegationInvalid     ReasonCode = "delegation_invalid"
	ReasonPolicyDenied          ReasonCode = "policy_denied"
	ReasonLimitExceeded         ReasonCode = "limit_exceeded"
	ReasonTimeUntrusted         ReasonCode = "time_untrusted"
	ReasonInternalError         ReasonCode = "internal_error"
)

// Check is one step of the decision and how it ended.
type Check struct {
	Name   CheckName   `json:"name"`
	Result CheckResult `json:"result"`
	Detail string      `json:"detail,omitempty"`
}

// CheckName names a step of the decision core.
type CheckName string

const (
	CheckRequest     CheckName = "request"
	CheckSignature   CheckName = "signature"
	CheckStatus      CheckName = "status"
	CheckPoP         CheckName = "pop"
	CheckAudience    CheckName = "audience"
	CheckTime        CheckName = "time"
	CheckDelegation  CheckName = "delegation"
	CheckSubset      CheckName = "subset"
	CheckSensitivity CheckName = "sensitivity"
	CheckPolicy      CheckName = "policy"
	CheckLimits      CheckName = "limits"
)

// CheckResult is how a check ended.
type CheckResult string

const (
	CheckPass CheckResult = "pass"
	CheckFail CheckResult = "fail"
	CheckSkip CheckResult = "skip"
)

// PDP is where a decision was made.
type PDP struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

// PEPKind is the kind of point of enforcement.
type PEPKind string

const (
	PEPGateway  PEPKind = "gateway"
	PEPExtAuthz PEPKind = "ext_authz"
	PEPSDK      PEPKind = "sdk"
	PEPBroker   PEPKind = "broker"
)

// PEP is where a decision was enforced.
type PEP struct {
	ID   string  `json:"id"`
	Kind PEPKind `json:"kind"`
}

// LimitUse is what one call drew from one budget.
type LimitUse struct {
	Name      string  `json:"name"`
	Consumed  float64 `json:"consumed"`
	Remaining float64 `json:"remaining"`
}

// ApprovalRef names the approval request opened for a call.
type ApprovalRef struct {
	Request string `json:"request"`
}

// ChainLink is a record's place in the hash-chained journal. The first
// record, Seq 0, has no Prev.
type ChainLink struct {
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev,omitempty"`
	Hash string `json:"hash"`
}
