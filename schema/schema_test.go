package schema_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/schema"
)

const examples = "../examples/v0"

func newValidator(t *testing.T) *schema.Validator {
	t.Helper()
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// example reads one example file as a single JSON document.
func example(t *testing.T, rel string, kind schema.Kind) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(examples, rel))
	if err != nil {
		t.Fatal(err)
	}
	srcs, err := schema.Read(rel, data, kind)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 {
		t.Fatalf("%s: %d documents, want 1", rel, len(srcs))
	}
	return srcs[0].JSON
}

// F02 "done when": every example passes validation, decodes into its Go type,
// and comes back out of the Go type unchanged and still valid.
func TestExamplesValidateAndRoundTrip(t *testing.T) {
	v := newValidator(t)
	dirs := map[string]schema.Kind{
		"config":      "",
		"taskrequest": schema.TaskRequest,
		"grant":       schema.Grant,
		"decision":    schema.Decision,
		"approval":    schema.Approval,
	}
	seen := map[schema.Kind]int{}

	for dir, kind := range dirs {
		paths, err := filepath.Glob(filepath.Join(examples, dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			srcs, err := schema.Read(p, data, kind)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			for _, src := range srcs {
				t.Run(filepath.Base(src.Name), func(t *testing.T) {
					seen[src.Kind]++
					if err := v.Validate(src.Kind, src.JSON); err != nil {
						t.Fatalf("invalid example:\n%v", err)
					}
					roundTrip(t, v, src)
				})
			}
		}
	}
	for _, k := range schema.Kinds {
		if seen[k] == 0 {
			t.Errorf("no example of kind %s", k)
		}
	}
}

func roundTrip(t *testing.T, v *schema.Validator, src schema.Source) {
	t.Helper()
	var out any
	var err error
	switch src.Kind {
	case schema.Agent:
		out, err = schema.Decode[v0.Agent](v, src.JSON)
	case schema.TaskType:
		out, err = schema.Decode[v0.TaskType](v, src.JSON)
	case schema.Manifest:
		out, err = schema.Decode[v0.Manifest](v, src.JSON)
	case schema.Application:
		out, err = schema.Decode[v0.Application](v, src.JSON)
	case schema.TaskRequest:
		out, err = schema.Decode[v0.TaskRequest](v, src.JSON)
	case schema.Grant:
		out, err = schema.Decode[v0.Grant](v, src.JSON)
	case schema.Decision:
		out, err = schema.Decode[v0.Decision](v, src.JSON)
	case schema.Approval:
		out, err = schema.Decode[v0.Approval](v, src.JSON)
	default:
		t.Fatalf("no decoder for kind %s", src.Kind)
	}
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	again, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(src.Kind, again); err != nil {
		t.Fatalf("re-encoded document is invalid:\n%v\n%s", err, again)
	}
	var before, after any
	if err := json.Unmarshal(src.JSON, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(again, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("round trip changed the document\nbefore: %s\nafter:  %s", src.JSON, again)
	}
}

// edit is one change to a valid example that must make it invalid.
type edit struct {
	set   string // JSON Pointer to set...
	value any    // ...to this value
	del   string // or JSON Pointer to delete
}

// The examples the negative tests start from.
const (
	agent     = "config/agent-invoice-assistant.yaml"
	tasktype  = "config/tasktype-pay-invoice.yaml"
	svcTask   = "config/tasktype-reconcile-day.yaml"
	manifest  = "config/manifest-payments-api.yaml"
	mcp       = "config/manifest-ledger-mcp.yaml"
	app       = "config/application-billing-app.yaml"
	taskreq   = "taskrequest/start-pay-invoice.json"
	svcReq    = "taskrequest/start-reconcile-day.json"
	userGrant = "grant/pay-invoice.json"
	svcGrant  = "grant/reconcile-day.json"
	allow     = "decision/1-allow-get-invoice.json"
	deny      = "decision/2-deny-amount-over-grant.json"
	hold      = "decision/3-approval-required-pay-invoice.json"
	svcAllow  = "decision/4-allow-reconciler-post-entry.json"
	userAppr  = "approval/pay-invoice-1200-eur.json"
	groupAppr = "approval/write-off-rounding.json"
)

// Values the edits below put into documents.
var (
	alice     = map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "00u8a1iceQ2xYz7"}
	bob       = map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "00u5b0bR7tLm2Qa"}
	agentTask = map[string]any{"type": "agent_task", "task_type": "pay-invoice", "object_id": "inv_7Q2M9X4K", "agent": "invoice-assistant", "trigger": "ui"}
)

func TestInvalidDocuments(t *testing.T) {
	v := newValidator(t)
	cases := []struct {
		name    string
		file    string
		kind    schema.Kind
		edits   []edit
		keyword string // a schema keyword the error must mention
	}{
		// Envelope.
		{"wrong apiVersion", agent, schema.Agent, []edit{{set: "/apiVersion", value: "agentbox/v1"}}, "const"},
		{"unknown top-level field", agent, schema.Agent, []edit{{set: "/status", value: map[string]any{}}}, "additionalProperties"},
		{"name with upper case", agent, schema.Agent, []edit{{set: "/metadata/name", value: "Invoice-Assistant"}}, "pattern"},

		// Agent.
		{"agent without owner", agent, schema.Agent, []edit{{del: "/spec/owner"}}, "required"},
		{"owner contact not an email", agent, schema.Agent, []edit{{set: "/spec/owner/contact", value: "on-call"}}, "format"},
		{"agent without identities", agent, schema.Agent, []edit{{del: "/spec/identities"}}, "required"},
		{"jwt identity without subject", agent, schema.Agent, []edit{{del: "/spec/identities/0/subject"}}, "required"},
		{"registration with an issuer", agent, schema.Agent, []edit{{set: "/spec/identities/0", value: map[string]any{"type": "registration", "issuer": "https://x"}}}, "false schema"},
		{"unknown identity type", agent, schema.Agent, []edit{{set: "/spec/identities/0/type", value: "password"}}, "enum"},
		{"max_ttl in words", agent, schema.Agent, []edit{{set: "/spec/max_ttl", value: "1 day"}}, "pattern"},
		{"unknown tier", agent, schema.Agent, []edit{{set: "/spec/max_sensitivity", value: "high"}}, "enum"},
		{"empty permissions", agent, schema.Agent, []edit{{set: "/spec/permissions", value: []any{}}}, "minItems"},
		{"wildcard action", agent, schema.Agent, []edit{{set: "/spec/permissions/0/actions/0", value: "*"}}, "pattern"},
		{"location not a URL", agent, schema.Agent, []edit{{set: "/spec/permissions/0/locations/0", value: "payments"}}, "format"},
		{"unknown constraint type", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{"regex": ".*"}}}, "unevaluatedProperties"},
		{"empty constraint", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{}}}, "minProperties"},
		{"constraint key not a pointer", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/amount", value: map[string]any{"max": 1}}}, "pattern"},
		{"sum limit without field", agent, schema.Agent, []edit{{del: "/spec/limits/0/field"}}, "required"},
		{"delegation is not in v0", agent, schema.Agent, []edit{{set: "/spec/delegation", value: map[string]any{"max_depth": 1}}}, "additionalProperties"},

		// Task type.
		{"task type without runs_as", tasktype, schema.TaskType, []edit{{del: "/spec/runs_as"}}, "required"},
		{"task type without start", tasktype, schema.TaskType, []edit{{del: "/spec/start"}}, "required"},
		{"chat task without confirmation", tasktype, schema.TaskType, []edit{{set: "/spec/start/confirmation", value: "none"}}, "const"},
		{"user task without initiators", tasktype, schema.TaskType, []edit{{del: "/spec/initiators"}}, "required"},
		{"user task on a schedule", tasktype, schema.TaskType, []edit{{set: "/spec/start/triggers", value: []any{"schedule"}}}, "enum"},
		{"unanchored id_pattern", tasktype, schema.TaskType, []edit{{set: "/spec/object/id_pattern", value: "inv_[0-9]+"}}, "pattern"},
		{"id_pattern not a regex", tasktype, schema.TaskType, []edit{{set: "/spec/object/id_pattern", value: "^inv_[0-9+$"}}, "format"},
		{"count limit with a field", tasktype, schema.TaskType, []edit{{set: "/spec/limits/1/field", value: "/amount"}}, "false schema"},
		{"count limit not whole", tasktype, schema.TaskType, []edit{{set: "/spec/limits/1/max", value: 2.5}}, "integer"},
		{"task_object false", tasktype, schema.TaskType, []edit{{set: "/spec/permissions/0/constraints/~1invoice_id/task_object", value: false}}, "const"},
		{"user route needing two", tasktype, schema.TaskType, []edit{{set: "/spec/approval/required", value: 2}}, "const"},
		{"user route with groups", tasktype, schema.TaskType, []edit{{set: "/spec/approval/approvers/groups", value: []any{"x"}}}, "false schema"},
		{"approval without sign-in age", tasktype, schema.TaskType, []edit{{del: "/spec/approval/max_auth_age"}}, "required"},
		{"service task with initiators", svcTask, schema.TaskType, []edit{{set: "/spec/initiators", value: []any{"billing-app"}}}, "false schema"},
		{"service task asking the user to confirm", svcTask, schema.TaskType, []edit{{set: "/spec/start/confirmation", value: "user"}}, "const"},
		{"service task from chat", svcTask, schema.TaskType, []edit{{set: "/spec/start/triggers", value: []any{"chat"}}}, "enum"},
		{"service task approved by its user", svcTask, schema.TaskType, []edit{{set: "/spec/approval/approvers", value: map[string]any{"kind": "user"}}, {set: "/spec/approval/required", value: 1}}, "const"},
		{"group route needing one", svcTask, schema.TaskType, []edit{{set: "/spec/approval/required", value: 1}}, "minimum"},
		{"group route without groups", svcTask, schema.TaskType, []edit{{del: "/spec/approval/approvers/groups"}}, "required"},

		// Manifest.
		{"http operation without route", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/http"}}, "required"},
		{"http param without location", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/params/~1invoice_id/in"}}, "required"},
		{"operation without tier", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/sensitivity"}}, "required"},
		{"old tier name", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/sensitivity", value: "low"}}, "enum"},
		{"object param", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1invoice_id/type", value: "object"}}, "enum"},
		{"unknown protocol", manifest, schema.Manifest, []edit{{set: "/spec/protocol", value: "grpc"}}, "enum"},
		{"mcp operation with a route", mcp, schema.Manifest, []edit{{set: "/spec/operations/0/http", value: map[string]any{"method": "GET", "path": "/"}}}, "false schema"},
		{"mcp param with a location", mcp, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1day/in", value: "body"}}, "false schema"},

		// Application.
		{"application without users", app, schema.Application, []edit{{del: "/spec/users"}}, "required"},
		{"application with no user source", app, schema.Application, []edit{{set: "/spec/users", value: map[string]any{}}}, "minProperties"},
		{"private_key_jwt without keys", app, schema.Application, []edit{{del: "/spec/authentication/jwks_uri"}}, "oneOf"},
		{"keys over plain HTTP", app, schema.Application, []edit{{set: "/spec/authentication/jwks_uri", value: "http://billing.example.internal/jwks"}}, "pattern"},
		{"OAuth client application without client_id", app, schema.Application, []edit{
			{set: "/spec/authentication/method", value: "oauth_client"}, {del: "/spec/authentication/jwks_uri"},
			{set: "/spec/authentication/issuer", value: "https://login.example.com"}}, "required"},
		{"self-asserted users without a signing key", app, schema.Application, []edit{
			{set: "/spec/authentication/method", value: "oauth_client"}, {del: "/spec/authentication/jwks_uri"},
			{set: "/spec/authentication/issuer", value: "https://login.example.com"},
			{set: "/spec/authentication/client_id", value: "0oa1billing"},
			{set: "/spec/users/self_asserted", value: true}}, "const"},

		// Task request.
		{"not a token exchange", taskreq, schema.TaskRequest, []edit{{set: "/grant_type", value: "client_credentials"}}, "const"},
		{"two tasks in one request", taskreq, schema.TaskRequest, []edit{{set: "/authorization_details", value: []any{agentTask, agentTask}}}, "maxItems"},
		{"task without an agent", taskreq, schema.TaskRequest, []edit{{del: "/authorization_details/0/agent"}}, "required"},
		{"task without a trigger", taskreq, schema.TaskRequest, []edit{{del: "/authorization_details/0/trigger"}}, "required"},
		{"unknown trigger", taskreq, schema.TaskRequest, []edit{{set: "/authorization_details/0/trigger", value: "cron"}}, "enum"},
		{"client assertion without its type", taskreq, schema.TaskRequest, []edit{{del: "/client_assertion_type"}}, "dependentRequired"},
		{"access token as the user's identity", taskreq, schema.TaskRequest, []edit{{set: "/subject_token_type", value: "urn:ietf:params:oauth:token-type:access_token"}}, "enum"},

		// Grant.
		{"grant without act", userGrant, schema.Grant, []edit{{del: "/act"}}, "required"},
		{"grant without task", userGrant, schema.Grant, []edit{{del: "/task"}}, "required"},
		{"grant without client_id", userGrant, schema.Grant, []edit{{del: "/client_id"}}, "required"},
		{"task without started", userGrant, schema.Grant, []edit{{del: "/task/started"}}, "required"},
		{"sub_id in another format", userGrant, schema.Grant, []edit{{set: "/sub_id/format", value: "email"}}, "const"},
		{"aud as a string", userGrant, schema.Grant, []edit{{set: "/aud", value: "https://payments.example.internal"}}, "type"},
		{"empty aud", userGrant, schema.Grant, []edit{{set: "/aud", value: []any{}}}, "minItems"},
		{"exp as a date string", userGrant, schema.Grant, []edit{{set: "/exp", value: "2026-10-30T10:00:00Z"}}, "type"},
		{"short key thumbprint", userGrant, schema.Grant, []edit{{set: "/cnf/jkt", value: "abc"}}, "pattern"},
		{"unknown claim", userGrant, schema.Grant, []edit{{set: "/roles", value: []any{"admin"}}}, "additionalProperties"},
		{"delegation claims are not in v0", userGrant, schema.Grant, []edit{{set: "/parent", value: "grt_01JBXR4T7Q2M9X4KZ8D3F6H1ZZ"}}, "additionalProperties"},
		{"nested actor is not in v0", userGrant, schema.Grant, []edit{{set: "/act/act", value: map[string]any{"sub": "other"}}}, "additionalProperties"},
		{"actor with a foreign ID", userGrant, schema.Grant, []edit{{set: "/act/sub", value: "spiffe://example.internal/agent"}}, "pattern"},
		{"unresolved task_object", userGrant, schema.Grant, []edit{{set: "/authorization_details/0/constraints/~1invoice_id", value: map[string]any{"task_object": true}}}, "unevaluatedProperties"},
		{"authorization detail without type", userGrant, schema.Grant, []edit{{del: "/authorization_details/0/type"}}, "required"},
		{"foreign authorization detail type", userGrant, schema.Grant, []edit{{set: "/authorization_details/0/type", value: "payment_initiation"}}, "const"},

		// Decision.
		{"unknown outcome", allow, schema.Decision, []edit{{set: "/outcome", value: "maybe"}}, "enum"},
		{"allow without principal", allow, schema.Decision, []edit{{del: "/principal"}}, "required"},
		{"principal with nobody accountable", allow, schema.Decision, []edit{{del: "/principal/user"}}, "oneOf"},
		{"principal with user and owner", allow, schema.Decision, []edit{{set: "/principal/owner", value: "payments"}}, "oneOf"},
		{"allow without grant", allow, schema.Decision, []edit{{del: "/grant"}}, "required"},
		{"allow without action hash", allow, schema.Decision, []edit{{del: "/action_hash"}}, "required"},
		{"no checks", allow, schema.Decision, []edit{{set: "/checks", value: []any{}}}, "minItems"},
		{"no point of enforcement", allow, schema.Decision, []edit{{del: "/pep"}}, "required"},
		{"no point of decision", allow, schema.Decision, []edit{{del: "/pdp"}}, "required"},
		{"request without subject", allow, schema.Decision, []edit{{del: "/request/subject"}}, "required"},
		{"time not RFC 3339", allow, schema.Decision, []edit{{set: "/time", value: "30.10.2026 09:30"}}, "format"},
		{"time without milliseconds", allow, schema.Decision, []edit{{set: "/time", value: "2026-10-30T09:30:12Z"}}, "pattern"},
		{"time with an offset", allow, schema.Decision, []edit{{set: "/time", value: "2026-10-30T11:30:12.418+02:00"}}, "pattern"},
		{"malformed action hash", allow, schema.Decision, []edit{{set: "/action_hash", value: "md5:abc"}}, "pattern"},
		{"first record with prev", allow, schema.Decision, []edit{{set: "/chain/prev", value: "sha-256:example-hash-not-computed-record-0000000000"}}, "not"},
		{"later record without prev", deny, schema.Decision, []edit{{del: "/chain/prev"}}, "required"},
		{"deny without reasons", deny, schema.Decision, []edit{{del: "/reasons"}}, "required"},
		{"deny with empty reasons", deny, schema.Decision, []edit{{set: "/reasons", value: []any{}}}, "minItems"},
		{"deny spends budget", deny, schema.Decision, []edit{{set: "/limits", value: []any{map[string]any{"name": "calls", "consumed": 1, "remaining": 49}}}}, "false schema"},
		{"unknown reason code", deny, schema.Decision, []edit{{set: "/reasons/0/code", value: "too_expensive"}}, "anyOf"},
		{"hold without approval request", hold, schema.Decision, []edit{{del: "/approval"}}, "required"},
		{"hold spends budget", hold, schema.Decision, []edit{{set: "/limits", value: []any{map[string]any{"name": "calls", "consumed": 1, "remaining": 49}}}}, "false schema"},
		{"unknown check", hold, schema.Decision, []edit{{set: "/checks/0/name", value: "vibes"}}, "enum"},
		{"delegation check is not in v0", hold, schema.Decision, []edit{{set: "/checks/0/name", value: "delegation"}}, "enum"},
		{"unknown enforcement point kind", hold, schema.Decision, []edit{{set: "/pep/kind", value: "firewall"}}, "enum"},
		{"approval_required as a reason", hold, schema.Decision, []edit{{set: "/reasons", value: []any{map[string]any{"code": "approval_required"}}}}, "anyOf"},
		{"service decision naming a user", svcAllow, schema.Decision, []edit{{set: "/principal/user", value: "alice@example.com"}}, "oneOf"},

		// Approval record.
		{"approval without route", userAppr, schema.Approval, []edit{{del: "/route"}}, "required"},
		{"user route without the user", userAppr, schema.Approval, []edit{{del: "/user"}}, "required"},
		{"approved without closing time", userAppr, schema.Approval, []edit{{del: "/closed"}}, "required"},
		{"pending with a grant", userAppr, schema.Approval, []edit{{set: "/status", value: "pending"}}, "false schema"},
		{"rejected with a grant", groupAppr, schema.Approval, []edit{{set: "/status", value: "rejected"}}, "false schema"},
		{"unknown verdict", groupAppr, schema.Approval, []edit{{set: "/votes/0/verdict", value: "maybe"}}, "enum"},
		{"vote without sign-in time", groupAppr, schema.Approval, []edit{{del: "/votes/0/auth_time"}}, "required"},
		{"approver in another format", groupAppr, schema.Approval, []edit{{set: "/votes/0/approver/format", value: "email"}}, "const"},
		{"group route without groups", groupAppr, schema.Approval, []edit{{del: "/route/groups"}}, "required"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := applyEdits(t, example(t, tc.file, tc.kind), tc.edits)
			err := v.Validate(tc.kind, doc)
			if err == nil {
				t.Fatalf("document was accepted:\n%s", doc)
			}
			var verr *jsonschema.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("want a schema validation error, got %v", err)
			}
			if msg := verr.Error() + flatten(*verr.DetailedOutput()); !strings.Contains(msg, tc.keyword) {
				t.Errorf("error does not mention %q:\n%s", tc.keyword, msg)
			}
		})
	}
}

// The rules that span fields: each document has the right shape but breaks one.
func TestRuleChecks(t *testing.T) {
	v := newValidator(t)
	cases := []struct {
		name  string
		file  string
		kind  schema.Kind
		edits []edit
		want  string
	}{
		{"aud wider than the details", userGrant, schema.Grant, []edit{{set: "/aud", value: []any{"https://payments.example.internal", "https://other.example.internal"}}}, "aud must list exactly"},
		{"expiring before issue", userGrant, schema.Grant, []edit{{set: "/exp", value: 1793352000}}, "exp must be after iat"},
		{"confirmed after issue", userGrant, schema.Grant, []edit{{set: "/task/started/confirmed_at", value: 1793352700}}, "confirmed_at is after iat"},
		{"user grant without sub_id", userGrant, schema.Grant, []edit{{del: "/sub_id"}}, "sub_id must say"},
		{"user task without initiator", userGrant, schema.Grant, []edit{{del: "/task/initiator"}}, "names the application"},
		{"min above max", userGrant, schema.Grant, []edit{{set: "/authorization_details/1/constraints/~1amount/min", value: 9000}}, "min 9000 is above max 5000"},
		{"limit defined twice", userGrant, schema.Grant, []edit{{set: "/limits/1", value: map[string]any{"name": "payout-total", "kind": "count", "max": 3}}}, `limit "payout-total" is defined twice`},
		{"service grant with sub_id", svcGrant, schema.Grant, []edit{{set: "/sub_id", value: alice}}, "service task and carries no sub_id"},
		{"service grant with an initiator", svcGrant, schema.Grant, []edit{{set: "/task/initiator", value: "billing-app"}}, "has no initiator"},
		{"service grant confirmed by nobody", svcGrant, schema.Grant, []edit{{set: "/task/started/confirmed_at", value: 1793322000}}, "nobody to confirm"},

		{"allow with a failed check", allow, schema.Decision, []edit{{set: "/checks/1/result", value: "fail"}}, "cannot have failed checks"},
		{"deny with nothing failed", deny, schema.Decision, []edit{{set: "/checks/6/result", value: "pass"}}, "must have a failed check"},
		{"hold for another reason", hold, schema.Decision, []edit{{set: "/checks/6/result", value: "fail"}}, "fails the sensitivity check and nothing else"},
		{"check listed twice", allow, schema.Decision, []edit{{set: "/checks/1/name", value: "request"}}, `check "request" is listed twice`},

		{"path segment without a param", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/params"}}, "path segment {invoice_id} has no param"},
		{"path param not in the path", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1extra", value: map[string]any{"type": "string", "in": "path"}}}, "param /extra is in the path"},
		{"operation declared twice", manifest, schema.Manifest, []edit{{set: "/spec/operations/1/name", value: "get_invoice"}}, `operation "get_invoice" is declared twice`},
		{"identity listed twice", agent, schema.Agent, []edit{{set: "/spec/identities", value: []any{
			map[string]any{"type": "jwt", "issuer": "https://login.example.com", "subject": "0oa8f2k1LmN3pQ4rS5t6"},
			map[string]any{"type": "jwt", "issuer": "https://login.example.com", "subject": "0oa8f2k1LmN3pQ4rS5t6"}}}}, "listed twice"},

		{"user task asking for the grant itself", taskreq, schema.TaskRequest, []edit{{set: "/requested_token_type", value: "urn:ietf:params:oauth:token-type:access_token"}}, "asks for a ticket"},
		{"service task asking for a ticket", svcReq, schema.TaskRequest, []edit{{set: "/requested_token_type", value: "urn:agentbox:params:oauth:token-type:task-ticket"}}, "asks for the grant itself"},
		{"service task with a confirmation", svcReq, schema.TaskRequest, []edit{{set: "/confirmation", value: "eyJ.x.y"}}, "nobody to confirm"},
		{"service task started with an ID token", svcReq, schema.TaskRequest, []edit{{set: "/subject_token_type", value: "urn:ietf:params:oauth:token-type:id_token"}}, "agent's own token"},

		{"someone else voting on a user route", userAppr, schema.Approval, []edit{{set: "/votes/0/approver", value: bob}}, "only the task's user votes"},
		{"user route needing two", userAppr, schema.Approval, []edit{{set: "/required", value: 2}}, "exactly 1 approval"},
		{"user voting on a group route", groupAppr, schema.Approval, []edit{{set: "/user", value: alice}, {set: "/votes/0/approver", value: alice}}, "cannot approve the call on a group route"},
		{"approver voting twice", groupAppr, schema.Approval, []edit{{set: "/votes/1/approver", value: bob}}, "voted twice"},
		{"approved with too few votes", groupAppr, schema.Approval, []edit{{del: "/votes/1"}}, "approved needs 2 approvals"},
		{"vote after closing", groupAppr, schema.Approval, []edit{{set: "/votes/1/time", value: "2026-10-30T08:00:00.000Z"}}, "not open"},
		{"signed in after voting", groupAppr, schema.Approval, []edit{{set: "/votes/0/auth_time", value: "2026-10-30T07:03:20.000Z"}}, "auth_time is after the vote"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := applyEdits(t, example(t, tc.file, tc.kind), tc.edits)
			if err := v.Validate(tc.kind, doc); err != nil {
				t.Fatalf("the edit should keep the schema satisfied:\n%v", err)
			}
			err := v.Check(tc.kind, doc)
			var rerr *schema.RuleError
			if !errors.As(err, &rerr) {
				t.Fatalf("want a rule error, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not mention %q:\n%v", tc.want, err)
			}
		})
	}
}

// A custom reason code is fine as long as it says it is one.
func TestCustomReasonCode(t *testing.T) {
	v := newValidator(t)
	doc := applyEdits(t, example(t, deny, schema.Decision),
		[]edit{{set: "/reasons/0/code", value: "x-fraud_score"}})
	if err := v.Validate(schema.Decision, doc); err != nil {
		t.Fatalf("custom code rejected: %v", err)
	}
}

func flatten(u jsonschema.OutputUnit) string {
	var b strings.Builder
	b.WriteString(u.KeywordLocation)
	b.WriteString(" ")
	if u.Error != nil {
		b.WriteString(u.Error.String())
	}
	for _, e := range u.Errors {
		b.WriteString("\n")
		b.WriteString(flatten(e))
	}
	return b.String()
}

func applyEdits(t *testing.T, doc []byte, edits []edit) []byte {
	t.Helper()
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatal(err)
	}
	for _, e := range edits {
		if e.del != "" {
			root = patch(t, root, e.del, nil, true)
		} else {
			root = patch(t, root, e.set, e.value, false)
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// patch sets or deletes the value at a JSON Pointer.
func patch(t *testing.T, node any, pointer string, value any, del bool) any {
	t.Helper()
	parts := strings.Split(pointer, "/")[1:]
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	var walk func(node any, parts []string) any
	walk = func(node any, parts []string) any {
		key := parts[0]
		last := len(parts) == 1
		switch n := node.(type) {
		case map[string]any:
			if last {
				if del {
					if _, ok := n[key]; !ok {
						t.Fatalf("%s: nothing to delete", pointer)
					}
					delete(n, key)
				} else {
					n[key] = value
				}
				return n
			}
			child, ok := n[key]
			if !ok {
				t.Fatalf("%s: no member %q", pointer, key)
			}
			n[key] = walk(child, parts[1:])
			return n
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(n) {
				t.Fatalf("%s: bad index %q", pointer, key)
			}
			if last {
				if del {
					return append(n[:i], n[i+1:]...)
				}
				n[i] = value
				return n
			}
			n[i] = walk(n[i], parts[1:])
			return n
		default:
			t.Fatalf("%s: cannot descend into %T", pointer, node)
			return nil
		}
	}
	return walk(node, parts)
}

func TestDuplicateKeysAreRejected(t *testing.T) {
	v := newValidator(t)

	// The second "sub" would win in encoding/json; neither may win.
	grant := example(t, userGrant, schema.Grant)
	forged := strings.Replace(string(grant), `"sub":`, `"sub":"mallory@example.com","sub":`, 1)
	if err := v.Validate(schema.Grant, []byte(forged)); err == nil || !strings.Contains(err.Error(), `duplicate key "sub"`) {
		t.Errorf("duplicate sub in a grant: got %v", err)
	}

	nested := `{"a":{"b":[{"c":1,"c":2}]}}`
	if err := schema.CheckDuplicateKeys([]byte(nested)); err == nil || !strings.Contains(err.Error(), `"/a/b/0"`) {
		t.Errorf("nested duplicate: got %v", err)
	}

	yamlDoc := "apiVersion: agentbox/v0\nkind: Agent\nkind: TaskType\n"
	if _, err := schema.Read("x.yaml", []byte(yamlDoc), ""); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("duplicate YAML key: got %v", err)
	}
}

func TestTrailingDataIsRejected(t *testing.T) {
	if err := schema.CheckDuplicateKeys([]byte(`{"a":1} {"a":2}`)); err == nil {
		t.Error("two JSON values accepted as one document")
	}
}

func TestReadMultiDocumentYAML(t *testing.T) {
	var all []byte
	for _, f := range []string{"agent-invoice-assistant.yaml", "tasktype-pay-invoice.yaml"} {
		data, err := os.ReadFile(filepath.Join(examples, "config", f))
		if err != nil {
			t.Fatal(err)
		}
		all = append(append(all, "---\n"...), data...)
	}
	srcs, err := schema.Read("bundle.yaml", all, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 || srcs[0].Kind != schema.Agent || srcs[1].Kind != schema.TaskType {
		t.Fatalf("got %+v", srcs)
	}
	if srcs[1].Name != "bundle.yaml#2" {
		t.Errorf("name %q", srcs[1].Name)
	}
}

func TestReadKindResolution(t *testing.T) {
	agentDoc := []byte(`{"apiVersion":"agentbox/v0","kind":"Agent"}`)
	grant := []byte(`{"jti":"grt_0000000000"}`)

	if _, err := schema.Read("g.json", grant, ""); err == nil {
		t.Error("grant without --kind accepted")
	}
	if srcs, err := schema.Read("g.json", grant, schema.Grant); err != nil || srcs[0].Kind != schema.Grant {
		t.Errorf("grant with kind: %v %+v", err, srcs)
	}
	if _, err := schema.Read("b.json", agentDoc, schema.TaskType); err == nil {
		t.Error("Agent read as TaskType")
	}
	for _, k := range []string{"boundary", "Grant", "Policy"} {
		doc := []byte(`{"kind":"` + k + `"}`)
		if _, err := schema.Read("k.json", doc, ""); err == nil {
			t.Errorf("kind %q accepted as a configuration kind", k)
		}
	}
}

func TestDecodeRejectsAnInvalidDocument(t *testing.T) {
	v := newValidator(t)
	doc := applyEdits(t, example(t, userGrant, schema.Grant), []edit{{del: "/act"}})
	if _, err := schema.Decode[v0.Grant](v, doc); err == nil {
		t.Fatal("Decode accepted a grant without act")
	}
}

func TestParseKind(t *testing.T) {
	for in, want := range map[string]schema.Kind{"grant": schema.Grant, "TASKTYPE": schema.TaskType, "Decision": schema.Decision} {
		if got, err := schema.ParseKind(in); err != nil || got != want {
			t.Errorf("ParseKind(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := schema.ParseKind("task-type"); err == nil {
		t.Error("ParseKind accepted task-type")
	}
}
