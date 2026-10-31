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
		"config":   "",
		"consent":  schema.Consent,
		"grant":    schema.Grant,
		"decision": schema.Decision,
		"approval": schema.Approval,
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
	case schema.Manifest:
		out, err = schema.Decode[v0.Manifest](v, src.JSON)
	case schema.Agent:
		out, err = schema.Decode[v0.Agent](v, src.JSON)
	case schema.Mandate:
		out, err = schema.Decode[v0.Mandate](v, src.JSON)
	case schema.Consent:
		out, err = schema.Decode[v0.Consent](v, src.JSON)
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
	agent      = "config/agent-invoice-assistant.yaml"
	svcAgent   = "config/agent-reconciler.yaml"
	newAgent   = "config/agent-desk-helper.yaml"
	mandate    = "config/mandate-invoices.yaml"
	openMand   = "config/mandate-invoices-readonly.yaml"
	svcMandate = "config/mandate-reconcile.yaml"
	manifest   = "config/manifest-payments-api.yaml"
	mcp        = "config/manifest-ledger-mcp.yaml"
	consent    = "consent/alice-invoice-assistant.json"
	userGrant  = "grant/pay-invoice.json"
	svcGrant   = "grant/reconcile.json"
	allow      = "decision/1-allow-get-invoice.json"
	deny       = "decision/2-deny-amount-over-grant.json"
	hold       = "decision/3-approval-required-pay-invoice.json"
	svcAllow   = "decision/4-allow-reconciler-post-entry.json"
	userAppr   = "approval/pay-invoice-1200-eur.json"
	groupAppr  = "approval/write-off-rounding.json"
)

// Values the edits below put into documents.
var (
	alice    = map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "00u8a1iceQ2xYz7"}
	bob      = map[string]any{"format": "iss_sub", "iss": "https://login.example.com", "sub": "00u5b0bR7tLm2Qa"}
	someKeys = map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}}}
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
		{"agent without status", agent, schema.Agent, []edit{{del: "/spec/status"}}, "required"},
		{"unknown status", agent, schema.Agent, []edit{{set: "/spec/status", value: "trusted"}}, "enum"},
		{"verified agent without owner", agent, schema.Agent, []edit{{del: "/spec/owner"}}, "required"},
		{"owner contact not an email", agent, schema.Agent, []edit{{set: "/spec/owner/contact", value: "on-call"}}, "format"},
		{"unverified agent without publisher", newAgent, schema.Agent, []edit{{del: "/spec/publisher"}}, "required"},
		{"unverified agent with mandates", newAgent, schema.Agent, []edit{{set: "/spec/mandates", value: []any{"invoices"}}}, "maxItems"},
		{"publisher over plain HTTP", newAgent, schema.Agent, []edit{{set: "/spec/publisher/uri", value: "http://deskhelper.example"}}, "pattern"},
		{"agent without identities", agent, schema.Agent, []edit{{del: "/spec/identities"}}, "required"},
		{"OAuth client without client_id", agent, schema.Agent, []edit{{del: "/spec/identities/0/client_id"}}, "required"},
		{"OAuth client with two key sources", agent, schema.Agent, []edit{{set: "/spec/identities/0/jwks", value: someKeys}}, "not"},
		{"OAuth client with an issuer", agent, schema.Agent, []edit{{set: "/spec/identities/0/issuer", value: "https://x"}}, "false schema"},
		{"jwt identity without subject", svcAgent, schema.Agent, []edit{{del: "/spec/identities/0/subject"}}, "required"},
		{"jwt identity with redirect URIs", svcAgent, schema.Agent, []edit{{set: "/spec/identities/0/redirect_uris", value: []any{"https://x/cb"}}}, "false schema"},
		{"registration with an issuer", svcAgent, schema.Agent, []edit{{set: "/spec/identities/0", value: map[string]any{"type": "registration", "issuer": "https://x"}}}, "false schema"},
		{"unknown identity type", agent, schema.Agent, []edit{{set: "/spec/identities/0/type", value: "password"}}, "enum"},
		{"max_ttl in words", agent, schema.Agent, []edit{{set: "/spec/max_ttl", value: "1 day"}}, "pattern"},
		{"unknown tier", agent, schema.Agent, []edit{{set: "/spec/max_sensitivity", value: "high"}}, "enum"},
		{"empty permissions", agent, schema.Agent, []edit{{set: "/spec/permissions", value: []any{}}}, "minItems"},
		{"wildcard action", agent, schema.Agent, []edit{{set: "/spec/permissions/0/actions/0", value: "*"}}, "pattern"},
		{"location not a URL", agent, schema.Agent, []edit{{set: "/spec/permissions/0/locations/0", value: "payments"}}, "format"},
		{"unknown constraint type", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{"regex": ".*"}}}, "unevaluatedProperties"},
		{"task_object is gone", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{"task_object": true}}}, "unevaluatedProperties"},
		{"empty constraint", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/~1amount", value: map[string]any{}}}, "minProperties"},
		{"constraint key not a pointer", agent, schema.Agent, []edit{{set: "/spec/permissions/0/constraints/amount", value: map[string]any{"max": 1}}}, "pattern"},
		{"sum limit without field", agent, schema.Agent, []edit{{del: "/spec/limits/0/field"}}, "required"},
		{"unknown limit period", agent, schema.Agent, []edit{{set: "/spec/limits/0/per", value: "week"}}, "enum"},
		{"delegation is not in v0", agent, schema.Agent, []edit{{set: "/spec/delegation", value: map[string]any{"max_depth": 1}}}, "additionalProperties"},

		// Mandate.
		{"mandate without principal", mandate, schema.Mandate, []edit{{del: "/spec/principal"}}, "required"},
		{"user mandate without consent terms", mandate, schema.Mandate, []edit{{del: "/spec/consent"}}, "required"},
		{"consent without text", mandate, schema.Mandate, []edit{{del: "/spec/consent/text"}}, "required"},
		{"consent without duration", mandate, schema.Mandate, []edit{{del: "/spec/consent/max_duration"}}, "required"},
		{"open is never false", openMand, schema.Mandate, []edit{{set: "/spec/open", value: false}}, "const"},
		{"user route needing two", mandate, schema.Mandate, []edit{{set: "/spec/approval/required", value: 2}}, "const"},
		{"user route with groups", mandate, schema.Mandate, []edit{{set: "/spec/approval/approvers/groups", value: []any{"x"}}}, "false schema"},
		{"approval without sign-in age", mandate, schema.Mandate, []edit{{del: "/spec/approval/max_auth_age"}}, "required"},
		{"count limit with a field", mandate, schema.Mandate, []edit{{set: "/spec/limits/1/field", value: "/amount"}}, "false schema"},
		{"count limit not whole", mandate, schema.Mandate, []edit{{set: "/spec/limits/1/max", value: 2.5}}, "integer"},
		{"service mandate with consent terms", svcMandate, schema.Mandate, []edit{{set: "/spec/consent", value: map[string]any{"text": "x", "max_duration": "1h"}}}, "false schema"},
		{"service mandate marked open", svcMandate, schema.Mandate, []edit{{set: "/spec/open", value: true}}, "false schema"},
		{"service mandate approved by its user", svcMandate, schema.Mandate, []edit{{set: "/spec/approval/approvers", value: map[string]any{"kind": "user"}}, {set: "/spec/approval/required", value: 1}}, "const"},
		{"group route needing one", svcMandate, schema.Mandate, []edit{{set: "/spec/approval/required", value: 1}}, "minimum"},
		{"group route without groups", svcMandate, schema.Mandate, []edit{{del: "/spec/approval/approvers/groups"}}, "required"},

		// Manifest.
		{"http operation without route", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/http"}}, "required"},
		{"http param without location", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/params/~1invoice_id/in"}}, "required"},
		{"operation without tier", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/sensitivity"}}, "required"},
		{"old tier name", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/sensitivity", value: "low"}}, "enum"},
		{"object param", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1invoice_id/type", value: "object"}}, "enum"},
		{"unknown protocol", manifest, schema.Manifest, []edit{{set: "/spec/protocol", value: "grpc"}}, "enum"},
		{"mcp operation with a route", mcp, schema.Manifest, []edit{{set: "/spec/operations/0/http", value: map[string]any{"method": "GET", "path": "/"}}}, "false schema"},
		{"mcp param with a location", mcp, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1day/in", value: "body"}}, "false schema"},

		// Consent.
		{"consent without user", consent, schema.Consent, []edit{{del: "/user"}}, "required"},
		{"consent without mandate version", consent, schema.Consent, []edit{{del: "/mandate_version"}}, "required"},
		{"consent without expiry", consent, schema.Consent, []edit{{del: "/expires_at"}}, "required"},
		{"user in another format", consent, schema.Consent, []edit{{set: "/user/format", value: "email"}}, "const"},
		{"unknown consent status", consent, schema.Consent, []edit{{set: "/status", value: "paused"}}, "enum"},
		{"revoked without who", consent, schema.Consent, []edit{{set: "/status", value: "revoked"}, {set: "/revoked_at", value: "2026-11-01T00:00:00.000Z"}}, "required"},
		{"active with a revocation", consent, schema.Consent, []edit{{set: "/revoked_at", value: "2026-11-01T00:00:00.000Z"}}, "false schema"},
		{"auth without time", consent, schema.Consent, []edit{{del: "/auth/auth_time"}}, "required"},

		// Grant.
		{"grant without act", userGrant, schema.Grant, []edit{{del: "/act"}}, "required"},
		{"grant without mandate", userGrant, schema.Grant, []edit{{del: "/mandate"}}, "required"},
		{"grant without client_id", userGrant, schema.Grant, []edit{{del: "/client_id"}}, "required"},
		{"sub_id in another format", userGrant, schema.Grant, []edit{{set: "/sub_id/format", value: "email"}}, "const"},
		{"aud as a string", userGrant, schema.Grant, []edit{{set: "/aud", value: "https://payments.example.internal"}}, "type"},
		{"empty aud", userGrant, schema.Grant, []edit{{set: "/aud", value: []any{}}}, "minItems"},
		{"exp as a date string", userGrant, schema.Grant, []edit{{set: "/exp", value: "2026-10-30T10:00:00Z"}}, "type"},
		{"short key thumbprint", userGrant, schema.Grant, []edit{{set: "/cnf/jkt", value: "abc"}}, "pattern"},
		{"unknown claim", userGrant, schema.Grant, []edit{{set: "/roles", value: []any{"admin"}}}, "additionalProperties"},
		{"task claim is gone", userGrant, schema.Grant, []edit{{set: "/task", value: map[string]any{"id": "tsk_0000000000"}}}, "additionalProperties"},
		{"delegation claims are not in v0", userGrant, schema.Grant, []edit{{set: "/parent", value: "grt_01JBXR4T7Q2M9X4KZ8D3F6H1ZZ"}}, "additionalProperties"},
		{"nested actor is not in v0", userGrant, schema.Grant, []edit{{set: "/act/act", value: map[string]any{"sub": "other"}}}, "additionalProperties"},
		{"actor with a foreign ID", userGrant, schema.Grant, []edit{{set: "/act/sub", value: "spiffe://example.internal/agent"}}, "pattern"},
		{"authorization detail without type", userGrant, schema.Grant, []edit{{del: "/authorization_details/0/type"}}, "required"},
		{"foreign authorization detail type", userGrant, schema.Grant, []edit{{set: "/authorization_details/0/type", value: "payment_initiation"}}, "const"},

		// Decision.
		{"unknown outcome", allow, schema.Decision, []edit{{set: "/outcome", value: "maybe"}}, "enum"},
		{"allow without principal", allow, schema.Decision, []edit{{del: "/principal"}}, "required"},
		{"principal with nobody accountable", allow, schema.Decision, []edit{{del: "/principal/user"}}, "oneOf"},
		{"principal with user and owner", allow, schema.Decision, []edit{{set: "/principal/owner", value: "payments"}}, "oneOf"},
		{"allow without grant", allow, schema.Decision, []edit{{del: "/grant"}}, "required"},
		{"grant without mandate", allow, schema.Decision, []edit{{del: "/grant/mandate"}}, "required"},
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
		{"approval without mandate", userAppr, schema.Approval, []edit{{del: "/mandate"}}, "required"},
		{"user route without the user", userAppr, schema.Approval, []edit{{del: "/user"}}, "required"},
		{"user route without the consent", userAppr, schema.Approval, []edit{{del: "/consent"}}, "required"},
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
		{"user grant without sub_id", userGrant, schema.Grant, []edit{{del: "/sub_id"}}, "sub_id must say"},
		{"user grant without consent", userGrant, schema.Grant, []edit{{del: "/consent"}}, "consent must name"},
		{"min above max", userGrant, schema.Grant, []edit{{set: "/authorization_details/1/constraints/~1amount/min", value: 9000}}, "min 9000 is above max 5000"},
		{"limit defined twice", userGrant, schema.Grant, []edit{{set: "/limits/1", value: map[string]any{"name": "payout-month", "kind": "count", "max": 3}}}, `limit "payout-month" is defined twice`},
		{"service grant with sub_id", svcGrant, schema.Grant, []edit{{set: "/sub_id", value: alice}}, "carries no sub_id"},
		{"service grant with a consent", svcGrant, schema.Grant, []edit{{set: "/consent", value: "cns_01JBXR4Q8M2P4R6T8V0X2Z4B6D"}}, "rests on no consent"},

		{"consent expiring before it was given", consent, schema.Consent, []edit{{set: "/expires_at", value: "2026-10-30T09:00:00.000Z"}}, "expires_at must be after"},
		{"consent revoked before it was given", consent, schema.Consent, []edit{{set: "/status", value: "revoked"}, {set: "/revoked_by", value: "user"}, {set: "/revoked_at", value: "2026-10-30T09:00:00.000Z"}}, "revoked_at must lie between"},
		{"signed in after consenting", consent, schema.Consent, []edit{{set: "/auth/auth_time", value: "2026-10-30T09:30:00.000Z"}}, "cannot sign in after consenting"},

		{"allow with a failed check", allow, schema.Decision, []edit{{set: "/checks/1/result", value: "fail"}}, "cannot have failed checks"},
		{"deny with nothing failed", deny, schema.Decision, []edit{{set: "/checks/6/result", value: "pass"}}, "must have a failed check"},
		{"hold for another reason", hold, schema.Decision, []edit{{set: "/checks/6/result", value: "fail"}}, "fails the sensitivity check and nothing else"},
		{"check listed twice", allow, schema.Decision, []edit{{set: "/checks/1/name", value: "request"}}, `check "request" is listed twice`},
		{"user call without a consent", allow, schema.Decision, []edit{{del: "/grant/consent"}}, "rests on a consent"},
		{"service call with a consent", svcAllow, schema.Decision, []edit{{set: "/grant/consent", value: "cns_01JBXR4Q8M2P4R6T8V0X2Z4B6D"}}, "rests on no consent"},

		{"path segment without a param", manifest, schema.Manifest, []edit{{del: "/spec/operations/0/params"}}, "path segment {invoice_id} has no param"},
		{"path param not in the path", manifest, schema.Manifest, []edit{{set: "/spec/operations/0/params/~1extra", value: map[string]any{"type": "string", "in": "path"}}}, "param /extra is in the path"},
		{"operation declared twice", manifest, schema.Manifest, []edit{{set: "/spec/operations/1/name", value: "get_invoice"}}, `operation "get_invoice" is declared twice`},
		{"identity listed twice", agent, schema.Agent, []edit{{set: "/spec/identities", value: []any{
			map[string]any{"type": "oauth_client", "client_id": "acme-invoice-assistant"},
			map[string]any{"type": "oauth_client", "client_id": "acme-invoice-assistant"}}}}, "listed twice"},

		{"grant outliving the consent", mandate, schema.Mandate, []edit{{set: "/spec/consent/max_duration", value: "10m"}}, "longer than the consent"},
		{"service mandate with a monthly budget", svcMandate, schema.Mandate, []edit{{set: "/spec/limits/0/per", value: "month"}}, "no consent to share it across"},

		{"someone else voting on a user route", userAppr, schema.Approval, []edit{{set: "/votes/0/approver", value: bob}}, "only the user the agent acts for votes"},
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
	for _, f := range []string{"agent-invoice-assistant.yaml", "mandate-invoices.yaml"} {
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
	if len(srcs) != 2 || srcs[0].Kind != schema.Agent || srcs[1].Kind != schema.Mandate {
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
	if _, err := schema.Read("b.json", agentDoc, schema.Mandate); err == nil {
		t.Error("Agent read as Mandate")
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
	for in, want := range map[string]schema.Kind{"grant": schema.Grant, "MANDATE": schema.Mandate, "Decision": schema.Decision} {
		if got, err := schema.ParseKind(in); err != nil || got != want {
			t.Errorf("ParseKind(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := schema.ParseKind("task-type"); err == nil {
		t.Error("ParseKind accepted task-type")
	}
}
