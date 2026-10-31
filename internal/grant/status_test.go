package grant_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/internal/store/postgres"
	"github.com/vladmsnk/doorward/schema"
)

func openStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("DOORWARD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("DOORWARD_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	s, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Pool().Exec(ctx, "TRUNCATE documents, consents, grants, decisions, approvals, counters, signing_keys, secrets"); err != nil {
		t.Fatal(err)
	}
	return s
}

func putDoc(t *testing.T, s store.Store, rel string) {
	t.Helper()
	data, err := os.ReadFile("../../examples/v0/" + rel)
	if err != nil {
		t.Fatal(err)
	}
	src, err := schema.Read(rel, data, "")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Metadata struct{ Name string } `json:"metadata"`
	}
	_ = json.Unmarshal(src[0].JSON, &meta)
	if _, err := s.Documents().Put(context.Background(), string(src[0].Kind), meta.Metadata.Name, src[0].JSON, "test"); err != nil {
		t.Fatal(err)
	}
}

func putAgent(t *testing.T, s store.Store, status v0.AgentStatus) {
	t.Helper()
	data, err := os.ReadFile("../../examples/v0/config/agent-invoice-assistant.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src, err := schema.Read("agent-invoice-assistant.yaml", data, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(src[0].JSON, &m)
	m["spec"].(map[string]any)["status"] = string(status)
	doc, _ := json.Marshal(m)
	if _, err := s.Documents().Put(context.Background(), v0.KindAgent, "invoice-assistant", doc, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestStoreStatus(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	f := setup(t)
	st := grant.StoreStatus{Store: s, Now: func() time.Time { return f.now }}
	putDoc(t, s, "config/mandate-invoices.yaml")

	standing := func(want string) {
		t.Helper()
		got, err := st.Standing(ctx, f.claims)
		if err != nil {
			t.Fatal(err)
		}
		if (want == "") != (got.Refusal == "") || !strings.Contains(got.Refusal, want) {
			t.Errorf("standing %q, want %q", got.Refusal, want)
		}
	}

	standing("no record of grant")
	// A user grant rests on a consent the box recorded first.
	data, err := os.ReadFile("../../examples/v0/consent/alice-invoice-assistant.json")
	if err != nil {
		t.Fatal(err)
	}
	consent, err := schema.Decode[v0.Consent](f.v.Validator, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Consents().Create(ctx, consent); err != nil {
		t.Fatal(err)
	}
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: f.claims, Agent: "invoice-assistant"}); err != nil {
		t.Fatal(err)
	}
	standing("agent invoice-assistant is not registered")
	putAgent(t, s, v0.AgentVerified)
	standing("")
	if got, _ := st.Standing(ctx, f.claims); got.Ceiling != v0.SensitivityCritical || got.SingleUse {
		t.Errorf("standing of a standing grant: %+v", got)
	}
	putAgent(t, s, v0.AgentSuspended)
	standing("agent invoice-assistant is suspended")
	putAgent(t, s, v0.AgentVerified)
	standing("")

	// The mandate and the consent the grant rests on are read too (P3).
	if _, err := s.Documents().SetDisabled(ctx, v0.KindMandate, "invoices", true, "test"); err != nil {
		t.Fatal(err)
	}
	standing("mandate invoices is disabled")
	if _, err := s.Documents().SetDisabled(ctx, v0.KindMandate, "invoices", false, "test"); err != nil {
		t.Fatal(err)
	}
	standing("")
	f.now = consent.ExpiresAt.Time
	standing("consent cns_01JBXR4Q8M2P4R6T8V0X2Z4B6D expired at 2026-11-29T09:29:45.000Z")
	f.now = time.Unix(f.claims.IssuedAt, 0).Add(5 * time.Minute)
	standing("")

	// A single-use grant stands, bound to its call, until it is spent.
	once := f.claims
	once.ID = "grt_01JBXR7D2F4H6K8M0P3R5T7V9X"
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: once, Agent: "invoice-assistant", SingleUse: true, ActionHash: "sha-256:" + strings.Repeat("a", 43)}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Standing(ctx, once)
	if err != nil || got.Refusal != "" || !got.SingleUse || got.ActionHash != "sha-256:"+strings.Repeat("a", 43) {
		t.Fatalf("single-use grant: %+v %v", got, err)
	}
	if err := s.Grants().Spend(ctx, once.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Standing(ctx, once); !strings.Contains(got.Refusal, "was used at") {
		t.Errorf("spent single-use grant: %+v", got)
	}

	if err := s.Grants().Revoke(ctx, f.claims.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	standing("was revoked at")

	// A grant whose consent was revoked fails, even if the grant itself
	// was missed when its consent's grants were revoked.
	if _, err := s.Consents().Revoke(ctx, consent.ID, v0.RevokedByUser, f.now); err != nil {
		t.Fatal(err)
	}
	other := f.claims
	other.ID = "grt_01JBXR9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z"
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: other, Agent: "invoice-assistant"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Standing(ctx, other); got.Refusal != "consent cns_01JBXR4Q8M2P4R6T8V0X2Z4B6D is revoked" {
		t.Errorf("grant on a revoked consent: %q", got.Refusal)
	}

	// Through the verifier: the record of a revoked grant ends at status.
	f.v.Status = st
	r, err := f.v.Verify(ctx, f.sign(t, f.claims), aud)
	if err != nil || r.OK() || r.Reason.Code != v0.ReasonGrantRevoked {
		t.Fatalf("%+v %v", r.Reason, err)
	}
}
