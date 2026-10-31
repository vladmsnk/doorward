package grant_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/grant"
	"github.com/vladmsnk/agentbox/internal/store"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

func openStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("AGENTBOX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTBOX_TEST_POSTGRES_DSN not set")
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
	st := grant.StoreStatus{Store: s}

	standing := func(want string) {
		t.Helper()
		got, err := st.Standing(ctx, f.claims)
		if err != nil {
			t.Fatal(err)
		}
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("standing %q, want %q", got, want)
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
	putAgent(t, s, v0.AgentSuspended)
	standing("agent invoice-assistant is suspended")
	putAgent(t, s, v0.AgentVerified)
	standing("")
	if err := s.Grants().Revoke(ctx, f.claims.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	standing("was revoked at")

	// Through the verifier: the record of a revoked grant ends at status.
	f.v.Status = st
	r, err := f.v.Verify(ctx, f.sign(t, f.claims), aud)
	if err != nil || r.OK() || r.Reason.Code != v0.ReasonGrantRevoked {
		t.Fatalf("%+v %v", r.Reason, err)
	}
}
