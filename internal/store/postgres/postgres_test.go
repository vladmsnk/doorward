package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/store"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
)

// The tests need a real PostgreSQL: the chain lock, the version lock and the
// conditional counter update are what is being tested, and only the database
// can arbitrate them. Point AGENTBOX_TEST_POSTGRES_DSN at an empty database;
// without it the tests skip. Every package that uses the database truncates
// it first, so `make test` runs packages one at a time (-p 1).
func open(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("AGENTBOX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTBOX_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	s, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// Each test starts from an empty database.
	_, err = s.Pool().Exec(ctx, "TRUNCATE documents, consents, grants, decisions, approvals, counters")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func example[T any](t *testing.T, rel string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../examples/v0", rel))
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return v
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := open(t)
	if err := postgres.Migrate(context.Background(), s.Pool()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var n int
	if err := s.Pool().QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if want := len(postgres.Migrations()); n != want {
		t.Errorf("%d migrations recorded, want %d", n, want)
	}
}

func TestDocumentsAreVersioned(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	docs := s.Documents()

	v1, err := docs.Put(ctx, "Mandate", "invoices", []byte(`{"spec": {"ttl": "15m"}}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if v1.Version != 1 || v1.Digest == "" || string(v1.Doc) != `{"spec":{"ttl":"15m"}}` {
		t.Errorf("first version: %+v", v1)
	}
	v2, err := docs.Put(ctx, "Mandate", "invoices", []byte(`{"spec":{"ttl":"10m"}}`), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if v2.Version != 2 || v2.Digest == v1.Digest {
		t.Errorf("second version: %+v", v2)
	}

	cur, err := docs.Current(ctx, "Mandate", "invoices")
	if err != nil || cur.Version != 2 {
		t.Errorf("Current: %+v %v", cur, err)
	}
	if old, err := docs.Version(ctx, "Mandate", "invoices", 1); err != nil || string(old.Doc) != string(v1.Doc) {
		t.Errorf("Version 1: %+v %v", old, err)
	}
	if byDigest, err := docs.ByDigest(ctx, "Mandate", "invoices", v1.Digest); err != nil || byDigest.Version != 1 {
		t.Errorf("ByDigest: %+v %v", byDigest, err)
	}
	if hist, err := docs.History(ctx, "Mandate", "invoices"); err != nil || len(hist) != 2 || hist[0].Version != 1 {
		t.Errorf("History: %+v %v", hist, err)
	}
	if _, err := docs.Current(ctx, "Mandate", "nothing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing document: %v", err)
	}

	// Disabling is a new version with the same content.
	dis, err := docs.SetDisabled(ctx, "Mandate", "invoices", true, "admin")
	if err != nil || !dis.Disabled || dis.Version != 3 || dis.Digest != v2.Digest {
		t.Errorf("SetDisabled: %+v %v", dis, err)
	}
	again, _ := docs.SetDisabled(ctx, "Mandate", "invoices", true, "admin")
	if again.Version != 3 {
		t.Errorf("disabling twice added a version: %+v", again)
	}

	if _, err := docs.Put(ctx, "Agent", "reconciler", []byte(`{}`), "admin"); err != nil {
		t.Fatal(err)
	}
	list, err := docs.List(ctx, "Mandate")
	if err != nil || len(list) != 1 || list[0].Version != 3 {
		t.Errorf("List: %+v %v", list, err)
	}
	if _, err := docs.Put(ctx, "Agent", "x", []byte(`not json`), "admin"); err == nil {
		t.Error("non-JSON document accepted")
	}
}

// Concurrent writers get consecutive versions, never the same one.
func TestDocumentVersionsUnderConcurrency(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Documents().Put(ctx, "Agent", "a", []byte(fmt.Sprintf(`{"i":%d}`, i)), "t")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	hist, _ := s.Documents().History(ctx, "Agent", "a")
	if len(hist) != 20 || hist[19].Version != 20 {
		t.Errorf("%d versions, last %d", len(hist), hist[len(hist)-1].Version)
	}
}

func TestConsentsAndGrants(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c := example[v0.Consent](t, "consent/alice-invoice-assistant.json")
	if err := s.Consents().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.Consents().Create(ctx, c); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate consent: %v", err)
	}
	got, err := s.Consents().Get(ctx, c.ID)
	if err != nil || got.ID != c.ID || got.User != c.User {
		t.Fatalf("Get: %+v %v", got, err)
	}
	mine, _ := s.Consents().ByUser(ctx, c.User, true)
	if len(mine) != 1 {
		t.Errorf("ByUser: %d", len(mine))
	}

	g := example[v0.Grant](t, "grant/pay-invoice.json")
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: g, Agent: "invoice-assistant"}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Grants().Get(ctx, g.ID)
	if err != nil || rec.Grant.Subject != g.Subject || rec.Agent != "invoice-assistant" || rec.RevokedAt != nil {
		t.Fatalf("Get grant: %+v %v", rec, err)
	}

	// Revoking the consent revokes the grants resting on it. The example
	// grant expired long ago by the clock, so revoke "at" its issue time.
	at := time.Unix(g.IssuedAt+60, 0)
	revoked, err := s.Consents().Revoke(ctx, c.ID, v0.RevokedByUser, at)
	if err != nil || revoked.Status != v0.ConsentRevoked || revoked.RevokedAt == nil {
		t.Fatalf("Revoke: %+v %v", revoked, err)
	}
	if _, err := s.Consents().Revoke(ctx, c.ID, v0.RevokedByUser, at); !errors.Is(err, store.ErrState) {
		t.Errorf("second revoke: %v", err)
	}
	ids, err := s.Grants().RevokeByConsent(ctx, c.ID, at)
	if err != nil || len(ids) != 1 || ids[0] != g.ID {
		t.Fatalf("RevokeByConsent: %v %v", ids, err)
	}
	rec, _ = s.Grants().Get(ctx, g.ID)
	if rec.RevokedAt == nil {
		t.Error("grant not revoked")
	}
	if active, _ := s.Consents().ByUser(ctx, c.User, true); len(active) != 0 {
		t.Errorf("revoked consent still active: %d", len(active))
	}
}

func TestSingleUseGrantIsSpentOnce(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	g := example[v0.Grant](t, "grant/reconcile.json")
	g.ID = "grt_single_use_0001"
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: g, Agent: "reconciler", SingleUse: true, ActionHash: v0.Digest([]byte("call"))}); err != nil {
		t.Fatal(err)
	}
	if err := s.Grants().Spend(ctx, g.ID, time.Now()); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	if err := s.Grants().Spend(ctx, g.ID, time.Now()); !errors.Is(err, store.ErrState) {
		t.Errorf("second spend: %v", err)
	}
	if err := s.Grants().Spend(ctx, "grt_does_not_exist", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown grant: %v", err)
	}
}

func TestDecisionsChain(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Decisions().Head(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty journal head: %v", err)
	}
	var stored []v0.Decision
	for _, name := range []string{"1-allow-get-invoice", "2-deny-amount-over-grant", "3-approval-required-pay-invoice", "4-allow-reconciler-post-entry"} {
		d := example[v0.Decision](t, "decision/"+name+".json")
		d.Chain = nil
		out, err := s.Decisions().Append(ctx, d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		stored = append(stored, out)
	}
	if stored[0].Chain.Seq != 0 || stored[3].Chain.Seq != 3 || stored[3].Chain.Prev != stored[2].Chain.Hash {
		t.Errorf("chain not linked: %+v", stored[3].Chain)
	}
	all, err := s.Decisions().Range(ctx, 0, 100)
	if err != nil || len(all) != 4 {
		t.Fatalf("Range: %d %v", len(all), err)
	}
	if bad, err := v0.Verify(all); bad != -1 {
		t.Errorf("stored chain does not verify: %d %v", bad, err)
	}
	head, _ := s.Decisions().Head(ctx)
	if head.ID != stored[3].ID {
		t.Errorf("Head: %s", head.ID)
	}
	if got, err := s.Decisions().Get(ctx, stored[1].ID); err != nil || got.Outcome != v0.OutcomeDeny {
		t.Errorf("Get: %+v %v", got, err)
	}
}

// Parallel appends still produce one dense, verifiable chain.
func TestDecisionsChainUnderConcurrency(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	base := example[v0.Decision](t, "decision/1-allow-get-invoice.json")
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := base
			d.ID = fmt.Sprintf("dec_concurrent_%03d", i)
			d.Chain = nil
			if _, err := s.Decisions().Append(ctx, d); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	all, _ := s.Decisions().Range(ctx, 0, 100)
	if len(all) != 25 {
		t.Fatalf("%d records", len(all))
	}
	if bad, err := v0.Verify(all); bad != -1 {
		t.Errorf("chain broken at %d: %v", bad, err)
	}
}

func TestApprovalsLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	a := example[v0.Approval](t, "approval/write-off-rounding.json")
	votes := a.Votes
	a.Status, a.Closed, a.SingleUseGrant, a.Votes = v0.ApprovalPending, nil, "", []v0.Vote{}
	if err := s.Approvals().Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if pending, _ := s.Approvals().Pending(ctx); len(pending) != 1 {
		t.Errorf("Pending: %d", len(pending))
	}
	if _, err := s.Approvals().Vote(ctx, a.ID, votes[0]); err != nil {
		t.Fatalf("first vote: %v", err)
	}
	// The same person voting twice breaks the contract's rule; the store
	// enforces it through Check.
	if _, err := s.Approvals().Vote(ctx, a.ID, votes[0]); err == nil {
		t.Error("duplicate vote accepted")
	}
	// Approving with one vote when two are required is refused.
	if _, err := s.Approvals().Close(ctx, a.ID, v0.ApprovalApproved, votes[1].Time.Time, "grt_01JBXQ9D3F5H7K9M1P3R5T7V9X"); err == nil {
		t.Error("approved with too few votes")
	}
	if _, err := s.Approvals().Vote(ctx, a.ID, votes[1]); err != nil {
		t.Fatalf("second vote: %v", err)
	}
	closed, err := s.Approvals().Close(ctx, a.ID, v0.ApprovalApproved, votes[1].Time.Time, "grt_01JBXQ9D3F5H7K9M1P3R5T7V9X")
	if err != nil || closed.Status != v0.ApprovalApproved || closed.SingleUseGrant == "" {
		t.Fatalf("Close: %+v %v", closed, err)
	}
	if _, err := s.Approvals().Vote(ctx, a.ID, votes[0]); !errors.Is(err, store.ErrState) {
		t.Errorf("vote after close: %v", err)
	}
	if pending, _ := s.Approvals().Pending(ctx); len(pending) != 0 {
		t.Errorf("closed request still pending")
	}
}

func TestCountersNeverOverdraw(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	key := store.GrantKey("grt_x", "calls")

	remaining, err := s.Counters().Consume(ctx, key, 1, 3)
	if err != nil || remaining != 2 {
		t.Fatalf("first: %v %v", remaining, err)
	}
	if _, err := s.Counters().Consume(ctx, key, 5, 3); !errors.Is(err, store.ErrExhausted) {
		t.Errorf("overdraw: %v", err)
	}
	if v, _ := s.Counters().Consumed(ctx, key); v != 1 {
		t.Errorf("failed draw changed the counter: %v", v)
	}
	if _, err := s.Counters().Consume(ctx, store.ConsentKey("c", "payout", "2026-10"), 7000, 5000); !errors.Is(err, store.ErrExhausted) {
		t.Errorf("first draw over max: %v", err)
	}
	if v, _ := s.Counters().Consumed(ctx, store.ConsentKey("c", "payout", "2026-10")); v != 0 {
		t.Errorf("rejected first draw left %v", v)
	}

	// 100 parallel draws of 1 against a budget of 50: exactly 50 succeed.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Counters().Consume(ctx, store.GrantKey("grt_y", "calls"), 1, 50); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 50 {
		t.Errorf("%d draws succeeded, want 50", ok)
	}
}
