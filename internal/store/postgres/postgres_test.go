package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/internal/store/postgres"
)

// The tests need a real PostgreSQL: the chain lock, the version lock and the
// conditional counter update are what is being tested, and only the database
// can arbitrate them. Point DOORWARD_TEST_POSTGRES_DSN at an empty database;
// without it the tests skip. Every package that uses the database truncates
// it first, so `make test` runs packages one at a time (-p 1).
func open(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("DOORWARD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("DOORWARD_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	s, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// Each test starts from an empty database.
	_, err = s.Pool().Exec(ctx, "TRUNCATE documents, consents, grants, decisions, approvals, counters, signing_keys, secrets")
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

func TestKeysAndSecrets(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Keys().Active(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
	for _, kid := range []string{"k1", "k2"} {
		if err := s.Keys().Create(ctx, store.SigningKey{KID: kid, Alg: "ES256", PublicJWK: []byte(`{"kid":"` + kid + `"}`), PrivateEnc: []byte("sealed")}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond) // created_at orders them
	}
	if err := s.Keys().Create(ctx, store.SigningKey{KID: "k1", Alg: "ES256", PublicJWK: []byte(`{}`), PrivateEnc: []byte("x")}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate kid: %v", err)
	}
	if a, err := s.Keys().Active(ctx); err != nil || a.KID != "k2" {
		t.Fatalf("Active: %+v %v", a, err)
	}
	if err := s.Keys().Retire(ctx, "k2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.Keys().Active(ctx); a.KID != "k1" {
		t.Errorf("after retiring k2, active is %s", a.KID)
	}
	if all, _ := s.Keys().List(ctx); len(all) != 2 || all[0].KID != "k2" || all[0].RetiredAt == nil {
		t.Errorf("List: %+v", all)
	}

	if err := s.Secrets().Put(ctx, "ledger-mcp-api-key", []byte("sealed-1"), "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Secrets().Put(ctx, "ledger-mcp-api-key", []byte("sealed-2"), "admin"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Secrets().Get(ctx, "ledger-mcp-api-key"); err != nil || string(v) != "sealed-2" {
		t.Errorf("Get: %q %v", v, err)
	}
	if list, _ := s.Secrets().List(ctx); len(list) != 1 || list[0].Name != "ledger-mcp-api-key" {
		t.Errorf("List: %+v", list)
	}
	if err := s.Secrets().Delete(ctx, "ledger-mcp-api-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Secrets().Get(ctx, "ledger-mcp-api-key"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

// B4: budgets are exact, a call draws all of its budgets or none, and a
// single-use grant is spent with them, once.
func TestAllowIsExactAndAtomic(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	draw := func(key, amount, max string) store.Draw { return store.Draw{Key: key, Amount: amount, Max: max} }
	consumed := func(key string) string {
		t.Helper()
		v, err := s.Counters().Consumed(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Decimal amounts add up exactly: three draws of 0.10 fill 0.30.
	cents := store.ConsentKey("c", "payout", "2026-10")
	for i := 0; i < 3; i++ {
		d, err := s.Allow(ctx, store.Allowance{Draws: []store.Draw{draw(cents, "0.1", "0.3")}, At: now})
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		if want := []string{"0.2", "0.1", "0"}[i]; d[0].Remaining != want {
			t.Errorf("draw %d left %s, want %s", i, d[0].Remaining, want)
		}
	}
	_, err := s.Allow(ctx, store.Allowance{Draws: []store.Draw{draw(cents, "0.1", "0.3")}, At: now})
	var ex *store.ExhaustedError
	if !errors.As(err, &ex) || !errors.Is(err, store.ErrExhausted) || ex.Remaining != "0" {
		t.Fatalf("fourth draw: %v", err)
	}
	if v := consumed(cents); v != "0.3" {
		t.Errorf("consumed %s, want exactly 0.3", v)
	}

	// A first draw larger than the budget creates nothing.
	big := store.ConsentKey("c", "payout", "2026-11")
	if _, err := s.Allow(ctx, store.Allowance{Draws: []store.Draw{draw(big, "7000", "5000")}, At: now}); !errors.Is(err, store.ErrExhausted) {
		t.Errorf("first draw over max: %v", err)
	}
	if v := consumed(big); v != "0" {
		t.Errorf("a refused first draw left %s", v)
	}

	// All or nothing: the calls budget has room, the payout budget does not,
	// so neither is drawn.
	calls := store.GrantKey("grt_a", "calls")
	_, err = s.Allow(ctx, store.Allowance{Draws: []store.Draw{draw(calls, "1", "50"), draw(cents, "0.1", "0.3")}, At: now})
	if !errors.As(err, &ex) || ex.Key != cents {
		t.Fatalf("mixed draw: %v", err)
	}
	if v := consumed(calls); v != "0" {
		t.Errorf("the budget with room was drawn anyway: %s", v)
	}

	// A single-use grant is spent with its budgets, once, and not at all
	// when a budget refuses.
	g := example[v0.Grant](t, "grant/reconcile.json")
	g.ID = "grt_single_use_000000000001"
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: g, Agent: "reconciler", SingleUse: true, ActionHash: "sha-256:x"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Allow(ctx, store.Allowance{SingleUse: g.ID, Draws: []store.Draw{draw(cents, "0.1", "0.3")}, At: now})
	if !errors.Is(err, store.ErrExhausted) {
		t.Fatalf("single-use with an exhausted budget: %v", err)
	}
	if rec, _ := s.Grants().Get(ctx, g.ID); rec.UsedAt != nil {
		t.Error("the single-use grant was spent although its budget refused the call")
	}
	if _, err := s.Allow(ctx, store.Allowance{SingleUse: g.ID, Draws: []store.Draw{draw(calls, "1", "50")}, At: now}); err != nil {
		t.Fatalf("single-use: %v", err)
	}
	if _, err := s.Allow(ctx, store.Allowance{SingleUse: g.ID, Draws: []store.Draw{draw(calls, "1", "50")}, At: now}); !errors.Is(err, store.ErrState) {
		t.Errorf("single-use spent twice: %v", err)
	}
	if v := consumed(calls); v != "1" {
		t.Errorf("the refused second use drew %s", v)
	}

	// 100 parallel draws of 1 against a budget of 50: exactly 50 succeed.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Allow(ctx, store.Allowance{Draws: []store.Draw{draw(store.GrantKey("grt_y", "calls"), "1", "50")}, At: now}); err == nil {
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

	// Calls drawing the same two budgets, listed in opposite orders, do
	// not deadlock: budgets are always drawn in key order.
	k1, k2 := store.GrantKey("grt_z", "a"), store.GrantKey("grt_z", "b")
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ds := []store.Draw{draw(k1, "1", "1000"), draw(k2, "1", "1000")}
			if i%2 == 1 {
				ds[0], ds[1] = ds[1], ds[0]
			}
			if _, err := s.Allow(ctx, store.Allowance{Draws: ds, At: now}); err != nil {
				t.Errorf("draw %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if consumed(k1) != "40" || consumed(k2) != "40" {
		t.Errorf("after 40 calls: %s and %s", consumed(k1), consumed(k2))
	}
}

// B5: a decision and the spending it records commit together.
func TestSettle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	base := example[v0.Decision](t, "decision/1-allow-get-invoice.json")
	base.Chain = nil
	key := store.GrantKey("grt_settle", "calls")
	budget := &store.Allowance{Draws: []store.Draw{{Key: key, Amount: "1", Max: "1"}}, At: now}
	record := func(id string, outcome v0.Outcome) v0.Decision {
		d := base
		d.ID, d.Outcome = id, outcome
		return d
	}

	// Allowed: drawn and recorded.
	got, err := s.Settle(ctx, budget, func(drawn []store.Drawn, err error) (v0.Decision, error) {
		if err != nil || len(drawn) != 1 || drawn[0].Remaining != "0" {
			t.Errorf("first call: %v %v", drawn, err)
		}
		return record("dec_settle_allowed_000001", v0.OutcomeAllow), nil
	})
	if err != nil || got.Chain == nil || got.Chain.Seq != 0 {
		t.Fatalf("allowed: %+v %v", got.Chain, err)
	}
	// Refused by the budget: nothing drawn, the refusal recorded.
	got, err = s.Settle(ctx, budget, func(drawn []store.Drawn, err error) (v0.Decision, error) {
		if !errors.Is(err, store.ErrExhausted) || drawn != nil {
			t.Errorf("second call: %v %v", drawn, err)
		}
		return record("dec_settle_refused_000001", v0.OutcomeDeny), nil
	})
	if err != nil || got.Chain.Seq != 1 {
		t.Fatalf("refused: %+v %v", got.Chain, err)
	}
	if v, _ := s.Counters().Consumed(ctx, key); v != "1" {
		t.Errorf("the refused call drew: %s", v)
	}
	// A failure while deciding writes nothing at all.
	other := store.GrantKey("grt_settle", "other")
	if _, err := s.Settle(ctx, &store.Allowance{Draws: []store.Draw{{Key: other, Amount: "1", Max: "5"}}, At: now},
		func([]store.Drawn, error) (v0.Decision, error) { return v0.Decision{}, errors.New("boom") }); err == nil {
		t.Fatal("decide's error was swallowed")
	}
	if v, _ := s.Counters().Consumed(ctx, other); v != "0" {
		t.Errorf("an aborted settlement drew %s", v)
	}
	if head, _ := s.Decisions().Head(ctx); head.Chain.Seq != 1 {
		t.Errorf("an aborted settlement was recorded: seq %d", head.Chain.Seq)
	}
	// A spent single-use grant comes to decide as a refusal.
	g := example[v0.Grant](t, "grant/reconcile.json")
	g.ID = "grt_single_use_settle_0001"
	if err := s.Grants().Create(ctx, store.GrantRecord{Grant: g, Agent: "reconciler", SingleUse: true, ActionHash: "sha-256:x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Grants().Spend(ctx, g.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Settle(ctx, &store.Allowance{SingleUse: g.ID, At: now}, func(_ []store.Drawn, err error) (v0.Decision, error) {
		if !errors.Is(err, store.ErrState) {
			t.Errorf("spent single-use grant: %v", err)
		}
		return record("dec_settle_spent_00000001", v0.OutcomeDeny), nil
	}); err != nil {
		t.Fatal(err)
	}
	// The three records chain.
	all, err := s.Decisions().Range(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if broken, err := v0.Verify(all); err != nil || broken != -1 || len(all) != 3 {
		t.Errorf("chain of %d records: broken at %d: %v", len(all), broken, err)
	}
}

func TestPendingFor(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	a := example[v0.Approval](t, "approval/pay-invoice-1200-eur.json")
	a.Status, a.Closed, a.Votes, a.SingleUseGrant = v0.ApprovalPending, nil, []v0.Vote{}, ""
	// The approval names a consent, which must exist.
	if err := s.Consents().Create(ctx, example[v0.Consent](t, "consent/alice-invoice-assistant.json")); err != nil {
		t.Fatal(err)
	}
	if err := s.Approvals().Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := s.Approvals().PendingFor(ctx, a.Agent, a.Mandate, a.Consent, a.ActionHash)
	if err != nil || got.ID != a.ID {
		t.Fatalf("same call: %+v %v", got.ID, err)
	}
	// Q3: a second open request for the same call is refused by the store.
	dup := a
	dup.ID = "apr_duplicate_000000000001"
	if err := s.Approvals().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a second pending request for one call: %v", err)
	}
	// A different call, or a closed request, does not collide.
	other := a
	other.ID, other.ActionHash = "apr_other_call_00000000001", "sha-256:"+strings.Repeat("b", 43)
	if err := s.Approvals().Create(ctx, other); err != nil {
		t.Errorf("another call: %v", err)
	}
	if _, err := s.Approvals().PendingFor(ctx, a.Agent, a.Mandate, a.Consent, "sha-256:other"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another call: %v", err)
	}
	if _, err := s.Approvals().Close(ctx, a.ID, v0.ApprovalExpired, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approvals().PendingFor(ctx, a.Agent, a.Mandate, a.Consent, a.ActionHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a closed request still matches: %v", err)
	}
}

// holdChainLock takes the journal lock on a connection of its own and
// returns a function that releases it.
func holdChainLock(t testing.TB, s *postgres.Store) func() {
	t.Helper()
	ctx := context.Background()
	conn, err := s.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", postgres.ChainLock); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", postgres.ChainLock)
			conn.Release()
		})
	}
}

// Q1: a settlement that cannot get the journal in time is rolled back
// within the caller's deadline, drawing and recording nothing.
func TestSettleHonoursTheDeadline(t *testing.T) {
	s := open(t)
	release := holdChainLock(t, s)
	defer release()
	key := store.GrantKey("grt_deadline", "calls")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	base := example[v0.Decision](t, "decision/1-allow-get-invoice.json")
	base.Chain = nil
	start := time.Now()
	_, err := s.Settle(ctx, &store.Allowance{Draws: []store.Draw{{Key: key, Amount: "1", Max: "10"}}, At: time.Now()},
		func([]store.Drawn, error) (v0.Decision, error) { return base, nil })
	took := time.Since(start)
	if !errors.Is(err, store.ErrTimeout) {
		t.Fatalf("got %v after %s, want ErrTimeout", err, took)
	}
	if took > 2*time.Second {
		t.Errorf("took %s to give up on a 300ms deadline", took)
	}
	release()
	if v, _ := s.Counters().Consumed(context.Background(), key); v != "0" {
		t.Errorf("the timed-out settlement drew %s", v)
	}
	if _, err := s.Decisions().Head(context.Background()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the timed-out settlement was recorded: %v", err)
	}
	// With the lock free, the same settlement goes through.
	if _, err := s.Settle(context.Background(), &store.Allowance{Draws: []store.Draw{{Key: key, Amount: "1", Max: "10"}}, At: time.Now()},
		func([]store.Drawn, error) (v0.Decision, error) { return base, nil }); err != nil {
		t.Fatal(err)
	}
}
