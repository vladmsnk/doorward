package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/sealer"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

// grantEnv gives a database holding the example configuration, and a
// master key.
func grantEnv(t *testing.T) (dsn, masterKey string, st *postgres.Store) {
	t.Helper()
	dsn = os.Getenv("AGENTBOX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTBOX_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	st, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.Pool().Exec(ctx, "TRUNCATE documents, consents, grants, decisions, approvals, counters, signing_keys, secrets"); err != nil {
		t.Fatal(err)
	}
	// The store checks nothing but shape, so the documents go in directly;
	// the Admin API's rules have their own tests.
	for _, f := range []string{"manifest-payments-api.yaml", "mandate-invoices.yaml", "mandate-reconcile.yaml", "agent-invoice-assistant.yaml", "agent-reconciler.yaml"} {
		data, err := os.ReadFile(filepath.Join("../../examples/v0/config", f))
		if err != nil {
			t.Fatal(err)
		}
		src, err := schema.Read(f, data, "")
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Metadata struct{ Name string } `json:"metadata"`
		}
		if err := json.Unmarshal(src[0].JSON, &meta); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Documents().Put(ctx, string(src[0].Kind), meta.Metadata.Name, src[0].JSON, "test"); err != nil {
			t.Fatal(err)
		}
	}
	masterKey, err = sealer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return dsn, masterKey, st
}

const aliceConsent = "cns_01JBXR4Q8M2P4R6T8V0X2Z4B6D"

// writeConsent writes a copy of the example consent with another ID and
// times relative to now, so the test does not depend on the example's
// dates.
func writeConsent(t *testing.T, id string, grantedAgo, validFor time.Duration) string {
	t.Helper()
	data, err := os.ReadFile("../../examples/v0/consent/alice-invoice-assistant.json")
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	granted := time.Now().Add(-grantedAgo)
	c["id"] = id
	c["granted_at"] = v0.Timestamp{Time: granted}
	c["expires_at"] = v0.Timestamp{Time: granted.Add(validFor)}
	c["auth"].(map[string]any)["auth_time"] = v0.Timestamp{Time: granted.Add(-time.Minute)}
	return writeJSON(t, id+".json", c)
}

// writeClaims writes a copy of the example user grant, changed by edit.
func writeClaims(t *testing.T, name string, edit func(g map[string]any)) string {
	t.Helper()
	data, err := os.ReadFile("../../examples/v0/grant/pay-invoice.json")
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]any
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	edit(g)
	return writeJSON(t, name, g)
}

func writeJSON(t *testing.T, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// payBounds edits a grant's pay_invoice entry.
func payBounds(max float64) func(g map[string]any) {
	return func(g map[string]any) {
		for _, d := range g["authorization_details"].([]any) {
			e := d.(map[string]any)
			if c, ok := e["constraints"].(map[string]any); ok {
				c["/amount"].(map[string]any)["max"] = max
			}
		}
	}
}

func TestGrantMintAndVerify(t *testing.T) {
	dsn, mk, st := grantEnv(t)
	ctx := context.Background()
	consent := writeConsent(t, aliceConsent, time.Minute, 30*24*time.Hour)
	const payments = "https://payments.example.internal"
	mint := func(args ...string) (int, string, string) {
		return runCLI(append([]string{"grant", "mint", "--db", dsn, "--master-key", mk}, args...)...)
	}
	verify := func(args ...string) (int, string, string) {
		return runCLI(append([]string{"grant", "verify", "--db", dsn}, args...)...)
	}

	// A user grant needs its consent.
	code, _, stderr := mint("../../examples/v0/grant/pay-invoice.json")
	if code != 1 || !strings.Contains(stderr, "pass --consent FILE") {
		t.Fatalf("mint without consent: %d %s", code, stderr)
	}
	code, tok, stderr := mint("--consent", consent, "../../examples/v0/grant/pay-invoice.json")
	if code != 0 {
		t.Fatalf("mint: %d %s", code, stderr)
	}
	tok = strings.TrimSpace(tok)

	code, out, _ := verify("--aud", payments, tok)
	if code != 0 || !strings.Contains(out, "accepted: grant grt_") || !strings.Contains(out, "skip  pop") {
		t.Fatalf("verify: %d\n%s", code, out)
	}
	code, out, _ = verify("--aud", "https://ledger.example.internal", tok)
	if code != 1 || !strings.Contains(out, "refused: audience_mismatch") {
		t.Fatalf("verify other audience: %d\n%s", code, out)
	}
	// With a call: the subset check runs after the grant's own checks.
	// A payment inside the grant is critical: it is held for approval.
	const payArgs = `{"invoice_id":"inv_1","amount":1200,"currency":"EUR"}`
	code, out, _ = verify("--aud", payments, "--action", "pay_invoice", "--args", payArgs, tok)
	if code != 3 || !strings.Contains(out, "pass  subset") || !strings.Contains(out, "fail  sensitivity critical tier needs a single-use grant") ||
		!strings.Contains(out, "approval required") {
		t.Fatalf("verify a payment inside the grant: %d\n%s", code, out)
	}
	// A read runs.
	code, out, _ = verify("--aud", payments, "--action", "get_invoice", "--args", `{"invoice_id":"inv_1"}`, tok)
	if code != 0 || !strings.Contains(out, "pass  sensitivity") {
		t.Fatalf("verify a read: %d\n%s", code, out)
	}
	// Once approved, a single-use grant runs that exact call and nothing else.
	code, once, stderr := mint("--single-use", "--action", "pay_invoice", "--args", payArgs,
		"--consent", consent, "../../examples/v0/grant/pay-invoice.json")
	if code != 0 || !strings.Contains(stderr, "single-use: only pay_invoice at "+payments) {
		t.Fatalf("mint a single-use grant: %d %s", code, stderr)
	}
	once = strings.TrimSpace(once)
	code, out, _ = verify("--aud", payments, "--action", "pay_invoice", "--args", `{"currency":"EUR","amount":1.2e3,"invoice_id":"inv_1"}`, once)
	if code != 0 || !strings.Contains(out, "single-use grant for this exact call") {
		t.Fatalf("verify the approved call, written another way: %d\n%s", code, out)
	}
	code, out, _ = verify("--aud", payments, "--action", "pay_invoice", "--args", `{"invoice_id":"inv_1","amount":1201,"currency":"EUR"}`, once)
	if code != 1 || !strings.Contains(out, "issued for another call") {
		t.Fatalf("verify another call on the single-use grant: %d\n%s", code, out)
	}
	if code, _, _ := mint("--single-use", "../../examples/v0/grant/pay-invoice.json"); code != 2 {
		t.Errorf("--single-use without --action: %d", code)
	}
	code, out, _ = verify("--aud", payments, "--action", "pay_invoice", "--args", `{"invoice_id":"inv_1","amount":7500,"currency":"EUR"}`, tok)
	if code != 1 || !strings.Contains(out, "fail  subset      /amount") || !strings.Contains(out, "refused: constraint_violated") {
		t.Fatalf("verify a payment over the grant: %d\n%s", code, out)
	}
	code, out, _ = verify("--aud", payments, "--action", "refund_payment", tok)
	if code != 1 || !strings.Contains(out, "refused: action_not_granted") {
		t.Fatalf("verify an operation outside the grant: %d\n%s", code, out)
	}
	if code, _, _ := verify("--action", "pay_invoice", tok); code != 2 {
		t.Errorf("--action without --aud: %d", code)
	}
	if code, _, _ := verify("--aud", payments, "--action", "pay_invoice", "--args", `{"amount":1,"amount":2}`, tok); code != 2 {
		t.Errorf("duplicate argument names: %d", code)
	}

	code, out, _ = verify("--json", "--issuer", "https://other.example", tok)
	if code != 1 || !strings.Contains(out, `"code": "grant_malformed"`) {
		t.Fatalf("verify other issuer: %d\n%s", code, out)
	}

	// A service grant needs no consent.
	code, tok, stderr = mint("--ttl", "1m", "--issuer", "https://box.example.internal", "../../examples/v0/grant/reconcile.json")
	if code != 0 {
		t.Fatalf("mint service grant: %d %s", code, stderr)
	}
	code, out, _ = verify("--issuer", "https://box.example.internal", strings.TrimSpace(tok))
	if code != 0 || !strings.Contains(out, "acting for itself") {
		t.Fatalf("verify service grant: %d\n%s", code, out)
	}

	// Claims that name an operation in two entries are merged on mint: the
	// grant carries pay_invoice once, with its bounds.
	data, err := os.ReadFile("../../examples/v0/grant/pay-invoice.json")
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(t.TempDir(), "old-shape.json")
	if err := os.WriteFile(old, []byte(strings.Replace(string(data), `"actions": ["get_invoice", "list_payments"]`, `"actions": ["get_invoice", "list_payments", "pay_invoice"]`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, merged, stderr := mint(old)
	if code != 0 {
		t.Fatalf("mint from the old shape: %d %s", code, stderr)
	}
	code, out, _ = verify("--json", strings.TrimSpace(merged))
	var res struct {
		Grant struct {
			Details []struct{ Actions []string } `json:"authorization_details"`
		} `json:"grant"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != 0 {
		t.Fatalf("merged grant: %d %v\n%s", code, err, out)
	}
	n := 0
	for _, d := range res.Grant.Details {
		for _, a := range d.Actions {
			if a == "pay_invoice" {
				n++
			}
		}
	}
	if n != 1 {
		t.Errorf("pay_invoice is in %d entries: %+v", n, res.Grant.Details)
	}

	// P3: the consent is checked fully.
	expired := writeConsent(t, "cns_expired_000000000001", 40*24*time.Hour, 30*24*time.Hour)
	onExpired := writeClaims(t, "on-expired.json", func(g map[string]any) { g["consent"] = "cns_expired_000000000001" })
	if code, _, stderr := mint("--consent", expired, onExpired); code != 1 || !strings.Contains(stderr, "consent cns_expired_000000000001 expired at") {
		t.Errorf("mint on an expired consent: %d %s", code, stderr)
	}
	// A grant never outlives its consent.
	short := writeConsent(t, "cns_short_00000000000001", time.Minute, 5*time.Minute)
	onShort := writeClaims(t, "on-short.json", func(g map[string]any) { g["consent"] = "cns_short_00000000000001" })
	code, tok, stderr = mint("--ttl", "15m", "--consent", short, onShort)
	if code != 0 {
		t.Fatalf("mint on a short consent: %d %s", code, stderr)
	}
	code, out, _ = verify("--json", strings.TrimSpace(tok))
	var capped struct {
		Grant struct{ Exp int64 } `json:"grant"`
	}
	if err := json.Unmarshal([]byte(out), &capped); err != nil || code != 0 {
		t.Fatalf("verify the capped grant: %d %v\n%s", code, err, out)
	}
	if left := time.Until(time.Unix(capped.Grant.Exp, 0)); left > 5*time.Minute {
		t.Errorf("grant outlives its consent by %s", left-5*time.Minute)
	}
	// A grant wider than the mandate is refused.
	if code, _, stderr := mint(writeClaims(t, "wide.json", payBounds(8000))); code != 1 || !strings.Contains(stderr, "mandate invoices") {
		t.Errorf("mint wider than the mandate: %d %s", code, stderr)
	}
	// The mandate is widened after Alice consented: the current mandate
	// allows 8000, but Alice agreed to 5000.
	mdoc, err := st.Documents().Current(ctx, v0.KindMandate, "invoices")
	if err != nil {
		t.Fatal(err)
	}
	wider := strings.Replace(string(mdoc.Doc), `"/amount":{"max":5000,`, `"/amount":{"max":8000,`, 1)
	if wider == string(mdoc.Doc) {
		t.Fatalf("the mandate's amount bound is not where the test expects it: %s", mdoc.Doc)
	}
	if _, err := st.Documents().Put(ctx, v0.KindMandate, "invoices", []byte(wider), "test"); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := mint(writeClaims(t, "wide.json", payBounds(8000))); code != 1 || !strings.Contains(stderr, "as consented to in "+aliceConsent+" (version 1)") {
		t.Errorf("mint beyond the consented version: %d %s", code, stderr)
	}
	// Within both versions it still mints.
	if code, _, stderr := mint("../../examples/v0/grant/pay-invoice.json"); code != 0 {
		t.Errorf("mint within both versions: %d %s", code, stderr)
	}
	// A disabled mandate fails the status check of grants already issued.
	if _, err := st.Documents().SetDisabled(ctx, v0.KindMandate, "invoices", true, "test"); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := verify(once); code != 1 || !strings.Contains(out, "mandate invoices is disabled") {
		t.Errorf("verify under a disabled mandate: %d\n%s", code, out)
	}

	// Usage errors.
	if code, _, _ := runCLI("grant"); code != 2 {
		t.Errorf("grant with no command: %d", code)
	}
	if code, _, _ := runCLI("grant", "verify", "--db", dsn); code != 2 {
		t.Errorf("verify with no token: %d", code)
	}
	if code, _, _ := mint("--ttl", "48h", "../../examples/v0/grant/reconcile.json"); code != 2 {
		t.Errorf("mint with a 48h ttl: %d", code)
	}
}
