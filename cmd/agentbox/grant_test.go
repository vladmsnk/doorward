package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vladmsnk/agentbox/internal/sealer"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

// grantEnv gives a database holding the example configuration, and a
// master key.
func grantEnv(t *testing.T) (dsn, masterKey string) {
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
	defer func() { _ = st.Close() }()
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
	return dsn, masterKey
}

func TestGrantMintAndVerify(t *testing.T) {
	dsn, mk := grantEnv(t)
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
	code, tok, stderr := mint("--consent", "../../examples/v0/consent/alice-invoice-assistant.json", "../../examples/v0/grant/pay-invoice.json")
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
		"--consent", "../../examples/v0/consent/alice-invoice-assistant.json", "../../examples/v0/grant/pay-invoice.json")
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
