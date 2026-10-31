package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/core"
	"github.com/vladmsnk/agentbox/internal/grant"
	"github.com/vladmsnk/agentbox/internal/ids"
	"github.com/vladmsnk/agentbox/internal/keys"
	"github.com/vladmsnk/agentbox/internal/policy"
	"github.com/vladmsnk/agentbox/internal/sealer"
	"github.com/vladmsnk/agentbox/internal/store"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

const grantUsage = `usage:
  agentbox grant mint [flags] CLAIMS     sign and record a grant (until the token service exists)
  agentbox grant verify [flags] TOKEN    run the grant's checks; TOKEN - reads stdin
`

func runGrant(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, grantUsage)
		return 2
	}
	switch args[0] {
	case "mint":
		return runGrantMint(args[1:], stdout, stderr)
	case "verify":
		return runGrantVerify(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "agentbox grant: unknown command %q\n\n%s", args[0], grantUsage)
		return 2
	}
}

// runGrantMint does what the token service will do once it exists: take a
// grant's claims, give them a fresh ID and lifetime, sign them with the
// box's active key and record the grant. It needs the database and the
// master key, so it grants nothing their holder could not already do.
func runGrantMint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("grant mint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("AGENTBOX_DB"), "PostgreSQL connection string (or AGENTBOX_DB)")
	masterKey := fs.String("master-key", os.Getenv("AGENTBOX_MASTER_KEY"), "master key (or AGENTBOX_MASTER_KEY)")
	issuer := fs.String("issuer", os.Getenv("AGENTBOX_ISSUER"), "iss of the grant (or AGENTBOX_ISSUER); default: the claims' own")
	ttl := fs.Duration("ttl", 15*time.Minute, "lifetime of the grant")
	consentFile := fs.String("consent", "", "Consent record to store first, for a grant to a user")
	singleUse := fs.Bool("single-use", false, "issue a single-use grant for one call, given by --action, --args and --aud")
	action := fs.String("action", "", "with --single-use: the operation of the one call")
	argsJSON := fs.String("args", "{}", "with --single-use: the call's arguments, a JSON object")
	aud := fs.String("aud", "", "with --single-use: the resource of the call; default: the grant's only audience")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: agentbox grant mint [flags] CLAIMS\n\nCLAIMS is a grant in JSON, such as examples/v0/grant/pay-invoice.json.\niat, exp and jti are replaced; the token goes to stdout.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	if *ttl <= 0 || *ttl > 24*time.Hour {
		fmt.Fprintln(stderr, "agentbox grant mint: --ttl must be between 1s and 24h")
		return 2
	}
	if *singleUse != (*action != "") {
		fmt.Fprintln(stderr, "agentbox grant mint: --single-use and --action go together")
		return 2
	}
	var bound core.Call
	if *singleUse {
		args, err := readArgs(*argsJSON)
		if err != nil {
			fmt.Fprintf(stderr, "agentbox grant mint: --args: %v\n", err)
			return 2
		}
		bound = core.Call{Resource: *aud, Action: *action, Arguments: args}
	}
	sl, err := sealer.Parse(*masterKey)
	if err != nil {
		fmt.Fprintf(stderr, "agentbox grant mint: --master-key or AGENTBOX_MASTER_KEY: %v\n", err)
		return 2
	}
	v, err := schema.NewValidator()
	if err != nil {
		fmt.Fprintf(stderr, "agentbox grant mint: %v\n", err)
		return 1
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "agentbox grant mint: "+format+"\n", a...)
		return 1
	}

	g, err := readClaims(v, fs.Arg(0))
	if err != nil {
		return fail("%v", err)
	}
	now := time.Now()
	if *issuer != "" {
		g.Issuer = *issuer
	}
	g.IssuedAt, g.Expiry = now.Unix(), now.Add(*ttl).Unix()
	g.ID = ids.At(ids.Grant, now)
	// One entry per operation, carrying all of its bounds, as every grant
	// the box issues has it.
	perms, err := policy.OnePerOperation(core.Permissions(g.AuthorizationDetails))
	if err != nil {
		return fail("claims: %v", err)
	}
	g.AuthorizationDetails = core.Details(perms)
	// Check the result as a verifier will.
	claims, err := json.Marshal(g)
	if err != nil {
		return fail("%v", err)
	}
	if g, err = schema.Decode[v0.Grant](v, claims); err != nil {
		return fail("claims: %v", err)
	}

	rec := store.GrantRecord{Grant: g, Agent: g.Actor.Subject}
	if *singleUse {
		if bound.Resource == "" {
			if len(g.Audience) != 1 {
				return fail("the grant has %d audiences: say which with --aud", len(g.Audience))
			}
			bound.Resource = g.Audience[0]
		}
		hash, err := bound.Hash()
		if err != nil {
			return fail("%v", err)
		}
		rec.SingleUse, rec.ActionHash = true, hash
	}

	ctx := context.Background()
	st, code, ok := openStore(ctx, *dsn, "grant mint", stderr)
	if !ok {
		return code
	}
	defer func() { _ = st.Close() }()

	if err := mintable(ctx, st, g); err != nil {
		return fail("%v", err)
	}
	if *consentFile != "" {
		c, err := readRecord[v0.Consent](v, *consentFile, schema.Consent)
		if err != nil {
			return fail("%v", err)
		}
		if c.ID != g.Consent {
			return fail("consent %s is not the one the grant names (%q)", c.ID, g.Consent)
		}
		if err := st.Consents().Create(ctx, c); err != nil && !errors.Is(err, store.ErrConflict) {
			return fail("consent %s: %v", c.ID, err)
		}
	}
	if g.Consent != "" {
		if err := consentFits(ctx, st, g); err != nil {
			return fail("%v", err)
		}
	}
	signer, err := keys.New(st.Keys(), sl).Ensure(ctx)
	if err != nil {
		return fail("signing key: %v", err)
	}
	tok, err := grant.Sign(signer, g)
	if err != nil {
		return fail("%v", err)
	}
	if err := st.Grants().Create(ctx, rec); err != nil {
		return fail("recording %s: %v", g.ID, err)
	}
	fmt.Fprintln(stdout, tok)
	if rec.SingleUse {
		fmt.Fprintf(stderr, "single-use: only %s at %s with these arguments, action hash %s\n", bound.Action, bound.Resource, rec.ActionHash)
	}
	fmt.Fprintf(stderr, "minted %s for %s via agent %s under mandate %s, key %s, expires %s\n",
		g.ID, g.Subject, g.Actor.Subject, g.Mandate, signer.KID, time.Unix(g.Expiry, 0).UTC().Format(time.RFC3339))
	return 0
}

// mintable refuses what the token service would: an agent that is not
// registered or is suspended, a mandate that does not exist or is disabled.
// Whether the mandate allows these permissions is the token service's
// job, not this command's.
func mintable(ctx context.Context, st store.Store, g v0.Grant) error {
	doc, err := st.Documents().Current(ctx, v0.KindAgent, g.Actor.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("agent %s is not registered; PUT it through the Admin API first", g.Actor.Subject)
	}
	if err != nil {
		return err
	}
	var a v0.Agent
	if err := json.Unmarshal(doc.Doc, &a); err != nil {
		return err
	}
	if a.Spec.Status == v0.AgentSuspended {
		return fmt.Errorf("agent %s is suspended", g.Actor.Subject)
	}
	m, err := st.Documents().Current(ctx, v0.KindMandate, g.Mandate)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("mandate %s does not exist", g.Mandate)
	}
	if err != nil {
		return err
	}
	if m.Disabled {
		return fmt.Errorf("mandate %s is disabled", g.Mandate)
	}
	return nil
}

// consentFits checks that a user grant rests on a recorded, active consent
// given to this agent for this mandate.
func consentFits(ctx context.Context, st store.Store, g v0.Grant) error {
	c, err := st.Consents().Get(ctx, g.Consent)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("consent %s is not recorded; a grant to a user rests on one: pass --consent FILE", g.Consent)
	}
	if err != nil {
		return err
	}
	switch {
	case c.Agent != g.Actor.Subject:
		return fmt.Errorf("consent %s was given to agent %s, not %s", c.ID, c.Agent, g.Actor.Subject)
	case c.Mandate != g.Mandate:
		return fmt.Errorf("consent %s is for mandate %s, not %s", c.ID, c.Mandate, g.Mandate)
	case c.Status != v0.ConsentActive:
		return fmt.Errorf("consent %s is %s", c.ID, c.Status)
	}
	return nil
}

func runGrantVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("grant verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("AGENTBOX_DB"), "PostgreSQL connection string (or AGENTBOX_DB)")
	issuer := fs.String("issuer", os.Getenv("AGENTBOX_ISSUER"), "the only iss accepted (or AGENTBOX_ISSUER); default: any")
	aud := fs.String("aud", "", "the resource being called; without it the audience check is skipped")
	action := fs.String("action", "", "an operation to check against the grant (needs --aud)")
	argsJSON := fs.String("args", "{}", "the operation's arguments, a JSON object")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: agentbox grant verify [flags] TOKEN\n\nRuns the grant's checks in the order a decision record lists them. TOKEN - reads it from stdin.\nWith --action, also checks that the call lies inside the grant and how risky it is.\nExit status: 0 accepted, 1 refused, 3 approval required.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	var call *core.Call
	if *action != "" {
		if *aud == "" {
			fmt.Fprintln(stderr, "agentbox grant verify: --action needs --aud, the resource being called")
			return 2
		}
		args, err := readArgs(*argsJSON)
		if err != nil {
			fmt.Fprintf(stderr, "agentbox grant verify: --args: %v\n", err)
			return 2
		}
		call = &core.Call{Resource: *aud, Action: *action, Arguments: args}
	}
	tok := fs.Arg(0)
	if tok == "-" {
		data, err := io.ReadAll(io.LimitReader(stdin, grant.MaxTokenSize+2))
		if err != nil {
			fmt.Fprintf(stderr, "agentbox grant verify: %v\n", err)
			return 1
		}
		tok = strings.TrimSpace(string(data))
	}
	v, err := schema.NewValidator()
	if err != nil {
		fmt.Fprintf(stderr, "agentbox grant verify: %v\n", err)
		return 1
	}
	ctx := context.Background()
	st, code, ok := openStore(ctx, *dsn, "grant verify", stderr)
	if !ok {
		return code
	}
	defer func() { _ = st.Close() }()

	verifier := &grant.Verifier{
		// Looking up public keys needs no master key.
		Keys:      keys.New(st.Keys(), nil),
		Status:    grant.StoreStatus{Store: st},
		Validator: v,
		Issuer:    *issuer,
	}
	held := false
	r, err := verifier.Verify(ctx, tok, *aud)
	if err != nil {
		fmt.Fprintf(stderr, "agentbox grant verify: %v\n", err)
	}
	if call != nil && r.OK() {
		m, err := manifestFor(ctx, st, v, call.Resource)
		if err != nil {
			fmt.Fprintf(stderr, "agentbox grant verify: %v\n", err)
			return 1
		}
		held, err = checkCall(&r, m, *call)
		if err != nil {
			fmt.Fprintf(stderr, "agentbox grant verify: %v\n", err)
			return 1
		}
	}
	if *asJSON {
		out, _ := json.MarshalIndent(struct {
			grant.Result
			ActionHash string `json:"action_hash,omitempty"`
			Held       bool   `json:"approval_required,omitempty"`
		}{r, actionHash(call), held}, "", "  ")
		fmt.Fprintln(stdout, string(out))
	} else {
		printResult(stdout, r, call, held)
	}
	switch {
	case !r.OK():
		return 1
	case held:
		return 3
	}
	return 0
}

// checkCall runs the call's checks after the grant's own: subset, then
// sensitivity. It reports whether the call is held for approval.
func checkCall(r *grant.Result, m v0.Manifest, call core.Call) (bool, error) {
	op := core.Operation(m, call.Action)
	check, reason := core.Subset(*r.Grant, op, call)
	r.Checks, r.Reason = append(r.Checks, check), reason
	if reason != nil {
		return false, nil
	}
	hash, err := call.Hash()
	if err != nil {
		return false, err
	}
	b := core.Binding{SingleUse: r.Standing.SingleUse, ActionHash: r.Standing.ActionHash}
	check, reason, held := core.Sensitivity(*op, r.Standing.Ceiling, b, hash)
	r.Checks, r.Reason = append(r.Checks, check), reason
	return held, nil
}

func actionHash(call *core.Call) string {
	if call == nil {
		return ""
	}
	h, _ := call.Hash()
	return h
}

func printResult(w io.Writer, r grant.Result, call *core.Call, held bool) {
	for _, c := range r.Checks {
		line := fmt.Sprintf("%-5s %-11s %s", c.Result, c.Name, c.Detail)
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	if call != nil {
		fmt.Fprintf(w, "action hash %s\n", actionHash(call))
	}
	if !r.OK() {
		fmt.Fprintf(w, "refused: %s\n", r.Reason.Code)
		return
	}
	if held {
		fmt.Fprintln(w, "approval required: a person approves this exact call, then a single-use grant bound to its hash runs it")
		return
	}
	g := r.Grant
	who := "user " + g.Subject
	if g.Subject == g.ClientID {
		who = "itself (service mandate)"
	}
	left := time.Until(time.Unix(g.Expiry, 0)).Round(time.Second)
	fmt.Fprintf(w, "accepted: grant %s, agent %s acting for %s, mandate %s, expires in %s\n", g.ID, g.Actor.Subject, who, g.Mandate, left)
}

// readClaims reads a grant's claims to mint from: the schema must hold,
// but the grant's rules run only on the grant as minted, once its entries
// are merged and its times and ID are set.
func readClaims(v *schema.Validator, name string) (v0.Grant, error) {
	var g v0.Grant
	data, err := os.ReadFile(name) // #nosec G304 -- reading the file the user named is the command's job
	if err != nil {
		return g, err
	}
	src, err := schema.Read(name, data, schema.Grant)
	if err != nil {
		return g, err
	}
	if len(src) != 1 {
		return g, fmt.Errorf("%s: want one grant, found %d documents", name, len(src))
	}
	if err := v.Validate(schema.Grant, src[0].JSON); err != nil {
		return g, err
	}
	dec := json.NewDecoder(strings.NewReader(string(src[0].JSON)))
	dec.DisallowUnknownFields()
	return g, dec.Decode(&g)
}

// readArgs decodes a call's arguments: one JSON object, no duplicate names.
func readArgs(s string) (map[string]any, error) {
	if err := schema.CheckDuplicateKeys([]byte(s)); err != nil {
		return nil, err
	}
	var args map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&args); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the object")
	}
	if args == nil {
		return nil, errors.New("want a JSON object")
	}
	return args, nil
}

// manifestFor finds the enabled manifest whose audience is aud.
func manifestFor(ctx context.Context, st store.Store, v *schema.Validator, aud string) (v0.Manifest, error) {
	docs, err := st.Documents().List(ctx, v0.KindManifest)
	if err != nil {
		return v0.Manifest{}, err
	}
	for _, d := range docs {
		if d.Disabled {
			continue
		}
		m, err := schema.Decode[v0.Manifest](v, d.Doc)
		if err != nil {
			return v0.Manifest{}, fmt.Errorf("manifest %s: %w", d.Name, err)
		}
		if m.Spec.Audience == aud {
			return m, nil
		}
	}
	return v0.Manifest{}, fmt.Errorf("no enabled manifest has audience %s", aud)
}

// readRecord reads one record of a kind from a JSON or YAML file and
// decodes it fully: schema, strict decoding, rules.
func readRecord[T schema.Document](v *schema.Validator, name string, kind schema.Kind) (T, error) {
	var zero T
	data, err := os.ReadFile(name) // #nosec G304 -- reading the file the user named is the command's job
	if err != nil {
		return zero, err
	}
	src, err := schema.Read(name, data, kind)
	if err != nil {
		return zero, err
	}
	if len(src) != 1 {
		return zero, fmt.Errorf("%s: want one %s, found %d documents", name, kind, len(src))
	}
	return schema.Decode[T](v, src[0].JSON)
}

func openStore(ctx context.Context, dsn, cmd string, stderr io.Writer) (*postgres.Store, int, bool) {
	if dsn == "" {
		fmt.Fprintf(stderr, "agentbox %s: --db or AGENTBOX_DB is required\n", cmd)
		return nil, 2, false
	}
	st, err := postgres.Open(ctx, dsn)
	if err != nil {
		fmt.Fprintf(stderr, "agentbox %s: %v\n", cmd, err)
		return nil, 1, false
	}
	return st, 0, true
}

// parseFlags parses and reports whether to go on, and if not, the exit code.
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	return 0, true
}
