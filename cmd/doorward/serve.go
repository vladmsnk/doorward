package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/admin"
	"github.com/vladmsnk/doorward/internal/config"
	"github.com/vladmsnk/doorward/internal/gateway"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/keys"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/internal/store/postgres"
	"github.com/vladmsnk/doorward/internal/telemetry"
	"github.com/vladmsnk/doorward/schema"
)

// defaultAdminAddr keeps the Admin API off the network unless an operator
// opens it: one token authorizes every change to the configuration.
const defaultAdminAddr = "127.0.0.1:8081"

// runServe starts the box: a public listener (health, the JWK Set; the
// token service and the gateway join it in later steps) and the Admin API
// on its own port, so the two can be exposed differently.
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("DOORWARD_DB"), "PostgreSQL connection string (or DOORWARD_DB)")
	masterKey := fs.String("master-key", os.Getenv("DOORWARD_MASTER_KEY"), "32-byte key, hex or base64, that seals private keys and secrets (or DOORWARD_MASTER_KEY)")
	addr := fs.String("addr", ":8080", "address of the public listener")
	adminAddr := fs.String("admin-addr", defaultAdminAddr, "address of the Admin API; it changes configuration, so it listens on this machine only unless told otherwise")
	adminToken := fs.String("admin-token", os.Getenv("DOORWARD_ADMIN_TOKEN"), "bootstrap administrator token (or DOORWARD_ADMIN_TOKEN)")
	issuer := fs.String("issuer", os.Getenv("DOORWARD_ISSUER"), "the only grant issuer accepted (or DOORWARD_ISSUER); default: any grant this box signed")
	pdpID := fs.String("pdp-id", "doorward", "this decision point's name in decision records")
	gatewayID := fs.String("gateway-id", "gateway", "the built-in MCP gateway's name in decision records")
	gatewayOrigins := fs.String("gateway-origins", os.Getenv("DOORWARD_GATEWAY_ORIGINS"), "browser origins allowed to reach the MCP gateway besides its own host, comma-separated (or DOORWARD_GATEWAY_ORIGINS)")
	shutdownDelay := fs.Duration("shutdown-delay", 0, "on SIGTERM, keep serving for this long while /healthz reports 503, so a load balancer stops sending before the listeners close; 5s is usual behind one")
	decisionTimeout := fs.Duration("decision-timeout", pdp.DefaultTimeout, "how long one decision may take, the wait for the journal included; a decision that runs out of time is refused and nothing is recorded")
	journalPath := fs.String("journal", os.Getenv("DOORWARD_JOURNAL"), `file that receives every decision record as one JSON line, "-" for standard output (or DOORWARD_JOURNAL)`)
	var peps []pdp.Client
	pepFlag := func(v string) error {
		c, err := parsePEP(v)
		if err == nil {
			peps = append(peps, c)
		}
		return err
	}
	fs.Func("pep", "a point of enforcement allowed to ask for decisions, as ID=TOKEN; repeat for several (or DOORWARD_PEPS, comma-separated)", pepFlag)
	if env := os.Getenv("DOORWARD_PEPS"); env != "" {
		for _, v := range strings.Split(env, ",") {
			if err := pepFlag(strings.TrimSpace(v)); err != nil {
				fmt.Fprintf(stderr, "doorward serve: DOORWARD_PEPS: %v\n", err)
				return 2
			}
		}
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *dsn == "" {
		fmt.Fprintln(stderr, "doorward serve: --db or DOORWARD_DB is required")
		return 2
	}
	if *decisionTimeout <= 0 || *decisionTimeout > 20*time.Second {
		fmt.Fprintln(stderr, "doorward serve: --decision-timeout must be between 1ms and 20s, under the 30s HTTP write timeout")
		return 2
	}
	if len(*adminToken) < 16 {
		fmt.Fprintln(stderr, "doorward serve: --admin-token or DOORWARD_ADMIN_TOKEN must be at least 16 characters")
		return 2
	}
	sl, err := sealer.Parse(*masterKey)
	if err != nil {
		fmt.Fprintf(stderr, "doorward serve: --master-key or DOORWARD_MASTER_KEY: %v (generate one with: doorward master-key)\n", err)
		return 2
	}

	// The journal file is opened before the store, so a bad path fails fast.
	var journalFile *os.File
	switch *journalPath {
	case "", "-":
	default:
		f, err := os.OpenFile(*journalPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600) // #nosec G304 -- the operator names the journal file
		if err != nil {
			fmt.Fprintf(stderr, "doorward serve: --journal: %v\n", err)
			return 2
		}
		defer func() { _ = f.Close() }()
		journalFile = f
	}

	// Warnings and errors are sampled: one line per message per second, with
	// a count of the rest, so an outage does not flood the log.
	log := slog.New(telemetry.Sampled(slog.NewJSONHandler(stdout, nil), time.Second))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := postgres.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(stderr, "doorward serve: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	v, err := schema.NewValidator()
	if err != nil {
		fmt.Fprintf(stderr, "doorward serve: %v\n", err)
		return 1
	}

	km := keys.New(st.Keys(), sl)
	signer, err := km.Ensure(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "doorward serve: signing key: %v\n", err)
		return 1
	}

	var stopping atomic.Bool
	healthz := func(w http.ResponseWriter, r *http.Request) {
		if stopping.Load() {
			http.Error(w, "stopping", http.StatusServiceUnavailable)
			return
		}
		if err := st.Pool().Ping(r.Context()); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	}

	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", healthz)
	public.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		set, err := km.JWKS(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(set)
	})

	tp, stopTracing, err := telemetry.Setup(ctx, "doorward", versionString())
	if err != nil {
		fmt.Fprintf(stderr, "doorward serve: OpenTelemetry: %v\n", err)
		return 1
	}
	defer func() { _ = stopTracing(context.Background()) }()

	// The journal follower copies every committed record, from any
	// instance, to the file in order: a file resumes where it ended, and
	// standard output starts at the current head.
	var follower *journal.Follower
	if *journalPath != "" {
		var from uint64
		out := stdout
		if journalFile != nil {
			if from, err = journal.Resume(journalFile); err != nil {
				fmt.Fprintf(stderr, "doorward serve: --journal: %v\n", err)
				return 2
			}
			out = journalFile
		} else if head, err := st.Decisions().Head(ctx); err == nil {
			from = head.Chain.Seq + 1
		} else if !errors.Is(err, store.ErrNotFound) {
			fmt.Fprintf(stderr, "doorward serve: %v\n", err)
			return 1
		}
		follower = journal.New(st.Decisions(), out, from, 0, log)
		go follower.Run(ctx)
		log.Info("journal follower started", "from_seq", from, "to", *journalPath)
	}

	cfg := &config.Cache{Store: st, Validator: v, Log: log}
	decisions := &pdp.PDP{
		Store:  st,
		Config: cfg,
		Verifier: &grant.Verifier{
			Keys:      km,
			Status:    grant.StoreStatus{Store: st, Config: pdp.StatusConfig(cfg)},
			Validator: v,
			Issuer:    *issuer,
		},
		ID:      *pdpID,
		Version: versionString(),
		Log:     log,
		Tracer:  tp.Tracer("doorward"),
		Timeout: *decisionTimeout,
	}
	if follower != nil {
		decisions.Journal = follower
	}
	public.Handle("POST "+pdp.EvaluationPath, decisions.Handler(peps))
	mcp := &gateway.Gateway{
		Config: cfg, PDP: decisions, Verifier: decisions.Verifier, Secrets: st.Secrets(), Sealer: sl,
		ID: *gatewayID, Log: log, Origins: splitList(*gatewayOrigins),
	}
	public.Handle(gateway.Prefix, mcp.Handler())

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", healthz)
	api := &admin.Server{Store: st, Validator: v, Token: *adminToken, Sealer: sl, Keys: km, Log: log}
	adminMux.Handle("/admin/", api.Handler())

	newServer := func(addr string, h http.Handler, writeTimeout time.Duration) *http.Server {
		return &http.Server{
			Addr: addr, Handler: h,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: writeTimeout, IdleTimeout: 2 * time.Minute,
		}
	}
	// The public listener carries the gateway's event streams, which a
	// write deadline would cut off mid-call, so it has none; the slow-client
	// guards that remain are the read and idle timeouts. The admin listener
	// serves only short request-response calls and keeps a write deadline.
	servers := []*http.Server{newServer(*addr, public, 0), newServer(*adminAddr, adminMux, 30*time.Second)}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) { errc <- srv.ListenAndServe() }(srv)
	}
	log.Info("doorward serving", "version", versionString(), "addr", *addr, "admin_addr", *adminAddr, "kid", signer.KID, "points_of_enforcement", len(peps))

	select {
	case <-ctx.Done():
		stopping.Store(true)
		log.Info("shutting down", "delay", shutdownDelay.String())
		if *shutdownDelay > 0 {
			// Health already says 503; keep answering while the load
			// balancer notices.
			time.Sleep(*shutdownDelay)
		}
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "doorward serve: %v\n", err)
			return 1
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "doorward serve: shutdown: %v\n", err)
			return 1
		}
	}
	if follower != nil {
		if err := follower.Close(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "doorward serve: journal: %v\n", err)
			return 1
		}
	}
	return 0
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parsePEP reads a point of enforcement as ID=TOKEN.
func parsePEP(v string) (pdp.Client, error) {
	id, token, ok := strings.Cut(v, "=")
	switch {
	case !ok || !nameRE.MatchString(id):
		return pdp.Client{}, fmt.Errorf("%q: want ID=TOKEN, the ID lower case letters, digits, '.', '_' and '-'", v)
	case len(token) < 16:
		return pdp.Client{}, fmt.Errorf("point of enforcement %s: the token must be at least 16 characters", id)
	}
	return pdp.Client{Token: token, PEP: v0.PEP{ID: id, Kind: v0.PEPGateway}}, nil
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

// runMasterKey prints a fresh master key for an operator setting up a box.
func runMasterKey(stdout, stderr io.Writer) int {
	k, err := sealer.Generate()
	if err != nil {
		fmt.Fprintf(stderr, "doorward master-key: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, k)
	return 0
}
