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
	"syscall"
	"time"

	"github.com/vladmsnk/agentbox/internal/admin"
	"github.com/vladmsnk/agentbox/internal/keys"
	"github.com/vladmsnk/agentbox/internal/sealer"
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

// runServe starts the box: a public listener (health, the JWK Set; the
// token service and the gateway join it in later steps) and the Admin API
// on its own port, so the two can be exposed differently.
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("AGENTBOX_DB"), "PostgreSQL connection string (or AGENTBOX_DB)")
	masterKey := fs.String("master-key", os.Getenv("AGENTBOX_MASTER_KEY"), "32-byte key, hex or base64, that seals private keys and secrets (or AGENTBOX_MASTER_KEY)")
	addr := fs.String("addr", ":8080", "address of the public listener")
	adminAddr := fs.String("admin-addr", ":8081", "address of the Admin API")
	adminToken := fs.String("admin-token", os.Getenv("AGENTBOX_ADMIN_TOKEN"), "bootstrap administrator token (or AGENTBOX_ADMIN_TOKEN)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *dsn == "" {
		fmt.Fprintln(stderr, "agentbox serve: --db or AGENTBOX_DB is required")
		return 2
	}
	if len(*adminToken) < 16 {
		fmt.Fprintln(stderr, "agentbox serve: --admin-token or AGENTBOX_ADMIN_TOKEN must be at least 16 characters")
		return 2
	}
	sl, err := sealer.Parse(*masterKey)
	if err != nil {
		fmt.Fprintf(stderr, "agentbox serve: --master-key or AGENTBOX_MASTER_KEY: %v (generate one with: agentbox master-key)\n", err)
		return 2
	}

	log := slog.New(slog.NewJSONHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := postgres.Open(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(stderr, "agentbox serve: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	v, err := schema.NewValidator()
	if err != nil {
		fmt.Fprintf(stderr, "agentbox serve: %v\n", err)
		return 1
	}

	km := keys.New(st.Keys(), sl)
	signer, err := km.Ensure(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "agentbox serve: signing key: %v\n", err)
		return 1
	}

	healthz := func(w http.ResponseWriter, r *http.Request) {
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

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", healthz)
	api := &admin.Server{Store: st, Validator: v, Token: *adminToken, Sealer: sl, Keys: km, Log: log}
	adminMux.Handle("/admin/", api.Handler())

	newServer := func(addr string, h http.Handler) *http.Server {
		return &http.Server{
			Addr: addr, Handler: h,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		}
	}
	servers := []*http.Server{newServer(*addr, public), newServer(*adminAddr, adminMux)}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) { errc <- srv.ListenAndServe() }(srv)
	}
	log.Info("agentbox serving", "version", versionString(), "addr", *addr, "admin_addr", *adminAddr, "kid", signer.KID)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "agentbox serve: %v\n", err)
			return 1
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "agentbox serve: shutdown: %v\n", err)
			return 1
		}
	}
	return 0
}

// runMasterKey prints a fresh master key for an operator setting up a box.
func runMasterKey(stdout, stderr io.Writer) int {
	k, err := sealer.Generate()
	if err != nil {
		fmt.Fprintf(stderr, "agentbox master-key: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, k)
	return 0
}
