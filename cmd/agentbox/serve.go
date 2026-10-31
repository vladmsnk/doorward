package main

import (
	"context"
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
	"github.com/vladmsnk/agentbox/internal/store/postgres"
	"github.com/vladmsnk/agentbox/schema"
)

// runServe starts the box. In this version that is the Admin API and a
// health endpoint; the token service, the gateway and the decision core
// join it in later steps.
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("AGENTBOX_DB"), "PostgreSQL connection string (or AGENTBOX_DB)")
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.Pool().Ping(r.Context()); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	api := &admin.Server{Store: st, Validator: v, Token: *adminToken, Log: log}
	mux.Handle("/admin/", api.Handler())

	srv := &http.Server{
		Addr: *adminAddr, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("agentbox serving", "version", versionString(), "admin_addr", *adminAddr)

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
	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(stderr, "agentbox serve: shutdown: %v\n", err)
		return 1
	}
	return 0
}
