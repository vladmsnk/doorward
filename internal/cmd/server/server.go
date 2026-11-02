// Package server runs the box: doorward serve. It reads the settings,
// opens the registry, and serves two listeners, so the two can be exposed
// differently: the public one (health, the JWK Set, the evaluation endpoint,
// the MCP gateway) and the Admin API on its own port. It also runs the
// journal follower and shuts everything down in order.
package server

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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vladmsnk/doorward/internal/driver"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/telemetry"
	"github.com/vladmsnk/doorward/internal/x"
)

// Serve runs doorward serve with args until SIGINT or SIGTERM, and returns
// the exit code. version names the build in records and logs.
func Serve(args []string, stdout, stderr io.Writer, version string) int {
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "doorward serve: "+format+"\n", a...)
		return code
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	conf, err := config.Bind(fs, version)
	if err != nil {
		return fail(2, "%v", err)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := conf.Validate(); err != nil {
		return fail(2, "%v", err)
	}

	// The journal file is opened before the store, so a bad path fails fast.
	journalFile, err := openJournal(conf.JournalPath)
	if err != nil {
		return fail(2, "--journal: %v", err)
	}
	if journalFile != nil {
		defer func() { _ = journalFile.Close() }()
	}

	// Warnings and errors are sampled: one line per message per second, with
	// a count of the rest, so an outage does not flood the log.
	log := slog.New(telemetry.Sampled(slog.NewJSONHandler(stdout, nil), time.Second))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := driver.New(conf).WithLogger(log)
	if err := reg.Open(ctx); err != nil {
		return fail(1, "%v", err)
	}
	defer func() { _ = reg.Close() }()
	signer, err := reg.KeyRing().Ensure(ctx)
	if err != nil {
		return fail(1, "signing key: %v", err)
	}

	tp, stopTracing, err := telemetry.Setup(ctx, "doorward", version)
	if err != nil {
		return fail(1, "OpenTelemetry: %v", err)
	}
	defer func() { _ = stopTracing(context.Background()) }()
	reg.WithTracer(tp.Tracer("doorward"))

	follower, code, err := startJournal(ctx, reg, conf.JournalPath, journalFile, stdout, log)
	if err != nil {
		return fail(code, "%v", err)
	}
	if follower != nil {
		reg.WithJournal(follower)
	}

	var stopping atomic.Bool
	healthz := health(reg, &stopping)
	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", healthz)
	reg.RegisterPublicRoutes(public)
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", healthz)
	reg.RegisterAdminRoutes(admin)

	// The public listener carries the gateway's event streams, which a
	// write deadline would cut off mid-call, so it has none; the slow-client
	// guards that remain are the read and idle timeouts. The admin listener
	// serves only short request-response calls and keeps a write deadline.
	servers := []*http.Server{newServer(conf.Addr, public, 0), newServer(conf.AdminAddr, admin, 30*time.Second)}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) { errc <- srv.ListenAndServe() }(srv)
	}
	log.Info("doorward serving", "version", version, "addr", conf.Addr, "admin_addr", conf.AdminAddr, "kid", signer.KID,
		"points_of_enforcement", len(conf.PointsOfEnforcement))

	select {
	case <-ctx.Done():
		stopping.Store(true)
		log.Info("shutting down", "delay", conf.ShutdownDelay.String())
		if conf.ShutdownDelay > 0 {
			// Health already says 503; keep answering while the load
			// balancer notices.
			time.Sleep(conf.ShutdownDelay)
		}
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return fail(1, "%v", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fail(1, "shutdown: %v", err)
		}
	}
	if follower != nil {
		if err := follower.Close(shutdownCtx); err != nil {
			return fail(1, "journal: %v", err)
		}
	}
	return 0
}

// openJournal opens the journal file for appending, or returns nil when the
// journal goes to standard output or nowhere.
func openJournal(path string) (*os.File, error) {
	switch path {
	case "", "-":
		return nil, nil
	}
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600) // #nosec G304 -- the operator names the journal file
}

// startJournal starts the follower that copies every committed record, from
// any instance, in order: to the file, resuming where it ended, or to
// standard output, starting at the current head. It returns nil without a
// journal, and on failure the exit code to use.
func startJournal(ctx context.Context, reg *driver.RegistryDefault, path string, file *os.File, stdout io.Writer, log *slog.Logger) (*journal.Follower, int, error) {
	if path == "" {
		return nil, 0, nil
	}
	var from uint64
	out := stdout
	if file != nil {
		var err error
		if from, err = journal.Resume(file); err != nil {
			return nil, 2, fmt.Errorf("--journal: %w", err)
		}
		out = file
	} else if head, err := reg.JournalManager().Head(ctx); err == nil {
		from = head.Chain.Seq + 1
	} else if !errors.Is(err, x.ErrNotFound) {
		return nil, 1, err
	}
	follower := journal.NewFollower(reg.JournalManager(), out, from, 0, log)
	go follower.Run(ctx)
	log.Info("journal follower started", "from_seq", from, "to", path)
	return follower, 0, nil
}

// health answers 503 while stopping or when the database does not answer.
func health(reg *driver.RegistryDefault, stopping *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if stopping.Load() {
			http.Error(w, "stopping", http.StatusServiceUnavailable)
			return
		}
		if err := reg.Persister().Ping(r.Context()); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	}
}

func newServer(addr string, h http.Handler, writeTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: writeTimeout, IdleTimeout: 2 * time.Minute,
	}
}
