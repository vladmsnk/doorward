// Package driver builds the box. Its registry holds every component, builds
// each one once and on first use from the settings and the components it
// depends on, and hands domain packages what they ask for through the
// provider interfaces they declare (configuration.ManagerProvider,
// jwk.KeyRingProvider, ...). Nothing else constructs components, so a
// component's dependencies are written down in exactly one place.
package driver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/vladmsnk/doorward/internal/approval"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/consent"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/gateway"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/journal"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/pdp"
	"github.com/vladmsnk/doorward/internal/persistence"
	"github.com/vladmsnk/doorward/internal/persistence/sql"
	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

// RegistryDefault is the box's registry. Create it with New, override what
// a test or the command needs with the With methods, then Open it. The With
// methods must come before the components that use what they set are first
// asked for.
type RegistryDefault struct {
	conf      *config.DefaultProvider
	log       *slog.Logger
	tracer    trace.Tracer
	now       func() time.Time
	persister persistence.Persister
	validator *schema.Validator
	sealer    *sealer.Sealer
	follower  *journal.Follower

	keyRing  lazy[*jwk.KeyRing]
	cache    lazy[*configuration.Cache]
	verifier lazy[*grant.Verifier]
	pdp      lazy[*pdp.Evaluator]
	gateway  lazy[*gateway.Handler]
}

// New returns a registry for the settings.
func New(conf *config.DefaultProvider) *RegistryDefault {
	return &RegistryDefault{conf: conf}
}

// WithPersister uses p instead of opening the database named by the
// settings.
func (r *RegistryDefault) WithPersister(p persistence.Persister) *RegistryDefault {
	r.persister = p
	return r
}

// WithValidator uses v instead of loading the schemas again.
func (r *RegistryDefault) WithValidator(v *schema.Validator) *RegistryDefault {
	r.validator = v
	return r
}

// WithLogger sets the logger; the default is slog's.
func (r *RegistryDefault) WithLogger(l *slog.Logger) *RegistryDefault {
	r.log = l
	return r
}

// WithTracer sets the tracer decisions are traced with; the default traces
// nothing.
func (r *RegistryDefault) WithTracer(t trace.Tracer) *RegistryDefault {
	r.tracer = t
	return r
}

// WithClock stands the box's clock still, for tests.
func (r *RegistryDefault) WithClock(now func() time.Time) *RegistryDefault {
	r.now = now
	return r
}

// WithJournal has the decision point tell f about every record it commits.
func (r *RegistryDefault) WithJournal(f *journal.Follower) *RegistryDefault {
	r.follower = f
	return r
}

// Open connects to the database (unless WithPersister gave one), applying
// migrations, and loads the schema validator and the sealer.
func (r *RegistryDefault) Open(ctx context.Context) error {
	if r.persister == nil {
		p, err := sql.Open(ctx, r.conf.DSN)
		if err != nil {
			return err
		}
		r.persister = p
	}
	if r.validator == nil {
		v, err := schema.NewValidator()
		if err != nil {
			return err
		}
		r.validator = v
	}
	if r.conf.MasterKey != "" {
		sl, err := sealer.Parse(r.conf.MasterKey)
		if err != nil {
			return fmt.Errorf("--master-key or DOORWARD_MASTER_KEY: %w", err)
		}
		r.sealer = sl
	}
	return nil
}

// Close closes the database.
func (r *RegistryDefault) Close() error {
	if r.persister == nil {
		return nil
	}
	return r.persister.Close()
}

func (r *RegistryDefault) Config() *config.DefaultProvider  { return r.conf }
func (r *RegistryDefault) Persister() persistence.Persister { return r.persister }
func (r *RegistryDefault) Validator() *schema.Validator     { return r.validator }
func (r *RegistryDefault) Sealer() *sealer.Sealer           { return r.sealer }

func (r *RegistryDefault) Logger() *slog.Logger {
	if r.log == nil {
		return slog.Default()
	}
	return r.log
}

func (r *RegistryDefault) Tracer() trace.Tracer {
	if r.tracer == nil {
		return noop.NewTracerProvider().Tracer("")
	}
	return r.tracer
}

// Now is the box's time.
func (r *RegistryDefault) Now() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

func (r *RegistryDefault) ConfigurationManager() configuration.Manager {
	return r.persister.Documents()
}
func (r *RegistryDefault) SecretManager() configuration.SecretManager { return r.persister.Secrets() }
func (r *RegistryDefault) GrantManager() grant.Manager                { return r.persister.Grants() }
func (r *RegistryDefault) ConsentManager() consent.Manager            { return r.persister.Consents() }
func (r *RegistryDefault) JournalManager() journal.Manager            { return r.persister.Decisions() }
func (r *RegistryDefault) KeyManager() jwk.Manager                    { return r.persister.Keys() }
func (r *RegistryDefault) ApprovalManager() approval.Manager          { return r.persister.Approvals() }

// Settler spends what an allowed call spends and records it.
func (r *RegistryDefault) Settler() journal.Settler { return r.persister }

// JournalNotifier is the journal follower, or nil without one.
func (r *RegistryDefault) JournalNotifier() journal.Notifier {
	if r.follower == nil {
		return nil
	}
	return r.follower
}

// ConfigurationLocker serializes configuration changes.
func (r *RegistryDefault) ConfigurationLocker() configuration.Locker { return r.persister }

// GrantRevoker revokes a suspended agent's grants.
func (r *RegistryDefault) GrantRevoker() configuration.GrantRevoker { return r.persister.Grants() }

// KeyRing is the box's signing keys.
func (r *RegistryDefault) KeyRing() *jwk.KeyRing {
	return r.keyRing.get(func() *jwk.KeyRing { return jwk.NewKeyRing(r.KeyManager(), r.sealer) })
}

// ConfigurationCache is the decision point's copy of the configuration.
func (r *RegistryDefault) ConfigurationCache() *configuration.Cache {
	return r.cache.get(func() *configuration.Cache {
		return &configuration.Cache{Store: r.persister, Validator: r.validator, Log: r.log}
	})
}

// GrantVerifier checks grants: signature, standing, audience, time.
func (r *RegistryDefault) GrantVerifier() *grant.Verifier {
	return r.verifier.get(func() *grant.Verifier {
		return &grant.Verifier{
			Keys:      r.KeyRing(),
			Status:    grant.StoreStatus{Store: r.persister, Config: r.ConfigurationCache(), Now: r.now},
			Validator: r.validator,
			Issuer:    r.conf.Issuer,
			Now:       r.now,
		}
	})
}

// Evaluator is the decision point.
func (r *RegistryDefault) Evaluator() *pdp.Evaluator {
	return r.pdp.get(func() *pdp.Evaluator { return pdp.NewEvaluator(r) })
}

// GatewayHandler is the built-in MCP gateway. It is built once: it keeps
// the upstream credentials it has opened.
func (r *RegistryDefault) GatewayHandler() *gateway.Handler {
	return r.gateway.get(func() *gateway.Handler { return gateway.NewHandler(r) })
}

// RegisterPublicRoutes serves the JWK Set, the evaluation endpoint and the
// MCP gateway on the public listener.
func (r *RegistryDefault) RegisterPublicRoutes(mux *http.ServeMux) {
	jwk.NewHandler(r).SetPublicRoutes(mux)
	pdp.NewHandler(r).SetPublicRoutes(mux)
	r.GatewayHandler().SetPublicRoutes(mux)
}

// RegisterAdminRoutes serves the Admin API on the admin listener: every
// domain's routes, all behind the administrator's token.
func (r *RegistryDefault) RegisterAdminRoutes(mux *http.ServeMux) {
	a := x.NewAdminRouter(r.conf.AdminToken)
	configuration.NewHandler(r).SetAdminRoutes(a)
	jwk.NewHandler(r).SetAdminRoutes(a)
	journal.NewHandler(r).SetAdminRoutes(a)
	mux.Handle("/admin/", a)
}

// lazy builds a value once, on first use, whichever goroutine asks first.
type lazy[T any] struct {
	once sync.Once
	v    T
}

func (l *lazy[T]) get(build func() T) T {
	l.once.Do(func() { l.v = build() })
	return l.v
}
