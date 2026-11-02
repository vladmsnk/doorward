# How the code is organized

Doorward's Go code follows the layout [Ory Hydra](https://github.com/ory/hydra)
uses. Each domain package owns its storage interface, its HTTP handlers and
a description of what it needs from the rest of the box. One registry
builds every component, and one persister implements every storage
interface. Commands read flags and files, call the domain, and print.

## Layers

Dependencies point down this list and never up:

| Layer | Packages | What it is |
|---|---|---|
| Entry points | `cmd/doorward`, `cmd/demo-ledger` | `main`: names the build and hands over |
| Commands | `internal/cmd`, `internal/cmd/server` | flags, files, printing; `serve` runs the listeners, the journal follower and the shutdown |
| Wiring | `internal/driver`, `internal/driver/config` | the settings, and the registry that builds the box from them |
| Services | `internal/pdp`, `internal/gateway` | the decision point and the MCP gateway |
| Domains | `internal/configuration`, `grant`, `consent`, `approval`, `journal`, `jwk`, `budget` | each one's records, storage interface, handlers and rules |
| Pure logic | `internal/core`, `internal/policy` | the three call checks (subset, sensitivity, budgets) and the permission algebra |
| Storage | `internal/persistence`, `internal/persistence/sql` | the Persister, and its PostgreSQL implementation with the migrations |
| Shared | `internal/x`, `sealer`, `ids`, `telemetry` | storage errors, HTTP helpers and provider interfaces; sealing; record IDs; tracing |
| Contract | `api/v0`, `schema` | the v0 documents as Go types, and their schemas; the only public packages |

No domain or service package imports `persistence` or `driver`. Only the
wiring, the commands and the test helpers do.

## A domain package

Take `configuration`, which holds the Manifests, Agents and Mandates and the
secrets they name:

| File | Holds |
|---|---|
| `manager.go` | `Document`, `Manager` (the storage interface for documents), `SecretManager`, and their `ManagerProvider` interfaces |
| `registry.go` | `Registry`: what the package offers others; `InternalRegistry`: what its handlers need |
| `handler.go`, `handler_agent.go`, `handler_secret.go` | `Handler`, `NewHandler(r InternalRegistry)` and `SetAdminRoutes`, which registers the Admin API routes the package serves |
| `rules.go` | the rules that span documents, and the transaction a change runs in |
| `cache.go`, `snapshot.go` | the decision point's decoded copy of the configuration |

The other domains have the same shape where they need it. `jwk` publishes
the JWK Set (`SetPublicRoutes`) and serves the key routes. `journal` serves
the decision export and copies the journal out (`Follower`). `grant` signs
and verifies grants and issues them (`Issuer`). `approval` opens the request
for a held call. `consent` and `budget` are, so far, only their records.

A package's `InternalRegistry` lists provider interfaces, one method each:

```go
type InternalRegistry interface {
	Registry
	LockerProvider          // ConfigurationLocker() Locker
	GrantRevokerProvider    // GrantRevoker() GrantRevoker
	sealer.Provider         // Sealer() *sealer.Sealer
	x.LoggerProvider        // Logger() *slog.Logger
	x.ClockProvider         // Now() time.Time
	x.ValidatorProvider     // Validator() *schema.Validator
}
```

When a package needs something from a domain that already depends on it,
it declares that one thing as its own interface instead of importing the
domain. `configuration.GrantRevoker` revokes a suspended agent's grants;
`grant.Manager` satisfies it without `configuration` importing `grant`.

## The registry

`driver.RegistryDefault` implements every provider interface. It builds
each component once, on first use, behind a `sync.Once`, so two requests
never race to build one. A component's dependencies are written in exactly
one place, its getter:

```go
func (r *RegistryDefault) GrantVerifier() *grant.Verifier {
	return r.verifier.get(func() *grant.Verifier {
		return &grant.Verifier{Keys: r.KeyRing(), Status: grant.StoreStatus{...}, ...}
	})
}
```

`New(conf)` takes the settings, and the `With` methods override the
persister, logger, tracer, clock, validator and journal follower. `Open`
connects to the database and loads the schemas and the master key.
`RegisterPublicRoutes` and `RegisterAdminRoutes` mount every domain's
handlers; the Admin API's router puts each route behind the administrator's
token. An unexported `registry` interface lists everything the domains ask
for, and `var _ registry = (*RegistryDefault)(nil)` keeps the two in step:
a package that declares a new need does not compile until the registry
meets it.

Small components with few dependencies take them explicitly instead of a
registry: `grant.Verifier`, `jwk.KeyRing`, `configuration.Cache`,
`journal.Follower`. They can be built and tested on their own, and the
registry builds them for the rest of the box.

## Settings

`driver/config.DefaultProvider` is every `doorward serve` setting. `Bind`
defines the flags, each defaulting to its environment variable, and
`Validate` makes the checks serve cannot start without. Domain packages
read settings through `config.Provider`: the decision point reads its name
and its deadline, the gateway its name and allowed origins.

## Tests

Tests that need the database use `testhelpers.NewRegistry`. It returns an
open registry on the empty database `DOORWARD_TEST_POSTGRES_DSN` names, with
a fresh master key and signing key, and skips the test without one. A test
adjusts the settings or the registry (clock, journal, tracer) before it
opens, then mounts the handlers it tests as `serve` would. A storage test
takes the store alone with `OpenPersister`. `Example` reads an example
document as the box reads one, `PutExampleConfig` stores the example
configuration, and `Record` appends a record the way the decision point
does, by settling it.

## Adding a component

1. Put it in the domain it belongs to. If it is a new domain, give the
   package a `manager.go` for its records and a `registry.go` for what it
   needs.
2. Name its dependencies as provider interfaces in the package's
   `InternalRegistry`, or as explicit fields if it is small.
3. Give `RegistryDefault` a getter that builds it, and add the package's
   `InternalRegistry` to the `registry` interface.
4. Register its routes in `RegisterPublicRoutes` or `RegisterAdminRoutes`.
5. Add its storage to `persistence.Persister` and implement it in
   `persistence/sql`, one file per domain, with a migration.
