# agentbox

A single distribution for authorizing AI agents: who an agent is, what it
may do, for whom, on whose consent, and which calls a person must approve.
It sits on the resource side, in front of a company's own tools, because
that is the control point a company keeps when the agents themselves are
hosted by someone else. Agentbox is the decision, approval and evidence
core; its gateway and authorization server are thin built-in parts for a
company that has neither, and each can be replaced through a standard
interface (AuthZEN, RFC 9068 tokens with a JWK Set, OIDC).

> `agentbox` is a working name.
>
> Development is AI-assisted: much of the code is written with Claude Code,
> and every commit is authored and signed off by a human maintainer (see
> [CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-development)).

## Status

On main: the contract, PostgreSQL storage, the Admin API, signing keys and
sealed secrets, grant verification, and the decision core's subset and
sensitivity checks, with the fail-open paths found in review closed.
Nothing yet sits in front of a real tool. Next come budgets and the
evaluation endpoint, then one end-to-end slice in which an off-the-shelf
MCP client connects, a user consents, and a call is refused or approved.
The order and the reasons are in [docs/ROADMAP.md](docs/ROADMAP.md).

## What agentbox cannot see

Agentbox decides only on calls that pass through it, to tools a company has
described to it. It cannot see or stop:

- **Calls that never reach it**: an agent acting on the machine it runs on
  (a shell, local files, credentials stored there), or calling an API
  directly with a credential it already holds.
- **What the model decides**: prompt injection, a poisoned tool
  description, a goal hijacked mid-task. Agentbox does not prevent an agent
  from being manipulated; it bounds what a manipulated agent can do: which
  operations, with which arguments, within which budgets, and which calls a
  person approves first.
- **What a tool does with an allowed call**: a compromised server behind
  the gateway can misuse what it is allowed to receive. A constraint that
  pins an argument, such as an email's recipient, narrows that; nothing
  removes it.

## Quick start

```sh
make ci                                  # what CI runs: tidy, fmt, vet, lint, tests, examples
make build
bin/agentbox validate examples/v0/config/*.yaml
bin/agentbox validate --kind grant examples/v0/grant/*.json
bin/agentbox validate --kind approval examples/v0/approval/*.json
```

Configuration documents name their kind. Messages and records need `--kind`:
`consent`, `grant`, `decision` or `approval`.

Go 1.25 and, for `make lint`, golangci-lint v2. The store tests need
PostgreSQL 16: `make test-db` starts a throwaway one and prints the
`AGENTBOX_TEST_POSTGRES_DSN` to export; without that variable they skip.

## Admin API

Configuration enters the box through the Admin API, and only there. Every
write is validated against the contract, then against the whole
configuration as it would be after the write (a mandate's operations exist,
a mandate lies within every agent that may hold it, no identity is claimed
twice), under one lock so concurrent changes are checked one after the
other, and stored as a new version. Nothing is overwritten; `…/versions`
shows who changed what and when.

The Admin API listens on `127.0.0.1:8081` by default, because one token
authorizes every change. Expose it with `--admin-addr` only behind
something that restricts who can reach it.

```sh
export AGENTBOX_DB=postgres://… AGENTBOX_ADMIN_TOKEN=$(openssl rand -hex 16)
export AGENTBOX_MASTER_KEY=$(agentbox master-key)   # keep it: it seals the signing keys and secrets
agentbox serve                                      # public listener on :8080, Admin API on 127.0.0.1:8081

H="Authorization: Bearer $AGENTBOX_ADMIN_TOKEN"
curl -sS -X PUT -H "$H" -H "Content-Type: application/yaml" \
  --data-binary @examples/v0/config/manifest-payments-api.yaml \
  localhost:8081/admin/v0/manifests/payments-api
curl -sS -H "$H" localhost:8081/admin/v0/mandates/invoices/versions
curl -sS -X POST -H "$H" -d '{"owner":{"team":"support-tools"}}' \
  localhost:8081/admin/v0/agents/desk-helper-7f3a/verify
```

| Route | Does |
|---|---|
| `PUT /admin/v0/{manifests\|agents\|mandates}/{name}` | validate and store the next version (YAML or JSON body) |
| `GET …/{name}`, `GET …` | the current version; all current documents of a kind |
| `GET …/{name}/versions`, `…/versions/{n}` | the history; one version |
| `POST …/{name}/disable`, `/enable` | manifests and mandates; a manifest that enabled mandates name cannot be disabled |
| `POST /admin/v0/agents/{name}/verify`, `/suspend` | an agent's status; suspending revokes its live grants |
| `PUT /admin/v0/secrets/{name}` `{"value": …}`, `GET …`, `DELETE …/{name}` | upstream credentials a manifest's `secret_ref` names; values are never returned, and a secret an enabled manifest uses cannot be deleted |
| `GET /admin/v0/keys`, `POST …/rotate`, `POST …/{kid}/retire` | the box's signing keys; a rotated-out key stays published until retired |

Authentication is a bootstrap bearer token for now (`AGENTBOX_ADMIN_TOKEN`);
administrators from the identity provider come with the consent work.

## Keys and secrets

On first start the box creates an ES256 signing key, and publishes the
public half at `/.well-known/jwks.json` on the public listener; the `kid`
is the key's RFC 7638 thumbprint. Rotation makes a new key active and keeps
the old one published, so grants it signed still verify, until an
administrator retires it. Private keys and upstream secrets are sealed with
AES-256-GCM under the operator's master key (`AGENTBOX_MASTER_KEY`) before
they reach the database, each bound to its own slot, so the database never
holds them in clear and a value cannot be moved from one slot to another.

## Grants

A grant is a JWT access token (RFC 9068): header `{"alg":"ES256","typ":"at+jwt","kid":…}`,
the claims of [`grant.schema.json`](schema/v0/grant.schema.json), signed
with the box's active key. Verification ([`internal/grant`](internal/grant))
accepts exactly that header, finds the key by `kid` in the box's own key
table (retired keys included, so a grant outlives a rotation), checks the
signature before reading a single claim, then runs the claims through the
schema and the grant's rules. It produces the grant's part of a decision
record, in the record's order, and stops at the first failure:

| Check | Refused with |
|---|---|
| `signature` | `grant_missing`, `grant_malformed`, `grant_signature_invalid` |
| `status` | `grant_revoked`: the box has no record of the grant, revoked it, or it is a used single-use grant; its agent is suspended; its consent is revoked or expired; its mandate is disabled |
| `pop` | recorded as `skip`: the box issues Bearer grants and does not check proofs of possession yet. A grant that carries `cnf` anyway fails with `pop_missing` |
| `audience` | `audience_mismatch` |
| `time` | `grant_expired`, `grant_not_yet_valid` (30 s of clock skew allowed) |

Until the token service exists, grants are minted from the command line.
`mint` replaces `iat`, `exp` and `jti` and merges the grant to one entry
per operation. It checks that the agent is registered and not suspended,
the mandate exists and is enabled, and the grant lies within it. For a
user it also checks that the consent is recorded, active, unexpired and
given to this agent for this mandate, and that the grant lies within the
mandate as the user saw it, named by the consent's `mandate_version`; the
grant expires no later than the consent. Then it signs and records the
grant. It needs the database and the master
key, so it gives its user nothing they could not already do.

```sh
agentbox grant mint --consent examples/v0/consent/alice-invoice-assistant.json \
  examples/v0/grant/pay-invoice.json > grant.jwt
agentbox grant verify --aud https://payments.example.internal - < grant.jwt
```

```
pass  signature  key TDgsZWz9aL3UpCrlz8oKiwWOoLf11IcazmKRe9QPGpI
pass  status
skip  pop        proof of possession is not checked yet
pass  audience
pass  time
accepted: grant grt_01M68ZAY9YDFW1ZFC20G1RM7AM, agent invoice-assistant acting for user alice@example.com, mandate invoices, expires in 15m0s
```

`verify` exits 1 on a refusal; `--json` prints the checks and the reason.

Given a call, `verify` also runs the subset check
([`internal/core`](internal/core)): the grant must allow the operation at
the resource, and every bound the grant sets on its arguments must hold.
Bounds from every entry that names the operation apply together. A bound
on an argument the call carries is always checked; a missing argument is
refused only if the manifest declares it, since one entry may bound
`/amount` for operations that take no amount.

```sh
agentbox grant verify --aud https://payments.example.internal \
  --action pay_invoice --args '{"invoice_id":"inv_7Q2M9X4K","amount":7500,"currency":"EUR"}' - < grant.jwt
```

```
...
fail  subset      /amount
refused: constraint_violated
```

| Refused with | When |
|---|---|
| `action_not_granted` | no entry names the operation at that resource, or the manifest no longer has it |
| `field_missing` | a bounded argument the operation declares is absent or null |
| `constraint_violated` | a value breaks a bound, or is not the type the manifest declares |

Then the sensitivity check: the manifest gives the operation's tier, and
the grant's record says whether it is standing or single-use.

| Case | Answer |
|---|---|
| the tier is above the agent's `max_sensitivity`, as it stands now | deny, `sensitivity_exceeded` |
| a single-use grant, but not the call it was issued for | deny, `action_not_granted` |
| `critical` on a standing grant | approval required: the call is held |
| `read` or `write`, or the single-use grant's own call | pass |

A call is named by its action hash: the digest of
`{"name", "location", "arguments"}` in canonical JSON (RFC 8785), so the
same call written with other key order, spacing or number spelling hashes
the same, and a cent more does not. An approval is bound to that hash, and
so is the single-use grant issued once it is approved. `grant mint
--single-use` issues one by hand; the grant record keeps the hash, and a
used single-use grant fails the status check.

```sh
agentbox grant verify --aud https://payments.example.internal \
  --action pay_invoice --args '{"invoice_id":"inv_7Q2M9X4K","amount":1200,"currency":"EUR"}' - < grant.jwt
```

```
...
pass  subset
fail  sensitivity critical tier needs a single-use grant
action hash sha-256:gUi92kB2Ra9Uh-iK8Fg62NSU7pmAFgPjYOOHZ1mlHtg
approval required: a person approves this exact call, then a single-use grant bound to its hash runs it
```

`verify` exits 3 when a call needs approval. Spending a single-use grant
belongs to the evaluation endpoint, together with budgets: it happens only
for a call that is allowed.

## Storage

Everything the box keeps lives in one PostgreSQL database, behind the
`store.Store` interface in [`internal/store`](internal/store): configuration
(manifests, agents, mandates), versioned so nothing is ever overwritten and
a consent can name the exact mandate the user saw; and the records
(consents, grants, decisions, approvals) plus the budget counters. Decision
records form a hash chain; `v0.Verify` checks it. Migrations are embedded
and applied on start.

## The v0 schemas

Seven documents, as JSON Schema (draft 2020-12) in [`schema/v0`](schema/v0)
with matching Go types in [`api/v0`](api/v0). Three are configuration a
company writes, in YAML or JSON; the other four are records the box produces
as agents work.

| Document | Written by | What it is |
|---|---|---|
| [Manifest](schema/v0/manifest.schema.json) | company | One resource behind the gateway: where the gateway forwards to and with which credential, the operations it exposes (MCP tools or HTTP routes), the tier of each (`read`, `write`, `critical`), and where their constrainable arguments are |
| [Agent](schema/v0/agent.schema.json) | company, or the agent itself | One agent: how it presented itself, how it proves who it is, who answers for it, and the most it may ever be granted |
| [Mandate](schema/v0/mandate.schema.json) | company | What an agent may do for a principal and on what terms: permissions, limits, how long a user's consent stands, who approves critical calls |
| [Consent](schema/v0/consent.schema.json) | the box | One person allowing one agent one mandate, given on the box's consent page |
| [Grant](schema/v0/grant.schema.json) | the STS | Claims of the short-lived, key-bound JWT access token (RFC 9068) an agent holds under a mandate |
| [Decision](schema/v0/decision.schema.json) | the decision core | The record of one decision: who acted, for whom, under which grant and consent, what was asked, every check and its result, and where it was decided and enforced |
| [Approval](schema/v0/approval.schema.json) | the approval service | The record of one approval request: the exact call, who voted, how each of them signed in |

### How an agent asks for authority

A mandate's name is an OAuth scope. The gateway publishes, for each resource,
the standard protected-resource metadata (RFC 9728) listing the box as its
authorization server and the mandates it accepts as `scopes_supported`. A
standard MCP client therefore finds the consent flow on its own: it reads the
metadata, registers itself if it is new, and sends the user to the box with
`scope=invoices`. A deployed agent exchanges its workload token for a grant
with the same scope.

### How an agent comes in

An agent is an OAuth client of the box, as every MCP client already is.
An administrator registers it, or it introduces itself: by a client
metadata document at a URL, as MCP clients do, or by dynamic client
registration, kept for older clients. A self-registered agent is
**unverified**: it may request only mandates marked `open`, under the small
ceiling every unverified agent gets, until an administrator reviews it,
names its owner and marks it **verified**. A **suspended** agent is refused
everywhere.

### Two ways an agent acts

| | For a person (`principal: user`) | For its owner (`principal: service`) |
|---|---|---|
| Authority | the person consents once, on the box's consent page at the end of a standard OAuth authorization, for at most `consent.max_duration` | the owner gave the agent the mandate; the agent presents its workload identity |
| Grant | `sub` is the user, `sub_id` says which identity provider, `consent` names the record it rests on | `sub` is the agent, equal to `client_id` |
| What the resource sees | the user, as if they had called | the agent |
| Critical calls | approved by the user, or by a group | approved by a group: there is no user to ask |

A grant is the mandate intersected with the agent's own permissions, never
more. At call time a point of enforcement sends the call to the decision
core, which checks it against the grant, applies the operation's tier from
the manifest, and writes a decision record. A critical call opens an
approval. Budgets can run per grant or, under a consent, per day or month.

The examples in [`examples/v0`](examples/v0) tell both stories. Alice
connects Acme's `invoice-assistant` to her invoices under the `invoices`
mandate; the core allows a read, denies an overlarge payment and holds a
1,200 EUR payment until Alice approves it. The `reconciler` runs nightly on
its Kubernetes service-account token under the `reconcile` mandate, posts
entries, and two people from finance on-call approve a write-off. A third
agent, `desk-helper-7f3a`, registered itself and is still unverified: it can
ask users only for the open, read-only mandate.

### Conventions

- **Permissions** are RFC 9396 `authorization_details`: `locations`
  (audiences), `actions` (operation names, never wildcards) and
  `constraints`.
- **Constraints** are keyed by the argument's JSON Pointer and use a closed
  set of types, each of which can be compared with a narrower one. That is
  what keeps "request ⊆ grant" decidable:

  | Type | Meaning |
  |---|---|
  | `max`, `min` | numeric bounds, inclusive |
  | `one_of` | the value is one of a list |
  | `equals` | the value is exactly this |
  | `prefix` | a string starts with this |

  All bounds on a field must hold. A constrained field missing from the call
  fails the check.
- **Strict parsing.** Unknown fields are rejected. So are duplicate keys, in
  JSON and in YAML: two parsers reading one document differently is how a
  forged field gets past a check.
- **OAuth and OIDC shapes.** The grant is an RFC 9068 JWT access token
  (`typ: at+jwt`, with `client_id`), so ordinary resource servers can check
  it. Users are named with their identity provider (`sub_id`, RFC 9493),
  since an OIDC `sub` is unique only per issuer. A grant is a Bearer token
by default, as MCP clients send it; proof of possession (DPoP) will be
required per agent or mandate, and a grant carries `cnf` only where the box
checks the proof.
  Agents authenticate with the box's own registration or with any JWT that
  has an issuer and a subject: an IdP client, a Kubernetes service account,
  a workload identity.
- **Records have one serialization.** Times in records are UTC with exactly
  millisecond precision, since records are hash-chained.
- **The schemas are the contract.** The Go types mirror them, and
  [`schema/drift_test.go`](schema/drift_test.go) fails the build when the two
  disagree on a field, on whether it is required, or on an enum's members.

### Using the schemas from Go

```go
v, err := schema.NewValidator()
if err != nil { ... }
grant, err := schema.Decode[v0.Grant](v, claimsJSON) // duplicate keys, schema, strict decode, rules
```

### Rules beyond the schemas

JSON Schema checks each document's shape. Each Go type's `Check` adds the
rules that span its own fields, and `Decode` and the CLI run them: `aud`
equals the grant's locations, a grant for a user has `sub_id` and a
`consent` and a grant for the agent itself has neither, times come in
order, an allowed decision has no failed check, a manifest's path parameters
match its routes, an approval's voters are distinct and match its route, and
`min ≤ max` everywhere.

Rules that need a second document run in the Admin API, over the whole
configuration: a mandate lying within every agent that may hold it,
operations existing in a manifest, an agent requesting only mandates it
may, an identity claimed once.

In the examples, action hashes and the consent's `mandate_version` are real
digests, kept so by tests. Other IDs, chain hashes and policy versions have
the right format but are placeholders.

### Decisions for the first implementation

- **Approve, then retry.** A critical call is answered at once: pending,
  with a link to the approval. Once a person approves that exact call, the
  client's retry of it, matched by its action hash, runs exactly once under
  a single-use grant the box keeps. The gateway never holds a call open for
  the length of an approval and never runs a stored call on its own.
- **Bearer grants by default**, short-lived and checked for audience and
  status on every call; proof of possession is a per-agent or per-mandate
  requirement, enforced end to end where it is required.
- **One entry per operation** in a grant, so a reader that checks each
  `authorization_details` entry on its own reaches the same answer as the
  box.
- **Checks the first version does not run are recorded as `skip`**: `pop`
  and `policy` (the mandate is the policy). `status` reads the box's own
  records; a published status list comes later.
- **Upstream credentials** come from the box's sealed secret store, named
  by `secret_ref`, and the client's token is never passed on.

### Later

v0 covers agents that act for a person who consented and agents that act
for their owner, and nothing else. Each of these is a known extension, and
each adds fields or documents without changing what is here:

| Extension | What it adds |
|---|---|
| Delegation between agents | optional `parent` and `depth` on a grant (a grant without them is a root), a nested `act.act`, `delegation` blocks on agents and mandates, and an `Offer` record |
| Tasks started by an application | an `Application` document and a `TaskRequest` message (RFC 8693), for an app that starts a scoped task for its user without a consent page |
| A user narrowing a mandate | parameters on `Consent` the user chooses on the consent page, such as payees or a lower cap |
| Per-call data scoping | constraints tied to an object the task is about (`task_object`) |
| mTLS-bound grants | `cnf.x5t#S256` beside `jkt` |
| X.509 SPIFFE identities | a `spiffe` identity type on agents |
| Allow-and-notify | `obligations` on an allowed decision |
| Scopes for plain resource servers | `scope` on the grant, derived from the actions |

## Layout

```
cmd/agentbox/      the CLI: validate, serve, grant mint|verify, master-key, version
api/v0/            Go types of the v0 documents
internal/store/    the Store interface; postgres/ implements it, with migrations
internal/admin/    the Admin API and the rules across documents
internal/policy/   comparing permissions: tiers, constraints, "within"
internal/keys/     signing keys: create, rotate, retire, JWK Set
internal/sealer/   AES-256-GCM sealing under the master key
internal/grant/    signing grants and verifying them (B1)
internal/core/     the decision core: subset (B2) and sensitivity (B3) checks
internal/ids/      record IDs: prefix_ULID
schema/            the embedded schemas, the validator, strict YAML/JSON reading
schema/v0/         the JSON Schemas
examples/v0/       valid examples of every document
scripts/           check-dco.sh
```

## Releases

Pushing a `v*` tag builds Linux and macOS binaries with GoReleaser and signs
the checksum file with cosign's keyless flow. The signing certificate binds
the signature to this repository's release workflow. A tag with a suffix,
such as `v0.0.1-test.1`, makes a prerelease.

To verify a download:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/vladmsnk/agentbox/\.github/workflows/release\.yml@refs/tags/v'
sha256sum --check --ignore-missing checksums.txt
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every commit is signed off under the
[Developer Certificate of Origin](DCO).

## License

[Apache License 2.0](LICENSE).
