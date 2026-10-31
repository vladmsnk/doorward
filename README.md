# agentbox

A single distribution for authorizing AI agents: what an agent may do, for
which user, within which task, and to whom it may pass that authority on. It
is built for a company that has none of the usual infrastructure: no IdP with
token exchange, no policy engine, no service mesh. Everything is built in,
every built-in part can be replaced through a standard interface, and the box
grows level by level, L1 to L5, collecting the evidence for each level as it
goes.

> `agentbox` is a working name.

## Status

Stage 0, the foundation:

| Feature | | Status |
|---|---|---|
| F01 | Repository and CI | done; the first signed test release runs on the first tag |
| F02 | Schemas v0 | done |
| F03 | Negative test catalogue | not started |
| F04 | Test bench | not started |

## Quick start

```sh
make ci                                  # what CI runs: tidy, fmt, vet, lint, tests, examples
make build
bin/agentbox validate examples/v0/config/*.yaml
bin/agentbox validate --kind grant examples/v0/grant/*.json
bin/agentbox validate --kind approval examples/v0/approval/*.json
```

Configuration documents name their kind. Messages and records need `--kind`:
`taskrequest`, `grant`, `decision` or `approval`.

Go 1.24 and, for `make lint`, golangci-lint v2.

## The v0 schemas

Eight documents, as JSON Schema (draft 2020-12) in [`schema/v0`](schema/v0)
with matching Go types in [`api/v0`](api/v0). Four are configuration a
company writes, in YAML or JSON; the other four are messages and records,
in the order one task produces them.

| Document | Written by | What it is |
|---|---|---|
| [Manifest](schema/v0/manifest.schema.json) | company | The operations one resource exposes (MCP tools or HTTP routes), the tier of each (`read`, `write`, `critical`), and where their constrainable arguments are |
| [Agent](schema/v0/agent.schema.json) | company | One agent: how it proves who it is, who owns it, and the most it may ever be granted |
| [TaskType](schema/v0/tasktype.schema.json) | company | A kind of task: the object it is about, whom it runs as, how it may start, its lifetime, permissions, limits and approvers |
| [Application](schema/v0/application.schema.json) | company | An application that starts tasks for users: how it authenticates, and which identity providers vouch for its users |
| [TaskRequest](schema/v0/taskrequest.schema.json) | the application, or the agent | The RFC 8693 token exchange that starts a task |
| [Grant](schema/v0/grant.schema.json) | the STS | Claims of the short-lived, key-bound JWT access token (RFC 9068) an agent's sidecar holds for one task |
| [Decision](schema/v0/decision.schema.json) | the decision core | The record of one decision, with every element level L1 asks for |
| [Approval](schema/v0/approval.schema.json) | the approval service | The record of one approval request: the exact call, who voted, how each of them signed in |

### Two ways an agent runs

| | Personal assistant (`runs_as: user`) | Deployed agent (`runs_as: service`) |
|---|---|---|
| Accountable | the user; `sub` in the grant, `sub_id` says which identity provider | the agent's owner team; the agent is `sub` and `client_id` |
| Task started by | an application the user is in, from a button (`ui`) or a conversation (`chat`) | the agent itself, on a `schedule` or an `event` |
| Before it starts | the user confirms the exact task when the task type says so; a `chat` trigger always does | nothing: the owner approved the task type |
| Critical calls | approved by the user, or by a group | approved by a group: there is no user to ask |

The STS checks whoever starts the task, intersects the task type with the
agent's permissions, resolves references to the task's object, and issues a
grant. At call time a point of enforcement sends the call to the decision
core, which checks it against the grant, applies the operation's tier from
the manifest, and writes a decision record. A critical call opens an
approval.

The examples in [`examples/v0`](examples/v0) tell both stories. Alice asks
the assistant in `billing-app` to pay invoice `inv_7Q2M9X4K`, confirms it,
and the core allows a read, denies an overlarge payment and holds a 1,200 EUR
payment until Alice approves it. The `reconciler` runs `reconcile-day` at
night on its own service-account token, posts entries, and two people from
finance on-call approve a write-off.

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
  | `task_object` | equals the task's object ID; agents and task types only, resolved to `equals` in a grant |

  All bounds on a field must hold. A constrained field missing from the call
  fails the check.
- **Strict parsing.** Unknown fields are rejected. So are duplicate keys, in
  JSON and in YAML: two parsers reading one document differently is how a
  forged field gets past a check.
- **OAuth and OIDC shapes.** The grant is an RFC 9068 JWT access token
  (`typ: at+jwt`, with `client_id`), so ordinary resource servers can check
  it. Users are named with their identity provider (`sub_id`, RFC 9493),
  since an OIDC `sub` is unique only per issuer. A grant binds to a DPoP key.
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
equals the grant's locations, a user grant has `sub_id` and a service grant
has none, times come in order, an allowed decision has no failed check, a
manifest's path parameters match its routes, an approval's voters are
distinct and match its route, and `min ≤ max` everywhere.

Rules that need a second document belong to the features that load both: a
task type lying within an agent's permissions (F12), operations existing in
a manifest (F08), a request's trigger being one the task type allows (F11).
The hashes, key thumbprints and tokens in the examples have the right format
but are placeholders, not real values (F05, F10).

### Later

v0 covers the two ways of running an agent and nothing else. Each of these
is a known extension, and each adds fields or documents without changing
what is here:

| Extension | What it adds |
|---|---|
| Delegation between agents | optional `parent` and `depth` on a grant (a grant without them is a root), a nested `act.act`, `delegation` blocks on agents and task types, and an `Offer` record |
| A user's own envelope (mandate) | a `Mandate` document the user signs, intersected with the task type and the agent |
| mTLS-bound grants | `cnf.x5t#S256` beside `jkt` |
| X.509 SPIFFE identities | a `spiffe` identity type on agents |
| Session-bound revocation | `sid` on the grant, so an identity provider ending the session revokes the task |
| Allow-and-notify | `obligations` on an allowed decision |
| Scopes for plain resource servers | `scope` on the grant, derived from the actions |

## Layout

```
cmd/agentbox/      the CLI: validate, version
api/v0/            Go types of the v0 documents
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
