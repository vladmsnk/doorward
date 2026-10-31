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
`taskrequest`, `grant`, `offer`, `decision` or `approval`.

Go 1.24 and, for `make lint`, golangci-lint v2.

## The v0 schemas

Nine documents, as JSON Schema (draft 2020-12) in [`schema/v0`](schema/v0)
with matching Go types in [`api/v0`](api/v0). Four are configuration a
company writes, in YAML or JSON; the other five are messages and records,
in the order one task produces them.

| Document | Written by | What it is |
|---|---|---|
| [Manifest](schema/v0/manifest.schema.json) | company | The operations one resource exposes (MCP tools or HTTP routes), the sensitivity tier of each, and where their constrainable arguments are |
| [TaskType](schema/v0/tasktype.schema.json) | company | A kind of task an application may start: the object it is about, who may start it, its lifetime, permissions, shared limits, delegation plan and approvers |
| [Boundary](schema/v0/boundary.schema.json) | company | One agent: how it proves who it is, who owns it, and the most it may ever be granted |
| [Application](schema/v0/application.schema.json) | company | An application that starts tasks: how it authenticates, and which identity providers vouch for its users |
| [TaskRequest](schema/v0/taskrequest.schema.json) | the application | The RFC 8693 token exchange that starts a task for a user and an agent |
| [Grant](schema/v0/grant.schema.json) | the STS | Claims of the short-lived, key-bound JWT access token (RFC 9068) an agent's sidecar holds for one task |
| [Offer](schema/v0/offer.schema.json) | the agent and the STS | A delegation offer: a narrower grant proposed for one named recipient |
| [Decision](schema/v0/decision.schema.json) | the decision core | The record of one decision, with every element level L1 asks for |
| [Approval](schema/v0/approval.schema.json) | the approval service | The record of one approval request: the exact call, who voted, how each of them signed in |

How they fit together: an application starts a task with a token exchange
that carries the user's identity token and names a task type, an object and
an agent. The STS checks the application and the user, intersects the task
type with the agent's boundary, resolves references to the task's object,
and issues a grant. At call time a point of enforcement sends the call to the
decision core, which checks it against the grant, applies the operation's
tier from the manifest, and writes a decision record. A critical call opens
an approval; an agent hands work on through an offer. The examples in
[`examples/v0`](examples/v0) follow one such task end to end: `billing-app`
starts `pay-invoice` for Alice, `invoice-agent` receives the root grant and
offers a read-only grant to `ledger-agent`, and the core allows one call,
denies one, and holds one until two approvers say yes.

### Conventions

- **Permissions** are RFC 9396 `authorization_details`: `locations`
  (audiences), `actions` (operation names, never wildcards) and
  `constraints`.
- **Constraints** are keyed by the argument's JSON Pointer and use a closed
  set of types, each of which can be compared with a narrower one. That is
  what keeps "request ⊆ grant" and narrowing on delegation decidable:

  | Type | Meaning |
  |---|---|
  | `max`, `min` | numeric bounds, inclusive |
  | `one_of` | the value is one of a list |
  | `equals` | the value is exactly this |
  | `prefix` | a string starts with this |
  | `task_object` | equals the task's object ID; boundaries and task types only, resolved to `equals` in a grant |

  All bounds on a field must hold. A constrained field missing from the call
  fails the check.
- **Strict parsing.** Unknown fields are rejected. So are duplicate keys, in
  JSON and in YAML: two parsers reading one document differently is how a
  forged field gets past a check.
- **OAuth and OIDC shapes.** The grant is an RFC 9068 JWT access token
  (`typ: at+jwt`, with `client_id`), so ordinary resource servers can check
  it. Users are named with their identity provider (`sub_id`, RFC 9493),
  since an OIDC `sub` is unique only per issuer, and the grant keeps how they
  signed in (`acr`, `amr`, `auth_time`) and their session (`sid`). A grant
  binds to a DPoP key or an mTLS certificate. Agents authenticate with the
  box's own registration, an IdP client, a workload JWT or a SPIFFE ID.
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
equals the grant's locations, `scope` names nothing the grant does not, a
root grant is its own root, times come in order, an allowed decision has no
failed check, a manifest's path parameters match its routes, an approval's
voters are distinct and never the user, and `min ≤ max` everywhere.

Rules that need a second document belong to the features that load both: a
task type lying within each agent's boundary (F12), operations existing in a
manifest (F08), a child grant or offer lying within its parent (F15, F23).
The hashes, key thumbprints and tokens in the examples have the right format
but are placeholders, not real values (F05, F10).

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
