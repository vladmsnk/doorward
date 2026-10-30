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
bin/agentbox validate --kind decision examples/v0/decision/*.json
```

Go 1.24 and, for `make lint`, golangci-lint v2.

## The v0 schemas

Five documents, as JSON Schema (draft 2020-12) in [`schema/v0`](schema/v0)
with matching Go types in [`api/v0`](api/v0). Three are written by the
company, in YAML or JSON; two are produced by the box.

| Document | Written by | What it is |
|---|---|---|
| [Manifest](schema/v0/manifest.schema.json) | company | The operations one resource exposes (MCP tools or HTTP routes), the sensitivity tier of each, and where their constrainable arguments are |
| [TaskType](schema/v0/tasktype.schema.json) | company | A kind of task an application may start: the object it is about, who may start it, its lifetime, permissions, shared limits and delegation plan |
| [Boundary](schema/v0/boundary.schema.json) | company | The most one agent may ever be granted, and who owns the agent |
| [Grant](schema/v0/grant.schema.json) | the STS | Claims of the short-lived, key-bound JWT an agent's sidecar holds for one task |
| [Decision](schema/v0/decision.schema.json) | the decision core | The record of one decision, with every element level L1 asks for |

How they fit together: an application starts a task by naming a task type
and an object ID. The STS intersects the task type with the agent's boundary,
resolves references to the task's object, and issues a grant. At call time a
point of enforcement sends the call to the decision core, which checks it
against the grant, applies the operation's tier from the manifest, and writes
a decision record. The examples in [`examples/v0`](examples/v0) follow one
such task end to end: `billing-app` starts `pay-invoice` for Alice,
`invoice-agent` receives the root grant and delegates a read-only grant to
`ledger-agent`, and the core allows one call, denies one, and holds one for
approval.

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
- **Records have one serialization.** Decision times are UTC with exactly
  millisecond precision, since records are hash-chained.
- **The schemas are the contract.** The Go types mirror them, and
  [`schema/drift_test.go`](schema/drift_test.go) fails the build when the two
  disagree on a field, on whether it is required, or on an enum's members.

### Using the schemas from Go

```go
v, err := schema.NewValidator()
if err != nil { ... }
grant, err := schema.Decode[v0.Grant](v, claimsJSON) // duplicate keys, schema, then strict decode
```

### What v0 does not check

The schemas check each document's shape. Rules that span documents, or need
arithmetic, belong to the features that use them: a task type's permissions
lying within each agent's boundary (F12), operations existing in a manifest
(F08), `min ≤ max`, a child grant being narrower than its parent (F15, F23).
The hashes and key thumbprints in the examples have the right format but are
placeholders, not computed values (F05, F10).

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
