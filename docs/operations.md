# Operating doorward

Running the box: the Admin API, signing keys and sealed secrets, storage, and verifying a release.

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
export DOORWARD_DB=postgres://… DOORWARD_ADMIN_TOKEN=$(openssl rand -hex 16)
export DOORWARD_MASTER_KEY=$(doorward master-key)   # keep it: it seals the signing keys and secrets
doorward serve                                      # public listener on :8080, Admin API on 127.0.0.1:8081

H="Authorization: Bearer $DOORWARD_ADMIN_TOKEN"
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

Authentication is a bootstrap bearer token for now (`DOORWARD_ADMIN_TOKEN`);
administrators from the identity provider come with the consent work.

## Keys and secrets

On first start the box creates an ES256 signing key, and publishes the
public half at `/.well-known/jwks.json` on the public listener; the `kid`
is the key's RFC 7638 thumbprint. Rotation makes a new key active and keeps
the old one published, so grants it signed still verify, until an
administrator retires it. Private keys and upstream secrets are sealed with
AES-256-GCM under the operator's master key (`DOORWARD_MASTER_KEY`) before
they reach the database, each bound to its own slot, so the database never
holds them in clear and a value cannot be moved from one slot to another.

## Storage

Everything the box keeps lives in one PostgreSQL database, behind the
`store.Store` interface in [`internal/store`](../internal/store): configuration
(manifests, agents, mandates), versioned so nothing is ever overwritten and
a consent can name the exact mandate the user saw; and the records
(consents, grants, decisions, approvals) plus the budget counters. Decision
records form a hash chain; `v0.Verify` checks it. Migrations are embedded
and applied on start.

## Verifying a release

Pushing a `v*` tag builds Linux and macOS binaries with GoReleaser and signs
the checksum file with cosign's keyless flow. The signing certificate binds
the signature to this repository's release workflow. A tag with a suffix,
such as `v0.0.1-test.1`, makes a prerelease.

To verify a download:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/vladmsnk/doorward/\.github/workflows/release\.yml@refs/tags/v'
sha256sum --check --ignore-missing checksums.txt
```

## Stopping, and what the log says during an outage

On SIGTERM doorward stops at once unless `--shutdown-delay` is set. Behind
a load balancer set it to a few seconds (5 s is usual): from the signal on,
`/healthz` answers 503 "stopping" while decisions are still served, so the
balancer stops sending before the listeners close, and in-flight calls
finish. The journal follower drains before the process exits.

Warnings and errors in the log are sampled: one line per message per
second, and the next line of that message carries `suppressed`, the number
dropped in between. An outage therefore costs a few lines a second rather
than two per failed call. Informational lines are never sampled.
