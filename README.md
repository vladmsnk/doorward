# Doorward

[![CI](https://github.com/vladmsnk/doorward/actions/workflows/ci.yml/badge.svg)](https://github.com/vladmsnk/doorward/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vladmsnk/doorward.svg)](https://pkg.go.dev/github.com/vladmsnk/doorward)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Doorward is an open-source authorization server and decision point for AI
agents.** It sits in front of a company's own tools (MCP servers and HTTP
APIs) and decides every agent call: which agent is calling, on whose behalf,
under which consent, within which limits, and which calls a person must
approve first. Every decision goes into a hash-chained journal that anyone
can verify offline.

Apache-2.0 · Go · PostgreSQL · **Status: early.** The decision core works;
the MCP gateway, the OAuth authorization server and the consent page are
being built ([roadmap](docs/ROADMAP.md)).

## Why Doorward

Most AI agents that touch a company's systems run somewhere else: Claude,
ChatGPT, Copilot, coding agents. The company owns the tools and the data,
not the agent. The control point it can always keep is in front of its own
tools. Doorward is that control point:

- **Least privilege per call**, not per API key: an agent gets a short-lived
  grant for one mandate, and every argument it sends is checked against it.
- **Human approval of the exact call** before anything critical runs, such as
  a payment or a write-off.
- **Budgets on what agents spend**, counted per grant, per day or per month.
- **Proof** of who did what, for whom, and who approved it.
- **No meters.** Nothing counts agents, calls, consents or approvals
  against a limit.

## Features

| Feature | Status |
|---|---|
| Per-call decisions over the [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) evaluation API (`POST /access/v1/evaluation`) | ✅ available |
| Argument limits on tool calls (`max`, `min`, `one_of`, `equals`, `prefix` on JSON Pointer paths), refused with a readable reason | ✅ available |
| Budgets: count and sum per grant, day or month; exact decimals, atomic, never overdrawn | ✅ available |
| Risk tiers (`read`, `write`, `critical`); a critical call needs approval of its exact arguments, then runs once on a single-use grant | ✅ decision · 🚧 approval page |
| Verifiable journal: RFC 8785 canonical JSON, SHA-256 hash chain, JSON Lines export, OpenTelemetry spans, a verifier that shares no code with Doorward | ✅ available |
| Agent registry: unverified, verified, suspended; owners; suspending an agent revokes its grants | ✅ available |
| Grants as RFC 9068 JWT access tokens with RFC 9396 `authorization_details`; ES256 keys, JWK Set, rotation | ✅ available |
| Upstream credentials sealed with AES-256-GCM; the agent never sees them | ✅ storage · 🚧 injection at the gateway |
| Versioned configuration through an Admin API; every change checked against the whole configuration | ✅ available |
| Observe mode: try a mandate or an agent without enforcing its rules; each record says what enforcement would have refused | ✅ available |
| MCP gateway; OAuth authorization server (RFC 9728, RFC 8414, Client ID Metadata Documents); consent page | 🚧 next |
| Kill switch, approval thresholds, notifications, admin sign-in | 📋 planned |
| Enterprise identity (ID-JAG), per-user upstream OAuth tokens, workload identities, DPoP | 📋 planned |

## How it works

```
 AI agent / MCP client ── OAuth ──▶ Doorward ──▶ Person consents to a mandate
   │  short-lived grant (JWT)
   ▼
 Gateway ── "may this call run?" ──▶ Doorward decision core ──▶ journal
   │      ◀── allow · deny + reason · approval required
   │  allowed call + upstream credential
   ▼
 Your MCP server or HTTP API
```

1. A company describes each tool in a **manifest** (operations, risk tiers,
   arguments) and what agents may do in a **mandate** (permissions, limits,
   budgets, approvers). A mandate's name is an OAuth scope.
2. A person **consents** once to a mandate for one agent. An agent acting for
   its owner presents its workload identity instead.
3. Doorward issues a **grant**: the mandate intersected with what the agent
   may ever hold, never more.
4. The gateway sends every call to the decision core. Each check (grant,
   subset, tier, budgets) passes or fails with a reason, and the decision is
   appended to the journal.
5. Allowed calls go upstream with a credential the agent never holds. A
   critical call is answered "approval required"; once a person approves
   that exact call, the agent's retry runs once.

The seven documents (Manifest, Agent, Mandate, Consent, Grant, Decision,
Approval) are described in [docs/concepts.md](docs/concepts.md).

## Quick start

Needs Go 1.25 and PostgreSQL 16. All of it runs on one machine with the
[examples](examples/v0): Alice lets Acme's `invoice-assistant` read and pay
her invoices, up to 5,000 EUR per payment.

```sh
git clone https://github.com/vladmsnk/doorward && cd doorward
make build
docker run -d --name doorward-db -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16

export DOORWARD_DB='postgres://postgres@localhost:5432/postgres?sslmode=disable'
export DOORWARD_ADMIN_TOKEN=$(openssl rand -hex 16)
export DOORWARD_MASTER_KEY=$(bin/doorward master-key)   # seals keys and secrets: keep it
export PEP_TOKEN=$(openssl rand -hex 16)                 # the gateway's own token
bin/doorward serve --pep gateway-1=$PEP_TOKEN --journal journal.jsonl > doorward.log 2>&1 &
```

Load the example configuration through the Admin API (it listens on
`127.0.0.1:8081` only):

```sh
H="Authorization: Bearer $DOORWARD_ADMIN_TOKEN"; A=localhost:8081/admin/v0
put() { curl -sS -o /dev/null -w "%{http_code} $2\n" -X PUT -H "$H" \
  -H "Content-Type: application/yaml" --data-binary @examples/v0/config/$1.yaml "$A/$2"; }
curl -sS -X PUT -H "$H" -d '{"value":"demo-key"}' "$A/secrets/ledger-mcp-api-key"
put manifest-payments-api     manifests/payments-api
put manifest-ledger-mcp       manifests/ledger-mcp
put mandate-invoices          mandates/invoices
put mandate-invoices-readonly mandates/invoices-readonly
put mandate-reconcile         mandates/reconcile
put agent-invoice-assistant   agents/invoice-assistant
put agent-reconciler          agents/reconciler
put agent-desk-helper         agents/desk-helper-7f3a
```

Mint Alice's grant (the token service will do this after the OAuth flow),
then ask about three calls as a gateway would:

```sh
bin/doorward grant mint --consent examples/v0/consent/alice-invoice-assistant.json \
  examples/v0/grant/pay-invoice.json > grant.jwt

call() { curl -sS localhost:8080/access/v1/evaluation -H "Authorization: Bearer $PEP_TOKEN" -d '{
  "subject":  {"type": "agent", "id": "invoice-assistant"},
  "action":   {"name": "'"$1"'"},
  "resource": {"type": "tool_call", "id": "https://payments.example.internal",
               "properties": {"arguments": '"$2"'}},
  "context":  {"token": "'"$(cat grant.jwt)"'"}}'; echo; }

call get_invoice '{"invoice_id": "inv_7Q2M9X4K"}'
call pay_invoice '{"invoice_id": "inv_7Q2M9X4K", "amount": 7500, "currency": "EUR"}'
call pay_invoice '{"invoice_id": "inv_7Q2M9X4K", "amount": 1200, "currency": "EUR"}'
bin/doorward journal verify journal.jsonl
```

```
{"decision":true,"context":{"outcome":"allow","limits":[{"name":"calls","consumed":1,"remaining":49}],…}}
{"decision":false,"context":{"outcome":"deny","reasons":[{"code":"constraint_violated","message":"7500 is above the grant's max of 5000","field":"/amount"}],…}}
{"decision":false,"context":{"outcome":"approval_required","approval":{"request":"apr_…"},…}}
3 records valid, chain intact from seq 0 to 2, head hash sha-256:…
```

The read is allowed and counted against the budget, the 7,500 EUR payment
is refused with its reason, and the 1,200 EUR payment opens an approval
request for that exact call.
[`scripts/verify-journal.py`](scripts/verify-journal.py) checks the same
journal with Python's standard library alone.

## What Doorward does not do

Doorward decides only on calls that pass through it, to tools a company has
described to it. It cannot see or stop:

- **Calls that never reach it**: an agent acting on its own machine (a
  shell, local files, stored credentials), or calling an API directly with a
  credential it already holds.
- **What the model decides**: prompt injection, a poisoned tool description,
  a hijacked goal. Doorward does not stop an agent from being manipulated; it
  bounds what a manipulated agent can do.
- **What a tool does with an allowed call**: a compromised server can misuse
  what it receives. A constraint that pins an argument, such as an email's
  recipient, narrows that; nothing removes it.

It is also not a full MCP gateway (no federation, API-to-MCP conversion or
tool search), not an identity provider (people sign in through your existing
OIDC provider), and not a general policy language.

## Standards

| Standard | Use in Doorward | Status |
|---|---|---|
| [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) | Evaluation endpoint between gateway and decision core | ✅ evaluation · 📋 batch, discovery, conformance |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens | Grant format (`typ: at+jwt`, ES256) | ✅ |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) Rich Authorization Requests | Permissions and constraints in grants (`authorization_details`) | ✅ |
| [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) Subject identifiers | Users named with their identity provider (`sub_id`) | ✅ |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON canonicalization | Action hashes and journal hash chain | ✅ |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint | Signing key IDs in the JWK Set | ✅ |
| [W3C Trace Context](https://www.w3.org/TR/trace-context/), OpenTelemetry | Trace ID in every record; a span per decision | ✅ |
| [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (2026-07-28) | Gateway and authorization server for MCP clients | 🚧 |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207), OAuth 2.1, Client ID Metadata Documents | Discovery, audience binding, client registration | 🚧 |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange, RFC 7523, ID-JAG | Workload agents and enterprise identity | 📋 |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP | Proof of possession, per agent or mandate | 📋 |

## FAQ

### How do I add authorization to an MCP server?

Put Doorward in front of it. Its gateway will publish the protected resource
metadata MCP clients look for, send users through OAuth and a consent page,
and check every `tools/call` against the agent's grant. The decision core
behind it works today; the gateway and authorization server are the next
step on the [roadmap](docs/ROADMAP.md).

### How is Doorward different from an MCP gateway?

A gateway routes and filters traffic. Doorward decides and records: consent,
argument limits, budgets, exact-call approval and a verifiable journal. Its
built-in gateway is deliberately thin, and other gateways can call its
AuthZEN endpoint instead.

### How is Doorward different from an identity provider such as Keycloak or Auth0?

An identity provider authenticates people and issues tokens. Doorward
federates sign-in to the one you already run and adds what happens per call:
mandates, argument limits, budgets, approvals and the record of every
decision.

### How is Doorward different from OPA, Cerbos or OpenFGA?

Those are general policy engines. Doorward is specific to agents acting for
people: consent to a mandate, grants derived from it, budgets on argument
values, and approval bound to one exact call. A general engine can be added
later as a second policy stage over AuthZEN.

### Does Doorward stop prompt injection?

No. It limits what a manipulated agent can do: which operations, with which
arguments, within which budgets, and which calls a person approves first.

### Which AI clients will it work with?

Any MCP client that follows the MCP authorization specification (Claude,
ChatGPT, VS Code, Cursor, Claude Code), once the gateway and authorization
server land. Agents you deploy yourself will authenticate with workload
tokens, such as Kubernetes service-account tokens.

### Is Doorward production-ready?

No. There is no tagged release yet, and the v0 contract may still change.

### How fast is a decision?

About 5 ms for one caller against a local PostgreSQL, including the HTTP
round trip, both sets of checks, the budget draw and the record. Decisions
that arrive together are settled in one transaction, so sixteen concurrent
callers get about 800 decisions a second and 256 about 1,300 on a shared
4-core machine; every record still joins one chain. Details and the
measurements are in [docs/decision-point.md](docs/decision-point.md).

## Documentation

- [Concepts](docs/concepts.md): the seven documents, how an agent gets authority, conventions
- [Grants and the decision point](docs/decision-point.md): checks, refusal codes, the evaluation API, the journal
- [Operating Doorward](docs/operations.md): Admin API, keys and secrets, storage, verifying a release
- [Roadmap](docs/ROADMAP.md): what is built next, in order, and why
- [Examples](examples/v0): every document, telling both stories (a user's assistant and a nightly service agent)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every commit is signed off under the
[Developer Certificate of Origin](DCO).

Development is AI-assisted: much of the code is written with Claude Code.
Every commit is authored and signed off by a human maintainer, who answers
for it (see [CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-development)).

## License

[Apache License 2.0](LICENSE).
