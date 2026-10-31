# Roadmap

What doorward builds next, in order. Each step is one pull request that
lands with its tests and a "how to validate" section, and depends only on
the steps above it. There are no dates: order is what matters.

## Aim

Companies will own their tools and data, not the agents that call them:
most agents will be hosted by someone else (Claude, ChatGPT, Copilot,
coding agents). The control point a company can always keep is on the
resource side, in front of its own tools. Doorward is that control point:
an authorization server agents connect to with standard OAuth, and a
per-call decision point that checks, holds for approval, and records every
call.

Doorward is the **decision, approval and evidence core**. Its gateway and
authorization server are deliberately thin, for a small company that has
neither, and each can be replaced through a standard interface: decisions
over AuthZEN 1.0, tokens as RFC 9068 JWTs with a JWK Set, login through
OIDC federation, records over OpenTelemetry. Doorward does not try to be a
full MCP gateway (routing, federation, LLM traffic) or a full identity
provider.

What sets it apart, and what no open-source project combines today:

- **One small vocabulary** of permissions and constraints that drives the
  consent text a person reads, the check that a mandate fits its agent,
  grant minting, and per-call enforcement with a reason per field.
- **Approval bound to the exact call**: a person approves one canonical
  call, by its hash, and it runs once.
- **Evidence that can be verified** by someone who does not trust the box.

## Where we are

| Step | | State |
|---|---|---|
| Contract v0 | schemas, Go types, examples, validator | on main |
| A1 | PostgreSQL storage | on main |
| A2 | Admin API with rules across documents | on main |
| A3 | CLI client of the Admin API | skipped; superseded by `doorward apply` (O1) |
| A4 | signing keys, sealed secrets, JWK Set | on main |
| B1 | grant verification | on main |
| B2 | subset check | on main |
| B3 | tiers, action hash, single-use grants | on main |
| P1–P7 | fail-open paths closed | on main |
| | commits authored and signed off by a person, checked in CI | on main |

## What changed from the first plan, and why

An outside review of the design (October 2026) agreed with the aim and the
token choices and corrected the order of work and the fit with real MCP
clients. The code findings it reported were checked against the source;
all of them hold. Its claims about the MCP specification and about client
behaviour were not checked here: each step that depends on one says so,
and starts by reading the specification text.

| Was | Now | Why |
|---|---|---|
| Control plane first, a demo at the very end | one end-to-end slice first: a real MCP client connects, the user consents, a call is refused, a payment is approved | nobody can see the product work until a call is blocked |
| Fail-open paths left for later tests | fixed first, each with a negative test | they sit in code the token service and gateway reuse |
| Grants bound to a DPoP key by default | Bearer by default; proof of possession required per agent or mandate; no `cnf` in a grant until the box verifies proofs | MCP clients send Bearer tokens; a token must not claim a binding nobody enforces |
| The gateway holds a critical call open and runs it once approved | approve, then the client's retry runs it, exactly once | clients time out long before a person answers, and a stored call has nowhere to send its result and can run twice |
| Dynamic client registration first | Client ID Metadata Documents first; registration kept for compatibility | the MCP specification moved to metadata documents |
| Decision endpoint shaped like AuthZEN | a conformant AuthZEN 1.0 decision point | so other gateways can use the core |
| Several grant entries may name one operation, bounds combined | one entry per operation in every grant | a reader that checks each entry on its own would allow too much |
| Journal chain over Go's JSON output, inside PostgreSQL only | RFC 8785 canonical JSON, exported records, signed checkpoints later | tamper evidence that survives a database administrator |
| Configuration only through the Admin API | the Admin API stays the only writer; `doorward apply -f DIR` drives it, with a diff | platform teams keep configuration in review |

## Phase P: close the fail-open paths

Each step adds a test that fails before the fix and passes after it. These
are the first cases of the negative-test catalogue.

| # | Step | What changes | How you validate |
|---|---|---|---|
| P1 | **Contradictory bounds deny** | Combining two constraints that cannot both hold (disjoint `one_of`, two different `equals`, prefixes that diverge, `min` above `max`) gives "unsatisfiable", never "unconstrained". The subset check refuses every call against it; the Admin API refuses a mandate or agent that contains one. | A grant whose two entries allow `currency` EUR and USD respectively: today any currency passes; after the fix every currency is refused with `constraint_violated`. |
| P2 | **One entry per operation** | `Grant.Check` rejects a grant that names the same operation at the same location twice. Minting merges each operation's bounds into one entry. The example grant is rewritten. | `doorward validate` refuses the old `pay-invoice.json` shape; the rewritten example passes; B2's tests still pass. |
| P3 | **Consent is checked fully** | Minting refuses an expired consent and a consent given to an older version of the mandate, and caps the grant's `exp` at the consent's expiry. The status check refuses a grant whose consent has expired or whose mandate is disabled. | Mint on an expired consent: refused. Widen the mandate, mint under the old consent: refused. Disable the mandate: the grant fails `status`. |
| P4 | **The whole configuration is checked, in one transaction** | Every Admin API write validates the configuration as it would be after the write, manifests included, while holding one configuration lock. A manifest can no longer drop an operation a mandate names, or raise an operation above an agent's ceiling. | PUT the payments manifest without `pay_invoice`: refused, naming the mandate. A test runs conflicting writes in parallel: one wins, the other is refused. |
| P5 | **Safe Admin API default** | The Admin API listens on `127.0.0.1:8081` unless told otherwise. | Start with defaults; the Admin API answers on localhost only. |
| P6 | **Honest grants** | Minted grants carry no `cnf`; the examples drop it; the README says grants are Bearer tokens until proof of possession is enforced. | Decode a minted grant: no `cnf`. |
| P7 | **README tells the truth** | The status table, the secret store (sealed in the database, not files), and a section on what doorward cannot see: calls that never leave a machine, prompt injection, a compromised server. Undefined "L1 to L5" levels are replaced by plain descriptions of the evidence each record carries. | Read it. |

## Phase B, continued: the decision core

| # | Step | What it adds | How you validate |
|---|---|---|---|
| B4 | **Budgets** | Counters per grant and, under a consent, per day and month, kept in exact decimal minor units and drawn in one atomic statement with no compensating second write. Drawn last, only for a call that is otherwise allowed. | 100 parallel calls against a budget of 50: exactly 50 pass. A refused or held call leaves every counter unchanged. 0.1 + 0.2 EUR is exactly 0.30 EUR. |
| B5 | **The evaluation endpoint and the journal** | `POST /access/v1/evaluation` in the AuthZEN 1.0 request and response shape, running B1 to B4 in order. Allowing a call spends its single-use grant and its budget together. Every answer appends a decision record, hashed as RFC 8785 canonical JSON, carrying the manifest and mandate version digests and the W3C trace ID. Records are also written to stdout as JSON lines. | `curl` the example requests: the three outcomes, with the example records' checks and reasons. A short script outside the box verifies the chain from the exported lines. A benchmark reports the time per decision. |

## Phase C: one vertical slice

At the end of this phase an off-the-shelf MCP client connects to a tool
with nothing but its URL, the user consents to a mandate, an over-limit
payment is refused with its reason, and a 1,200 EUR payment is approved
and runs exactly once.

Every step that implements part of the MCP authorization specification
starts by reading the current specification text and the client's
documentation, and records in the pull request what it checked.

| # | Step | What it adds | How you validate |
|---|---|---|---|
| C1 | **Thin MCP gateway** | A Streamable HTTP endpoint per manifest. It requires a Bearer grant, checks the audience, never passes the client's token on, adds the upstream credential from the secret store, filters `tools/list` to the grant, and sends each `tools/call` to the core, in process. A refusal comes back as a tool error with the reason. A demo invoices MCP server is included. | With a minted grant in MCP Inspector: only granted tools are listed; 7,500 EUR comes back refused with "7500 is above the grant's max of 5000"; the demo server's log shows the upstream key, never the grant. |
| C2 | **Protected resource metadata** | RFC 9728 metadata per audience: the box as authorization server, the mandates as `scopes_supported`, proof of possession not required. A 401 points to it; a call needing another mandate gets 403 `insufficient_scope` naming it, so the client asks the user for it. | `curl` without a token: 401 with the pointer; follow it. |
| C3 | **Authorization server metadata and login** | RFC 8414 metadata, PKCE S256 only, the RFC 9207 `iss` response parameter, and sign-in through an upstream OIDC provider (Dex in the quick start). | `curl` the metadata; sign in as alice through Dex. |
| C4 | **Clients that introduce themselves** | Client ID Metadata Documents: the box fetches the client's metadata from its URL, with private, loopback and link-local addresses refused, and records the client as an unverified agent with its publisher. Dynamic client registration stays as a compatibility path. | Register from a hosted metadata document: the registry shows an unverified agent. A metadata URL that resolves to 127.0.0.1 is refused. |
| C5 | **Authorize and consent** | Code flow with PKCE; the `resource` parameter becomes the audience; the scope names the mandate. An unverified agent may ask only for open mandates. The consent page shows the agent, its publisher, the redirect host, and the mandate's text; Allow records a consent naming the mandate version. | In a browser: ask for `invoices` as an unverified agent, refused; `invoices-readonly`, consent page; Allow writes a consent record. |
| C6 | **Token endpoint** | Code exchange and refresh with rotation. The grant is built as a pure function, mandate intersected with agent, one entry per operation, a `scope` claim, `exp` no later than the consent. Revoking a consent stops refresh. | Tests rebuild the example grants from the example configuration. **Milestone:** Claude Code and VS Code connect from the URL alone, Alice consents, tools are listed, 7,500 EUR is refused. |
| C7 | **Approvals by retry** | A critical call opens an approval for its canonical call and returns a tool error saying it is pending, with the approval link (HTTP manifests: 202 with `Location`). The approver page requires a recent sign-in and counts N of a group. When the same call is retried under the same grant, its hash matches the approved request; the single-use grant the box keeps for it is spent atomically, and the call is forwarded once, with the approval as idempotency key. | **Milestone:** 1,200 EUR held, Alice approves, the client retries, the demo server receives exactly one payment; another retry is refused. |
| C8 | **Quick start** | Container image; `docker compose up` with doorward, PostgreSQL, Dex and the demo server; walkthroughs for Claude Code and VS Code; the MCP authorization conformance scenarios in CI. | Someone new sees a blocked call within ten minutes. |

## Phase D: speak the standards, harden the evidence

| # | Step | What it adds |
|---|---|---|
| D1 | **AuthZEN decision point** | Batch evaluation and discovery; the OpenID Foundation conformance suite passing; a mapping of MCP tool calls onto subject, action, resource and context following the AuthZEN MCP profile; an Envoy `ext_authz` adapter; agentgateway tested as the point of enforcement. |
| D2 | **Approvals v2** | MCP Tasks and URL elicitation where clients support them; CIBA for approvers on another device; step-up (RFC 9470) with `acr`/`amr` recorded; an approval API shaped after the AuthZEN access-request profile; approvals triggered by constraints (an amount above a threshold) instead of a whole operation; allow-and-notify; approval rate as a metric. |
| D3 | **Evidence v2** | Signed checkpoints of the chain head; export to write-once storage; an offline verifier; an OCSF mapping; a retention policy; call arguments kept outside the chain, encrypted per user so they can be erased; the single chain lock replaced by a sharded or batched chain. |
| D4 | **Workload agents** | Kubernetes service-account tokens and JWT-SVIDs as client credentials (RFC 8693, RFC 7523); proof of possession end to end following the MCP DPoP profile, required per agent or mandate. |
| D5 | **Enterprise interop** | Accept identity assertion grants (MCP Enterprise-Managed Authorization) at the token endpoint; publish a Token Status List; emit CAEP events on revocation; Keycloak tested as the authorization server. |
| D6 | **Operability** | `doorward apply -f DIR` with diff and prune, in one transaction; OIDC sign-in for administrators, each change attributed to a person; master key from a KMS or OpenBao Transit; key rotation that publishes the next key before using it; a Helm chart; cached status. |
| D7 | **Rules without hand-writing** | Manifest import from OpenAPI and MCP `tools/list`, unknown operations defaulting to critical; mandate templates; mandates proposed from a week of observed calls; replay of a configuration change against the journal before applying it; tool-description pinning; unregistered clients shown as discovered agents. |
| D8 | **Conformance bench and governance** | A suite of agent-authorization failure modes run against doorward and at least two other gateways, results published; GOVERNANCE.md; a second maintainer from another organization. |

## Later

Agent-to-agent delegation once an actor-chain draft converges; Transaction
Tokens and Identity Chaining; mTLS and X.509 SPIFFE identities; fronting
A2A agents; signed outbound requests to commerce APIs; portable signed
mandate receipts; transparency-log witnesses for checkpoints; Cedar or OPA
as a second policy stage; a Kubernetes controller over `apply`; users
narrowing a mandate on the consent page; per-call data scoping.

**Open question:** an embedded store for a five-minute evaluation mode.
The storage decision so far is PostgreSQL only; the quick start's compose
file may make this unnecessary.

## Not doing

- A full MCP gateway: routing, federation, server catalogues, LLM traffic.
- A general policy language: the constraint set stays closed, and a second
  policy stage goes to Cedar or OPA over AuthZEN.
- A gateway that executes stored calls with no client waiting.
- Language SDKs, until workload users ask for a sidecar.
