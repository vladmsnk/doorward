# Roadmap

What doorward builds next, in order. Each step is one pull request that
lands with its tests and a "how to validate" section, and depends only on
the steps above it. There are no dates: order is what matters. A step that
changes the contract (a schema field, a record shape) lands that change
first, in its own pull request.

## Aim

Companies will own their tools and data, not the agents that call them:
most agents will be hosted by someone else. The control point a company can
always keep is on the resource side, in front of its own tools. Doorward is
that control point: an authorization server agents connect to with standard
OAuth, and a per-call decision point that checks, holds for approval, and
records every call.

Doorward is the **decision, approval and evidence core**. Its gateway and
authorization server are deliberately thin, for a company that has neither,
and each can be replaced through a standard interface: decisions over
AuthZEN 1.0, tokens as RFC 9068 JWTs with a JWK Set, login through OIDC
federation, records over OpenTelemetry. It is not a full MCP gateway or a
full identity provider.

## What doorward gives away

Agent authorization is sold in two halves. The plumbing (OAuth front door,
token exchange, gateway, credential injection, call logs) is cheap or free
almost everywhere. The governance half is where enterprise tiers, add-ons
and separate subscriptions begin: human approval, admin single sign-on,
per-user upstream OAuth, long audit retention, agent owners, access
reviews, kill switches, multiple budget windows, tool pinning. Doorward
sits in the call path, where it sees the grant, the call and the approval
together, so it gives the governance half away and leads with it.

- **No meters.** Nothing in doorward counts agents, consents, tool calls,
  upstream connections, tokens or approvals against a limit.
- **The usually gated features are ordinary steps below.** Each step's
  "Class" says whether it is table stakes (**T**), usually sold behind an
  enterprise gate (**G**), or a differentiator no product we reviewed
  documents (**D**).
- **What doorward does not build, it plugs into** through standards (see
  [Sockets](#sockets-not-rebuilds)): discovery outside the call path,
  risk signals from many customers, ML guardrails, managed OAuth-app
  catalogues, hosted compliance.

What no product we reviewed documents, and doorward builds on one small
vocabulary:

- consent by a person to a constrained mandate, checked again at every call;
- budgets on sums of a call's arguments, per grant and per consent;
- approval bound to the hash of one exact call, spent once through a
  single-use grant, with an N-of-group quorum, the approver's
  authentication strength recorded, and a WebAuthn countersignature over
  the call hash, so not even the operator can forge an approval;
- signed decision records anyone can verify offline;
- right-sizing from what agents were granted against what they used.

## Where we are

| Step | | State |
|---|---|---|
| Contract v0 | schemas, Go types, examples, validator | done |
| A1, A2, A4 | PostgreSQL storage; Admin API with whole-configuration rules; signing keys, sealed secrets, JWK Set | done |
| B1, B2, B3 | grant verification; subset check; tiers, action hash, single-use grants | done |
| B4 | budgets: exact, atomic, drawn last with the single-use grant | done |
| B5 | AuthZEN evaluation endpoint; journal in RFC 8785, exported and verifiable outside the box; tracing | done |
| P1–P7 | fail-open paths from the first review closed, each with a negative test | done |
| | commits authored and signed off by a person, checked in CI | done |

**Next: B6, observe mode.**

## The build order at a glance

| Phase | Ends when |
|---|---|
| **B.** Finish the decision core | every call gets an AuthZEN answer and a chained record; budgets are exact |
| **C.** First slice, with the small give-aways | an off-the-shelf MCP client connects from a URL, Alice consents, an over-limit payment is refused with its reason, a 1,200 EUR payment is approved and runs once, and a newcomer sees it in ten minutes |
| **D.** Enterprise identity and the token vault | an enterprise IdP's assertion and a Kubernetes token both get grants; each user's own upstream OAuth token is used for their calls |
| **E.** Standard decision point and approvals v2 | doorward passes the AuthZEN conformance suite; approvals are countersigned, quorum-based, and work on another device |
| **F.** Evidence v2 | a record's inclusion and the log's consistency can be proven offline; an evidence bundle exports |
| **G.** Lifecycle governance and right-sizing | agents have owners and expiry, are reviewed, and get narrower mandates from their own usage |
| **H.** Policy and budget breadth | the constraint and budget vocabulary covers recipients, lists, windows and time |
| **I.** Sockets | risk signals, guardrail hooks, discovered agents and dynamic credentials plug in through standards |
| **O.** Operability and project health | configuration as code, managed keys, Helm, a public conformance bench |

D to O follow the order given, which is the recommended one; steps inside
them do not depend on each other unless a step says so. If the first slice
is at risk, C12 (admin sign-in) and C5's discovered-agents view slip first.

Every step that implements part of the MCP or OAuth specifications starts
by reading the current specification text and the client's documentation,
and records in the pull request what it checked.

## Phase B: finish the decision core

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| B4 | **Budgets** | Counters per grant and, under a consent, per day and month, kept in exact decimal minor units and drawn in one atomic statement with no compensating second write. Drawn last, only for a call that is otherwise allowed. | D | 100 parallel calls against a budget of 50: exactly 50 pass. A refused or held call leaves every counter unchanged. 0.1 + 0.2 EUR is exactly 0.30 EUR. |
| B5 | **Evaluation endpoint and journal** | `POST /access/v1/evaluation` in the AuthZEN 1.0 shape, running B1 to B4 in order. Allowing a call spends its single-use grant and its budget together. Every answer appends a record hashed as RFC 8785 canonical JSON, with the user and the agent, the manifest and mandate version digests and the W3C trace ID. Records are exported as JSON lines and OpenTelemetry. | T, D | `curl` the example requests: the three outcomes, with the example records' checks and reasons. A script outside the box verifies the chain from the exported lines. A benchmark reports the time per decision. |
| B6 | **Observe mode** | A flag on an agent or a mandate: the core decides and records what it would have done, and the call goes through. Records say they were observed, not enforced. An agent cannot be observed and enforced at once, and a tool marked "always ask" (E6) is never observed. | — | An over-limit call in observe mode passes, and its record says it would have been denied with `constraint_violated`. |

## Phase C: the first slice, with the small give-aways

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| C1 | **Thin MCP gateway** | A Streamable HTTP endpoint per manifest. It requires a Bearer grant, checks the audience, never passes the client's token on, adds the upstream credential from the secret store, filters `tools/list` to the grant, and sends each `tools/call` to the core in process. A refusal comes back as a tool error with its reason. A demo invoices MCP server is included. | T | With a minted grant in MCP Inspector: only granted tools are listed; 7,500 EUR is refused with "7500 is above the grant's max of 5000"; the demo server's log shows the upstream key, never the grant. |
| C2 | **Manifests from `tools/list`, with default tiers** | `doorward import mcp URL` drafts a manifest from a server's tools: parameters from each `inputSchema`; `readOnlyHint` gives read, `destructiveHint` gives critical, everything else write. The hints are treated as untrusted suggestions: the draft is a diff an administrator applies. A "reads pass, writes ask" mandate template. | G | Import the demo server: the draft shows its tools with tiers; apply it; a tool without hints comes out as write, never read. |
| C3 | **Protected resource metadata** | RFC 9728 metadata per audience: the box as authorization server, the mandates as `scopes_supported`, proof of possession not required. A 401 points to it; a call that needs another mandate gets 403 `insufficient_scope` naming it, so the client asks the user. | T | `curl` without a token: 401 with the pointer; follow it. |
| C4 | **Authorization server metadata and login** | RFC 8414 metadata, PKCE S256 only, the RFC 9207 `iss` parameter, and sign-in through an upstream OIDC provider (Dex in the quick start), with the user's groups. | T | `curl` the metadata; sign in as alice through Dex. |
| C5 | **Clients that introduce themselves; discovered agents** | Client ID Metadata Documents first, fetched with private, loopback and link-local addresses refused; dynamic client registration kept for compatibility. A new client becomes an unverified agent. The Admin API lists unverified agents with first and last seen and the calls they attempted. | T | Register from a hosted metadata document: the agent appears as discovered and unverified. A metadata URL that resolves to 127.0.0.1 is refused. |
| C6 | **Authorize and consent** | Code flow with PKCE; `resource` becomes the audience; the scope names the mandate. An unverified agent may ask only for open mandates. A mandate can be limited to users in given IdP groups. The consent page shows the agent, its publisher, the redirect host and the mandate's text; Allow records a consent naming the mandate version. | T | As an unverified agent ask for `invoices`: refused; `invoices-readonly`: consent page. A user outside the mandate's group is refused. Allow writes a consent record. |
| C7 | **Token endpoint** | Code exchange and refresh with rotation. The grant is built as a pure function: mandate intersected with agent, one entry per operation, a `scope` claim, `exp` no later than the consent. Revoking a consent stops refresh. | T | Tests rebuild the example grants from the example configuration. **Milestone:** Claude Code and VS Code connect from the URL alone, Alice consents, tools are listed, 7,500 EUR is refused. |
| C8 | **Kill switch** | Freeze one agent, one operation, or everything, with one Admin API call. Freezing revokes the affected grants and is checked on every call; a frozen state fails closed. | T, G | Freeze `pay_invoice`: the next call is refused and the tool disappears from `tools/list`; unfreeze restores it. Freeze everything: every call is refused. |
| C9 | **Approvals by retry** | A critical call opens an approval for its canonical call and returns a tool error saying it is pending, with the approval link (HTTP manifests: 202 with `Location`). The approver page requires a recent sign-in. When the same call is retried under the same grant, its hash matches the approved request; the single-use grant the box keeps for it is spent atomically, and the call is forwarded once, the approval ID as idempotency key. | D | **Milestone:** 1,200 EUR is held, Alice approves, the client retries, the demo server receives exactly one payment; another retry is refused. |
| C10 | **Approval thresholds** | A mandate can say when a call needs approval from its arguments: allow below X, ask between X and Y, refuse above Y. A whole operation can still always ask. | T | With "ask above 1000": 200 EUR runs, 1,200 EUR is held, 7,500 EUR is refused. |
| C11 | **Notifications** | Email and a signed webhook when an approval is waiting, each with a link to the approval page. The approval itself always happens on doorward's page, never in the message. | T | Hold a payment: the webhook receiver gets the request with a valid signature and the link; the email arrives in the quick start's mail catcher. |
| C12 | **Admin sign-in** | Administrators sign in with OIDC; every change is attributed to a person; roles for viewer, approver and administrator. The bootstrap token stays for first setup. | G | Change a mandate signed in as alice: `…/versions` names alice; a viewer's write is refused. |
| C13 | **Quick start** | Container image; `docker compose up` with doorward, PostgreSQL, Dex, a mail catcher and the demo server; walkthroughs for Claude Code and VS Code; the MCP authorization conformance scenarios in CI; signed releases with an SBOM. | G | **Milestone:** someone new sees a blocked call and approves a payment within ten minutes. |

## Phase D: enterprise identity and the token vault

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| D1 | **Accept enterprise identity assertions** | The JWT-bearer grant (RFC 7523) with identity assertion grants (ID-JAG, MCP Enterprise-Managed Authorization): type, signature, issuer, audience, client binding, resource, lifetime and replay checked. | T | A test IdP mints an assertion; it is exchanged for a grant. A replayed assertion, one for another audience, or one bound to another client is refused. |
| D2 | **Per-user upstream connections** | Each user connects their own account at an upstream that uses OAuth: connect flow started by URL elicitation or a link, refresh tokens sealed per user, rotation, revocation, injected per call in place of a shared secret. The callback is bound to the session that started it. | T, G | Alice and Bob each connect the demo OAuth upstream: Alice's calls carry her token, Bob's his. Revoke Alice's connection: her next call asks her to reconnect. A callback replayed from another session is refused. |
| D3 | **Workload agents** | Kubernetes service-account tokens, SPIFFE JWT-SVIDs and AWS STS tokens as client credentials (RFC 7523) and in token exchange (RFC 8693). Proof of possession (DPoP) required per agent or mandate and checked end to end, following the MCP DPoP profile. | T | The reconciler exchanges its service-account token for a service grant. For an agent that requires DPoP, a call without a proof, or with a replayed one, is refused. |
| D4 | **On-behalf-of upstream tokens** | For an upstream that accepts it, the gateway exchanges a permitted call's grant for a token minted for that upstream, with the user as subject and the agent in `act` (RFC 8693), instead of a shared secret. | T, G | The demo upstream sees `sub` alice, `act` the agent, `aud` itself, and nothing it could replay elsewhere. |

## Phase E: standard decision point and approvals v2

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| E1 | **AuthZEN 1.0 decision point** | Batch evaluation and discovery; the OpenID Foundation conformance suite passing; MCP tool calls mapped onto subject, action, resource and context following the AuthZEN MCP profile; approval requests shaped after the access-request profile; an Envoy `ext_authz` adapter; agentgateway tested as the point of enforcement. | G | The conformance suite passes. With agentgateway in front, an over-limit call is refused by doorward's decision. |
| E2 | **Countersigned approvals** | The approver signs the call hash with a WebAuthn assertion; the record keeps the assertion, `acr`, `amr` and the age of the sign-in; a sign-in older than the mandate allows triggers step-up (RFC 9470). | D | An approval verifies offline against the approver's public key; changing one argument of the call breaks it; an approval inserted directly into the database does not verify. |
| E3 | **Quorum and four eyes** | N distinct approvers from a group; the requester and the agent's owner cannot approve. | D | The write-off needs two people from finance; a second vote by the same person, or a vote by the agent's owner, is refused. |
| E4 | **Pending in the protocol** | MCP Tasks, and multi-round-trip requests with URL elicitation and integrity-protected, one-time request state, where the client supports them; the retry flow of C9 stays for every other client. | D | In a client with Tasks, a held payment shows as a running task that completes after approval. |
| E5 | **Approvers on another device** | CIBA to the company's IdP, and an installable approval page with Web Push and WebAuthn instead of a native app. | G | An approval request reaches a phone; approving there releases the retry. |
| E6 | **Approve for a window; guard rails** | A scoped multi-use grant: a time limit, a count, the same constraints, recorded as weaker than an exact-call approval. An organisation-wide "always ask" that no window, rule or scorer overrides. After repeated refusals the agent is frozen and a person is notified. Gated tools are marked for clients that can show it. | T | A 30-minute, 5-call window: the sixth call is held. An "always ask" tool still asks inside a window. Three refusals in a row freeze the agent. |
| E7 | **Approve with edit** | The approver may change arguments; the edited call gets its own hash and single-use grant; the record keeps both hashes. | G | Approve 1,200 EUR edited to 1,000 EUR: only the 1,000 EUR call runs, and the record names both. |
| E8 | **Chat notifications** | Slack, Microsoft Teams and PagerDuty notifications, each linking to the approval page. | T | A held call posts to a test Slack workspace with the link. |

## Phase F: evidence v2

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| F1 | **Signed checkpoints and proofs** | Records in an RFC 6962-style Merkle tree; checkpoints in the C2SP signed-note format, published outside the database; inclusion and consistency proofs; an offline verifier. The single chain lock gives way to batched appends. | D | The verifier proves a record's inclusion from an export. A record rewritten in the database is detected against a published checkpoint. Appends no longer serialize every decision. |
| F2 | **Arguments outside the chain** | Call arguments stored apart, encrypted per user, so a user's data can be erased by destroying their key while every record still verifies. Approval pages show redacted fields. | — | Erase Alice: her arguments are unreadable and the chain still verifies. |
| F3 | **Retention and export** | Retention policy, legal hold, write-once export (S3 Object Lock or similar), syslog, and an OCSF mapping of decision and approval events. | G | Records past retention are removed except under hold; an OCSF event validates against the schema. |
| F4 | **Evidence bundle** | `doorward evidence export`: inventory, owners, consents, approvals with authentication strength, revocations, mandate changes, a signed checkpoint, the verifier, and a table mapping them to the EU AI Act's logging and oversight articles, ISO/IEC 42001 and SOC 2. A mapping, never a certification claim. | D | The bundle verifies offline on another machine. |

## Phase G: lifecycle governance and right-sizing

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| G1 | **Owners, sponsors and expiry** | Required owner and sponsor, an expiry date, autonomy and criticality on every verified agent, with policy defaults (for example, high autonomy means approval for critical operations). | T, G | The Admin API refuses a verified agent without a sponsor; an agent past its expiry is refused on its next call. |
| G2 | **Offboarding** | Agents are suspended when their owner leaves (SCIM deprovisioning or Shared Signals account events from the IdP) and retired after N idle days. | G | Deprovision the owner in the test IdP: the agent is suspended and its grants fail. |
| G3 | **Access reviews** | Owners re-certify each agent's mandates on a schedule, or the mandates lapse. | G | Let a review lapse: the agent loses the mandate; certify it: the mandate stays. |
| G4 | **Right-sizing** | Compares what each agent was granted with what it used (operations, argument ranges, budgets) and proposes a narrower mandate; a proposed change is replayed against the journal before it is applied, showing which past calls it would have refused or held. | D | After a week of demo traffic, the proposal drops the unused operations and lowers the amount bound; the replay lists what would have changed. |
| G5 | **Tool pinning** | The hash of each tool's name, description and `inputSchema` is part of the manifest version a consent names; a changed tool is quarantined until an administrator approves the new definition. | G | Change the demo tool's description upstream: the tool disappears from `tools/list` until it is approved. |
| G6 | **Metrics** | Prometheus and OpenTelemetry metrics: decisions by outcome, approval rate and time to approve, refusals by reason, budget burn. | G | Scrape `/metrics` while the quick start runs. |

## Phase H: policy and budget breadth

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| H1 | **More constraint types** | `not_one_of`, `suffix` (an email domain), `each` (every item of a list), forced values (the box sets an argument), and `regex` where "within" compares only identical patterns or literal values; mandates are checked against each tool's `inputSchema` when written. | T, D | Every recipient must end in `@acme.com`: a list with one outside address is refused, naming it. |
| H2 | **Budget windows** | Rolling and weekly windows, several windows on one budget, a reset time zone, velocity per minute or hour, and soft-limit alerts by webhook. | G | 80% of a budget sends the alert; a burst above the per-minute velocity is refused while the monthly budget still has room. |
| H3 | **Budgets per argument value** | A budget kept separately per value of an argument, such as per payee or per merchant. | G | 500 EUR per payee per day: a second payee still has its own 500. |
| H4 | **Time constraints** | Not before, not after, time of day, and N runs per period. | T | A mandate valid on weekdays 08:00–18:00 refuses a Saturday call. |

## Phase I: sockets

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| I1 | **Shared Signals** | A receiver for CAEP and RISC events that feeds risk into the decision context and revokes on session or account events; CAEP `session-revoked` emitted on revocation; a published Token Status List. | G | A test transmitter marks Alice's session revoked: her next call is refused. |
| I2 | **Guardrail hooks** | Pre- and post-call hooks for guardrails, data-loss checks and redaction, using the AuthZEN request shape; fail open or closed per hook, always closed for critical operations; a hook can refuse or route to approval, never approve. | T | A hook that times out on a critical call refuses it; a hook that redacts a field changes what the upstream receives. |
| I3 | **Discovered-agent import** | An endpoint that records agents found by other tools as discovered and unverified. | — | Import a scanner's report: its agents appear next to self-registered ones. |
| I4 | **Connector manifests** | A community catalogue of upstream OAuth providers (endpoints, scopes, quirks) for D2, used with the company's own OAuth clients, so refresh tokens never pass through a third party. | — | Connect a catalogued provider with nothing but the company's client ID and secret. |
| I5 | **Dynamic upstream credentials** | Credential sources that mint per call: AWS STS with a session policy, GCP short-lived tokens, GitHub App installation tokens, OpenBao or Vault dynamic secrets. | G | Each call to an AWS-backed tool gets a fresh STS credential scoped by session policy. |

## Phase O: operability and project health

| # | Step | What it adds | Class | How you validate |
|---|---|---|---|---|
| O1 | **Configuration as code** | `doorward apply -f DIR` with a diff and `--prune`, applied through the Admin API in one transaction. | — | Apply the examples twice: the second run changes nothing; delete a file and apply with prune: the document is disabled. |
| O2 | **SAML and SCIM** | Through the federated login provider, not inside doorward: a tested Keycloak configuration and documentation. | G | Sign in through Keycloak federated to a SAML test IdP; deprovision through SCIM reaches G2. |
| O3 | **Managed keys** | The master key from a KMS or OpenBao Transit; key rotation that publishes the next key before using it. | — | Rotate: tokens signed by the new key verify at a resource server that cached the key set before the rotation. |
| O4 | **Helm and status off the hot path** | A Helm chart; cached grant status, so a decision touches the database only to record and to spend. | G | A benchmark shows fewer queries per decision with the same results. |
| O5 | **Conformance bench and governance** | A suite of agent-authorization failure modes (fail-closed behaviour, wrong-audience tokens, replay, exact-call binding, budgets that fail open) run against doorward and at least two other gateways, results published; GOVERNANCE.md; a second maintainer from another organisation. | D | The bench runs in CI and publishes its results. |

## Sockets, not rebuilds

Some things depend on assets an open-source project cannot build:
telemetry from many customers, sensors on laptops, trained models, vendor
OAuth apps, an audited hosted service. Doorward plugs into them through
standards and stays the decision of record.

| What it depends on | Socket | Step |
|---|---|---|
| Discovery outside the call path (SaaS grants, cloud agent platforms, laptops) | Import of discovered agents | I3 |
| Risk signals across many customers | Shared Signals (CAEP, RISC) into the decision context | I1 |
| ML guardrails, data-loss classifiers, server reputation | Pre- and post-call hooks | I2 |
| Provider-verified OAuth apps at catalogue scale | Connector manifests with the company's own OAuth clients | I4 |
| Identities native to a cloud or an IdP | ID-JAG, RFC 7523 assertions, SPIFFE JWT-SVIDs | D1, D3 |
| A mobile authenticator app | CIBA to the existing IdP; Web Push with WebAuthn | E5 |
| A hosted service with attestations | Signed releases, SBOM, the evidence bundle | C13, F4 |
| Sandboxes and network isolation for local agents | Out of scope; documented as a complement | — |

Two rules hold for every socket. It uses a standard, so any provider can
plug in, not one partner. And it never weakens fail-closed behaviour: a
hook or signal source that times out follows its per-hook policy, which is
"refuse" for critical operations, and no external scorer can approve a call
that policy marks "always ask".

## What changed, and why

Two outside reviews shaped this order. The first (design and code, October
2026) corrected the fit with real MCP clients and found fail-open paths,
since closed. The second (commercial products, late October 2026) found
that the governance half is what vendors gate, and added three things.

| Was | Now | Why |
|---|---|---|
| Control plane first, a demo at the very end | one end-to-end slice first | nobody can see the product work until a call is blocked |
| Grants bound to a DPoP key by default | Bearer by default; proof of possession per agent or mandate; no `cnf` until it is checked | MCP clients send Bearer tokens; a token must not claim a binding nobody enforces |
| The gateway holds a call open and runs it once approved | approve, then the client's retry runs it, exactly once | clients time out long before a person answers |
| Dynamic client registration first | Client ID Metadata Documents first | the MCP specification moved to metadata documents |
| Decision endpoint shaped like AuthZEN | a conformant AuthZEN 1.0 decision point, early | other gateways already speak AuthZEN to decision points |
| Shared upstream secrets only | **per-user upstream connections** (D2) | every product category sells a token vault; it was the largest gap |
| Owners and states in the registry | **lifecycle governance**: sponsors, expiry, offboarding, access reviews, a kill switch (C8, G1–G3) | the most consistently gated area, and cheap on the existing registry |
| One approval per exact call only | the exact call stays the default; **approve for a window** added, recorded as weaker (E6) | people want fewer prompts; the record must say which kind was given |
| Approval thresholds, notifications, discovered agents, admin sign-in, the evidence bundle later | moved into the first slice (C5, C10–C12) and into evidence v2 (F4) | small, and among the most commonly gated |
| Enterprise interop late | identity assertions (ID-JAG) first among the enterprise steps (D1) | the large IdPs shipped it within days of each other |

## Later

Minting a payment credential from an approved single-use grant; a
risk-scorer hook that can route to approval but never approve; settling a
budget to the actual amount, per-currency budgets and a payment adapter; a
rule-based agent risk score and anomaly alerts as OCSF findings; exporting
mandates as Cedar; agent-to-agent delegation once an actor-chain draft
converges; Transaction Tokens and Identity Chaining; mTLS and X.509 SPIFFE
identities; fronting A2A agents; signed outbound requests to commerce APIs;
portable signed mandate receipts; transparency-log witnesses for
checkpoints; Cedar or OPA as a second policy stage; a Kubernetes controller
over `apply`; users narrowing a mandate on the consent page; per-call data
scoping.

## Not doing

- A full MCP gateway: federation, API-to-MCP conversion, tool search, server
  catalogues, LLM traffic.
- A general policy language: the constraint set stays closed, and a second
  policy stage goes to Cedar or OPA over AuthZEN.
- A gateway that executes stored calls with no client waiting.
- ML models, threat feeds, endpoint agents, a hosted service: sockets
  instead.
- Language SDKs, until workload users ask for a sidecar.

## Open questions

- **Evaluation mode.** An embedded store for a five-minute trial; the
  storage decision so far is PostgreSQL only, and C13's compose file may
  make this unnecessary.
- **Regular expressions** (H1) are kept only where "within" stays exact;
  whether that is useful enough is decided when H1 starts.
- **Dates and standards.** The EU AI Act dates for high-risk logging and
  oversight (reported as 2 December 2027 after the 2026 Digital Omnibus),
  and the status of each draft named here, are checked against the
  primary text before they appear in documentation.
- **Evidence behind the commercial comparison** came mostly from search
  summaries of vendor pages; it guided the order of work, and no price or
  vendor claim is stated in this repository.
