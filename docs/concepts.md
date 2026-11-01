# Concepts: the v0 contract

The documents doorward reads and writes, how an agent gets authority, and the conventions every document follows.

## The v0 schemas

Seven documents, as JSON Schema (draft 2020-12) in [`schema/v0`](../schema/v0)
with matching Go types in [`api/v0`](../api/v0). Three are configuration a
company writes, in YAML or JSON; the other four are records the box produces
as agents work.

| Document | Written by | What it is |
|---|---|---|
| [Manifest](../schema/v0/manifest.schema.json) | company | One resource behind the gateway: where the gateway forwards to and with which credential, the operations it exposes (MCP tools or HTTP routes), the tier of each (`read`, `write`, `critical`), and where their constrainable arguments are |
| [Agent](../schema/v0/agent.schema.json) | company, or the agent itself | One agent: how it presented itself, how it proves who it is, who answers for it, and the most it may ever be granted |
| [Mandate](../schema/v0/mandate.schema.json) | company | What an agent may do for a principal and on what terms: permissions, limits, how long a user's consent stands, who approves critical calls |
| [Consent](../schema/v0/consent.schema.json) | the box | One person allowing one agent one mandate, given on the box's consent page |
| [Grant](../schema/v0/grant.schema.json) | the STS | Claims of the short-lived, key-bound JWT access token (RFC 9068) an agent holds under a mandate |
| [Decision](../schema/v0/decision.schema.json) | the decision core | The record of one decision: who acted, for whom, under which grant and consent, what was asked, every check and its result, and where it was decided and enforced |
| [Approval](../schema/v0/approval.schema.json) | the approval service | The record of one approval request: the exact call, who voted, how each of them signed in |

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

The examples in [`examples/v0`](../examples/v0) tell both stories. Alice
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
  [`schema/drift_test.go`](../schema/drift_test.go) fails the build when the two
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
