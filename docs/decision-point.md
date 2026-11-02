# Grants and the decision point

How doorward verifies a grant, checks one call against it, and records the decision. The quick start in the [README](../README.md#quick-start) runs the same steps end to end.

## Grants

A grant is a JWT access token (RFC 9068): header `{"alg":"ES256","typ":"at+jwt","kid":…}`,
the claims of [`grant.schema.json`](../schema/v0/grant.schema.json), signed
with the box's active key. Verification ([`internal/grant`](../internal/grant))
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
doorward grant mint --consent examples/v0/consent/alice-invoice-assistant.json \
  examples/v0/grant/pay-invoice.json > grant.jwt
doorward grant verify --aud https://payments.example.internal - < grant.jwt
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
([`internal/core`](../internal/core)): the grant must allow the operation at
the resource, and every bound the grant sets on its arguments must hold.
Bounds from every entry that names the operation apply together. A bound
on an argument the call carries is always checked; a missing argument is
refused only if the manifest declares it, since one entry may bound
`/amount` for operations that take no amount.

```sh
doorward grant verify --aud https://payments.example.internal \
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
doorward grant verify --aud https://payments.example.internal \
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

Then the budgets (`limits`). A count budget draws 1 per call, a sum budget
the value of its argument, which must be present, a number and not
negative. A per-grant budget belongs to the grant; a daily or monthly one
to the consent and the calendar day or month in UTC, shared by every grant
under that consent. Budgets are drawn last, only for a call that passed
every other check, and all at once with the call's single-use grant: every
budget has room and the grant is unspent, or nothing changes. Amounts are
exact decimals, so ten draws of 0.10 fill a budget of 1.00 exactly.
`--spend` draws them, as allowing the call would:

```sh
doorward grant verify --aud https://payments.example.internal --action pay_invoice \
  --args '{"invoice_id":"inv_7Q2M9X4K","amount":1200,"currency":"EUR"}' --spend - < grant.jwt
```

```
...
fail  limits      payout-month
refused: limit_exceeded: budget payout-month has 1000 left this month; the call needs 1200
```

## Decision point

`POST /access/v1/evaluation` on the public listener answers one call in the
AuthZEN 1.0 shape. The point of enforcement (a gateway) authenticates with
its own token, configured with `--pep ID=TOKEN` (or `DOORWARD_PEPS`), and
sends the agent's grant in `context.token`. The built-in
[MCP gateway](gateway.md) asks the same question in process, and its
records name it as the point of enforcement:

```sh
curl -sS -X POST localhost:8080/access/v1/evaluation \
  -H "Authorization: Bearer $PEP_TOKEN" -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" \
  -d '{"subject":{"type":"agent","id":"invoice-assistant"},
       "action":{"name":"pay_invoice"},
       "resource":{"type":"tool_call","id":"https://payments.example.internal",
                   "properties":{"arguments":{"invoice_id":"inv_7Q2M9X4K","amount":7500,"currency":"EUR"}}},
       "context":{"token":"'"$GRANT"'"}}'
```

```json
{"decision":false,"context":{"id":"dec_01M69…","outcome":"deny",
 "reasons":[{"code":"constraint_violated","message":"7500 is above the grant's max of 5000","field":"/amount"}],
 "action_hash":"sha-256:zSm3ob6uLbcAwT_CafGYJI2ndRqedlo64DDnvnGROGQ"}}
```

`decision` is true only for an allowed call. The ten checks run in the
record's order and stop at the first failure; the rest are recorded as
skipped. A held critical call opens an approval request with the mandate's
route, or reuses the one already open for the same call, and the answer
names it. An allowed call's budgets and single-use grant are spent in the
same transaction that appends its record. A request missing its subject,
action or resource is refused with 400 and leaves no record; anything else
is decided and recorded, and an internal failure answers 500 with
`decision` false.

### Observe mode

A mandate or an agent can be set to `enforcement: observe` to try its rules
before enforcing them. Doorward then decides every call as usual and
records the answer, but the mandate's own rules do not stop a call:

| Observed, not enforced | Always enforced |
|---|---|
| an operation or argument outside the grant (`subset`) | the grant: signature, status, audience, time |
| a budget without room, or a call it cannot count (`limits`) | the agent's ceiling (`max_sensitivity`) |
| | approval of critical operations |
| | an operation the manifest does not declare |
| | a single-use grant already spent |

The record of an observed call has `"enforcement": "observe"` and, when
enforcement would have refused it, `observed` with that refusal and its
reasons; the answer to the gateway carries both. A budget without room
stays at its maximum, and the call's other budgets are drawn, since the
call ran. Records whose `observed` is set are the calls a mandate would
have stopped: the list to read before switching it to `enforce`.

### Configuration, read once per change

Every configuration write bumps one version counter. A decision reads that
counter and reuses its snapshot of the configuration (enabled manifests by
audience, mandates and agents by name, decoded and checked once) until the
counter changes, so a change still takes effect on the very next call
while a decision costs one small query instead of reading and decoding
every document. Public keys are cached by key ID; a key ID names one key
forever.

A document the running version cannot read, because it carries a field
from a newer doorward or breaks a rule, is marked broken when the snapshot
loads: calls that depend on it are refused with `internal_error` and
recorded, calls under other documents are unaffected, and the log says
which document. An older instance therefore never enforces less than it
should. Upgrade every instance before writing configuration that uses a
new field.

### Deadlines

Every decision has a deadline, `--decision-timeout` (default 5 s, at most
20 s so that it stays under the 30-second HTTP write timeout). It covers
the whole decision, the wait for the journal lock included: the lock is
taken with a matching `lock_timeout`, so a held lock produces fast refusals
instead of a stall. A decision that runs out of time is rolled back: nothing
drawn, nothing recorded, and the gateway gets 503 with `Retry-After`. Set
the gateway's own timeout above the decision timeout; a gateway that gives
up first cannot learn an answer that was committed a moment later.

Every record names the user or the owning team, the agent, the grant (its
ID; never the token), the versions of the mandate and the manifest in
force, the W3C trace ID, and every check. A grant refused after its
signature held (revoked, sent to another resource, expired) is named too,
with its agent and their user or owner, so a suspended agent's next attempt
is on record as that agent's; only a grant whose signature fails is
recorded without them. Records are chained: each one's
`chain.hash` is the SHA-256 of the record in RFC 8785 canonical JSON
without `chain.hash`, and covers the previous record's hash.

- `--journal FILE` keeps a complete copy of the chain as JSON lines: a
  follower copies every committed record out of the database in sequence
  order, including records other instances committed, so each instance's
  file is the whole journal. On start it continues after the file's last
  record, so nothing is lost to a crash; a new empty file receives the
  whole history. `--journal -` streams to standard output from the current
  head. `GET /admin/v0/decisions?from=SEQ` exports records from the Admin
  API, and `doorward journal export` from the command line.
- `doorward journal verify FILE` checks every record against the contract
  and the chain, in sequence order whatever order the lines are in, and
  reports a sequence number seen twice.
  [`scripts/verify-journal.py`](../scripts/verify-journal.py) checks the
  chain with Python's standard library alone, sharing no code with
  doorward.
- With `OTEL_EXPORTER_OTLP_ENDPOINT` set, each evaluation is a span in the
  caller's trace, carrying the decision's ID, outcome, agent, mandate and
  reason.

### How decisions are written

Every record joins one chain, so appends are serialized by one lock. One
transaction per decision made that lock, with its commit to disk, the
ceiling: about 550 decisions a second on a small machine, whatever the
concurrency. Instead, a writer per instance takes the settlements that
arrived while the previous batch was committing (up to 64) and settles
them in one transaction: one lock, one read of the head, every allowance
in one pipelined round trip, every record in another, one commit. A lone
decision goes at once; batches grow with the arrival rate. Each allowance
is one SQL statement that locks its budget rows in key order, checks that
everything fits and writes all of it or nothing, so no item leaves partial
state whatever happens to the others.

On a shared 4-core machine with a local PostgreSQL, one caller sees about
5 ms per decision; 16 concurrent callers get about 800 decisions a second
at 20 ms median, 64 about 1,100 at 57 ms, and 256 about 1,300 at 200 ms.
Several instances share the one chain and the same ceiling.
