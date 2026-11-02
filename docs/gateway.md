# The MCP gateway

Doorward's built-in gateway puts one address in front of each MCP server a
manifest describes, and makes the decision point part of the protocol: an
MCP client connects to the gateway with a grant, sees only the tools its
grant allows, and gets every refusal and every hold back as a tool result
it can read. The server behind the gateway keeps its own credential, which
the agent never holds.

The gateway implements the Streamable HTTP transport of the MCP
specification, revisions 2025-11-25 and 2026-07-28, and the parts of its
authorization section a resource server owns: Bearer tokens, audience
checks, the 401 challenge, and 403 `insufficient_scope`. It is deliberately thin: it does
not convert APIs to MCP, federate servers or search tools. Any other
gateway can do the same by calling the
[evaluation endpoint](decision-point.md#decision-point).

## Addresses

Every enabled manifest with `protocol: mcp` is served at
`/mcp/{manifest name}` on the public listener, so the example ledger is at
`http://localhost:8080/mcp/ledger-mcp`. A manifest's `audience` stays what
grants name; the path is only where clients connect. The manifest's
`upstream.url` is the real server, and `upstream.auth` names the header,
prefix and sealed secret the gateway adds:

```yaml
spec:
  audience: https://ledger.example.internal/mcp
  protocol: mcp
  upstream:
    url: http://127.0.0.1:8090/mcp
    auth: { header: Authorization, prefix: "Bearer ", secret_ref: ledger-mcp-api-key }
```

The secret is opened from the store once per configuration version and kept
in memory; changing it through the Admin API takes effect on the next call.

## What happens to each message

A request without a grant gets `401` with a challenge that names the
mandates that allow anything at this audience, so a client acting for a
user knows what to ask for:

```
WWW-Authenticate: Bearer realm="doorward", scope="reconcile"
```

A grant that does not verify (bad signature, revoked, expired, wrong
audience) gets `401` with `error="invalid_token"` and the reason. Every
other message is handled by what it is:

| Message | What the gateway does |
|---|---|
| `tools/call` | Asks the decision point, in process, exactly as a gateway would over the evaluation API. **Allowed**: forwarded, with the upstream credential, and the answer streamed back. **Refused**: a tool execution error (`isError: true`) whose text carries the reason, so the model can correct itself; the server never hears of it. **Held**: a tool error naming the approval request, to be retried unchanged once a person approves. A tool the grant lacks gets `403` with `error="insufficient_scope"` and, as the scope, the mandates the caller could obtain to run it: enabled, for the same kind of principal as its grant, ones its agent may request (open ones, or those it lists once verified), and only when the agent's own ceiling allows the tool. When there are none, the refusal is a plain tool error, so a client is never sent to ask for what it cannot get. |
| `tools/list` | Forwarded; the server's list is filtered to the tools the grant allows and the manifest declares, in plain JSON or inside the event stream. A tool the server offers but no manifest declares is never shown. The filtered list is the grant's, so it is marked `cacheScope: "private"` and no shared cache keeps it for others. |
| `initialize` or `server/discover`, `ping`, `subscriptions/listen`, notifications, responses, `GET` (listening stream), `DELETE` (session end) | Forwarded unchanged once the grant verifies. Session IDs and protocol versions are the server's. |
| Anything else: `resources/*`, `prompts/*`, `logging/*`, `sampling/*`, … | Refused with `-32601`, under 2026-07-28 with HTTP `404`: the manifest describes tools, so the gateway cannot decide on anything else. |

The gateway never passes the agent's grant upstream, and it forwards only
the headers the MCP transport defines (`MCP-Protocol-Version`, the
`Mcp-*` request-metadata headers) and the tracing headers (`traceparent`,
`tracestate`, `baggage`). Everything else the client sent, including its
`Authorization`, any `Cookie`, and anything a server might mistake for an
identity such as an `X-Forwarded-*` header, is dropped; the upstream
credential is set in its place.

It takes one JSON-RPC message per request, as the transport requires; a
batch is refused with `-32600`. A request whose `Origin` is
neither the gateway's own host nor one of `--gateway-origins` gets `403`.

## Reading the message the same way the server does

The gateway decides on its own reading of a message and then forwards the
message to the server. If the two could read it differently, an agent could
get one call decided and another one run. Go's JSON decoder matches member
names without regard to case and keeps the last of any duplicates, so a
message carrying both `method` and `Method`, or both `arguments` and
`Arguments`, reads one way here and another at a case-sensitive server. The
gateway refuses any message in which an object has two member names equal
ignoring case, at any depth, with `-32600`, so the two readings cannot
diverge.

Revision 2026-07-28 mirrors parts of the body into headers, for
intermediaries to route on: `MCP-Protocol-Version` repeats the version in
the body's `_meta`, `Mcp-Method` the method, and `Mcp-Name` the tool's name,
plainly or as `=?base64?…?=`. The gateway forwards these headers and decides
on the body, so a header that says something else is the same split: one
reading here, another wherever the header is read. A request whose headers
do not match its body, gives one twice, or, under 2026-07-28, leaves out
one the revision requires, is refused with HTTP `400` and `-32020`
(`HeaderMismatch`) before anything is decided; an older client that sends
the headers is held to the same.

For the same reason the gateway decides only on what the manifest
describes, which is tools. It passes through the protocol's own lifecycle
(`initialize` or `server/discover`, `ping`, the `subscriptions/listen`
stream, `notifications/*`, and a client's response to a server-initiated
request) once the grant verifies, and refuses every other method,
`resources/*`, `prompts/*`, `logging/*`, `sampling/*` and the rest, with
`-32601` rather than forward it undecided.

Results the gateway writes itself carry the decision under `_meta`, under
the key `dev.doorward/decision`, and, under 2026-07-28, `resultType:
"complete"`:

```json
{"jsonrpc":"2.0","id":7,"result":{
  "isError":true,
  "content":[{"type":"text","text":"doorward refused this call: 5000 is above the grant's max of 1000 (constraint_violated)"}],
  "_meta":{"dev.doorward/decision":{"decision":"dec_01M66…","outcome":"deny","action_hash":"sha-256:…",
           "reasons":[{"code":"constraint_violated","field":"/amount","message":"5000 is above the grant's max of 1000"}]}}}}
```

Every call the gateway decides is a record on the journal like any other,
with the gateway named as the point of enforcement (`--gateway-id`,
default `gateway`). A decision that cannot be made or recorded in time
answers the call with a JSON-RPC error and HTTP 503; the call is not made.

## Drafting a manifest from the server's tools

A manifest names every tool the gateway lets through, with its tier and the
arguments constraints can refer to. `doorward import mcp` drafts one from
what the server itself lists:

```sh
bin/doorward import mcp --name ledger-mcp --audience https://ledger.example.internal/mcp \
  --secret-ref ledger-mcp-api-key --header "Authorization: Bearer lk_live_example" \
  http://127.0.0.1:8090/mcp > ledger-mcp.yaml
```

It shakes hands with the server (MCP 2025-11-25, accepting 2025-06-18 and
2025-03-26), reads `tools/list` to its last page, writes the draft to
standard output, and says on standard error what it made of each tool:

```
ledger-mcp from demo-ledger 0.1 (MCP 2025-11-25): 4 tools listed, 4 operations
+ list_unmatched (read)
+ post_entry (write)
+ write_off (critical)
+ export_everything (write)
note: post_entry: it does not say whether it is destructive; drafted as write, though the protocol takes such a tool to be destructive: decide whether it is critical
note: export_everything: it does not say whether it is destructive; …
```

| From the tool | Into the operation |
|---|---|
| `name` | its name. A name the contract cannot hold (1 to 128 letters, digits, `_`, `.` and `-`) is left out with a note, and the gateway hides that tool. |
| `description`, else `title` | its description, cut to 1,024 characters |
| `inputSchema` | its params: every property of one scalar type, in nested objects too, keyed by JSON Pointer (`/payee/iban`). A type given with `null`, by `enum` or `const`, through a local `$ref`, or by alternatives of one type counts as that type. Arrays, values of several types and references outside the schema are left out, each with a note. |
| `annotations` | its tier: `readOnlyHint` gives read, `destructiveHint` critical, anything else write |

The annotations are the server's own say-so; the protocol calls them
untrusted, and nothing checks them. A tool that does not say it only reads
is never drafted as read, and one that does not say whether it is
destructive gets a note, since the protocol's default takes it to be. A
read operation runs on any valid grant, so check every tier before applying
the draft, and raise one when in doubt.

The import never touches the box. The draft is applied like any manifest,
through the Admin API, which checks it against the contract and the other
documents first:

```sh
curl -sS -X PUT -H "$H" -H "Content-Type: application/yaml" --data-binary @ledger-mcp.yaml "$A/manifests/ledger-mcp"
```

`--header` carries the server's credential for the import and is never
written to the draft; `--secret-ref` names the stored secret the gateway
sends in its place, as `Authorization: Bearer` (edit the draft for another
header). `--skip TOOL` leaves out a tool the manifest leaves out on purpose.

### Importing again

When the server changes, `--against` merges its tools into the manifest as
it stands; the URL defaults to the manifest's upstream:

```sh
bin/doorward import mcp --header "Authorization: Bearer lk_live_example" \
  --against ledger-mcp.yaml > ledger-mcp.next.yaml
```

Every operation keeps its tier and description and takes the server's
params as they are now; a new tool is added with the tier its hints
suggest; an operation whose tool is gone is removed. Tiers are never
changed: when the server marks a tool destructive that the manifest keeps
lower, a note says so. The changes are listed (`+` added, `-` removed, `~`
params), and the exit code is 3 when there are any and 0 when the server
still matches, so the same command can watch for drift. Comments in the
file are not carried into the draft.

The Admin API does the same for a stored manifest, with its stored secret
as the credential, and stores nothing:

```sh
curl -sS -X POST -H "$H" -d '{"skip":["export_everything"]}' "$A/manifests/ledger-mcp/draft"
```

The answer names the version the draft was merged into and holds the draft
under `document`, with its `changes` and `notes`. PUT the document once it
has been reviewed.

### A starter mandate

`--mandate FILE` also writes a mandate to start from, named like the
manifest: an agent acting for a user may run the read operations, and each
critical call once the user has approved that exact call. Write operations
would run on a standing grant without asking, so the starter leaves them
out and its comment names them; making a write ask first needs approval
thresholds (C10). Put its consent text in words the user will understand
before applying it.

## Trying it with the demo ledger

`cmd/demo-ledger` is a small MCP server over Streamable HTTP: a ledger with
three tools, one of each tier (`list_unmatched` read, `post_entry` write,
`write_off` critical) and a fourth, `export_everything`, that no manifest
declares. It wants an API key and logs which credential each request
carried. The example manifest `ledger-mcp` describes it, the example
mandate `reconcile` allows it with `/amount` at most 1,000 and the example
agent `reconciler` holds that mandate.

With doorward running and the examples loaded as in the
[quick start](../README.md#quick-start):

```sh
go run ./cmd/demo-ledger &                       # listens on 127.0.0.1:8090, key lk_live_example
curl -sS -X PUT -H "$H" -d '{"value":"lk_live_example"}' "$A/secrets/ledger-mcp-api-key"
bin/doorward import mcp --name ledger-mcp --audience https://ledger.example.internal/mcp \
  --secret-ref ledger-mcp-api-key --header "Authorization: Bearer lk_live_example" \
  --skip export_everything http://127.0.0.1:8090/mcp > ledger-mcp.yaml
curl -sS -X PUT -H "$H" -H "Content-Type: application/yaml" --data-binary @ledger-mcp.yaml "$A/manifests/ledger-mcp"
bin/doorward grant mint examples/v0/grant/reconcile.json > reconcile.jwt
```

The import drafts the same three operations, with the same tiers and
params, as the example manifest declares by hand, and leaves out
`export_everything` as the example does.

Then, with [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```sh
mcp() { npx @modelcontextprotocol/inspector --cli http://localhost:8080/mcp/ledger-mcp \
  --transport http --header "Authorization: Bearer $(cat reconcile.jwt)" "$@"; }
mcp --method tools/list
mcp --method tools/call --tool-name post_entry --tool-arg account_id=acc_EU_448120 --tool-arg amount=240.5
mcp --method tools/call --tool-name post_entry --tool-arg account_id=acc_EU_448120 --tool-arg amount=5000
mcp --method tools/call --tool-name write_off --tool-arg payment_id=pmt_8K2 --tool-arg amount=100 --tool-arg reason=duplicate
```

The list shows three tools, not four. The first entry is posted and the
demo server's log shows `"credential":"api key"`, never the grant. The
5,000 entry comes back as a tool error, "5000 is above the grant's max of
1000", and the write-off as a tool error naming its approval request;
neither reaches the server. `bin/doorward journal export` shows the three
decisions with `"pep":{"id":"gateway","kind":"gateway"}`.

Without a grant, the challenge:

```sh
curl -si localhost:8080/mcp/ledger-mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | grep -i www-authenticate
```

## What is not here yet

The gateway takes grants minted from the command line. Protected resource
metadata (RFC 9728), so that a client finds the authorization server from
the 401 (C3), the authorization server and consent page themselves (C4,
C6), and the approval page a held call waits on (C9) follow on the
[roadmap](ROADMAP.md).

The import reads tools only; resources and prompts stay refused at the
gateway.

Two parts of revision 2026-07-28 wait. Headers a tool's schema has mirrored
from its arguments (`Mcp-Param-*`, from `x-mcp-header`) are forwarded
without being checked against the arguments; checking them needs the
manifest to record which argument each one mirrors, the next step. And a
call that a server answers with a request for more input (multi round-trip
requests) is decided, and counted against budgets, at each round.

Two hardening steps also wait on later work. The `Origin` check still
trusts the request's `Host` header, so a browser request whose `Host` and
`Origin` both carry an attacker's name passes it; every request still needs
a valid grant, which a cross-site page cannot obtain, and C3 adds the
gateway's own public URL to check against. And the gateway does not yet tie
a server's MCP session to the grant that opened it, so under the older
revisions a server that keys state on its session ID alone, rather than on
the per-call decision, leaves that state reachable by another grant that
learns the ID; revision 2026-07-28 has no sessions.
