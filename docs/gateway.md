# The MCP gateway

Doorward's built-in gateway puts one address in front of each MCP server a
manifest describes, and makes the decision point part of the protocol: an
MCP client connects to the gateway with a grant, sees only the tools its
grant allows, and gets every refusal and every hold back as a tool result
it can read. The server behind the gateway keeps its own credential, which
the agent never holds.

The gateway implements the Streamable HTTP transport of the MCP
specification, revision 2025-11-25, and the parts of its authorization
section a resource server owns: Bearer tokens, audience checks, the 401
challenge, and 403 `insufficient_scope`. It is deliberately thin: it does
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
| `tools/call` | Asks the decision point, in process, exactly as a gateway would over the evaluation API. **Allowed**: forwarded, with the upstream credential, and the answer streamed back. **Refused**: a tool execution error (`isError: true`) whose text carries the reason, so the model can correct itself; the server never hears of it. **Held**: a tool error naming the approval request, to be retried unchanged once a person approves. A tool the grant lacks but an enabled mandate allows gets `403` with `error="insufficient_scope"` and that mandate as the scope. |
| `tools/list` | Forwarded; the server's list is filtered to the tools the grant allows and the manifest declares, in plain JSON or inside the event stream. A tool the server offers but no manifest declares is never shown. |
| `initialize`, `ping`, notifications, responses, resources, prompts, `GET` (listening stream), `DELETE` (session end) | Forwarded unchanged once the grant verifies. Session IDs and protocol versions are the server's. |

The gateway never passes the agent's grant upstream, and it forwards only
the headers the MCP transport defines (`MCP-Protocol-Version`, the
`Mcp-*` request-metadata headers) and the tracing headers (`traceparent`,
`tracestate`, `baggage`). Everything else the client sent, including its
`Authorization`, any `Cookie`, and anything a server might mistake for an
identity such as an `X-Forwarded-*` header, is dropped; the upstream
credential is set in its place.

It takes one JSON-RPC message per request, as the 2025-11-25 transport
requires; a batch is refused with `-32600`. A request whose `Origin` is
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

For the same reason the gateway decides only on what the manifest
describes, which is tools. It passes through the protocol's own lifecycle
(`initialize`, `ping`, `notifications/*`, and a client's response to a
server-initiated request) once the grant verifies, and refuses every other
method, `resources/*`, `prompts/*`, `logging/*`, `sampling/*` and the rest,
with `-32601` rather than forward it undecided.

Results the gateway writes itself carry the decision under `_meta`, under
the key `dev.doorward/decision`:

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
sed 's#url: .*#url: http://127.0.0.1:8090/mcp#' examples/v0/config/manifest-ledger-mcp.yaml \
  | curl -sS -X PUT -H "$H" -H "Content-Type: application/yaml" --data-binary @- "$A/manifests/ledger-mcp"
curl -sS -X PUT -H "$H" -d '{"value":"lk_live_example"}' "$A/secrets/ledger-mcp-api-key"
bin/doorward grant mint examples/v0/grant/reconcile.json > reconcile.jwt
```

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
C6), and the approval page a held call waits on (C7, C8) follow on the
[roadmap](ROADMAP.md). `doorward import mcp` (C2) will draft a manifest
from a server's `tools/list`.

Two hardening steps also wait on later work. The `Origin` check still
trusts the request's `Host` header, so a browser request whose `Host` and
`Origin` both carry an attacker's name passes it; every request still needs
a valid grant, which a cross-site page cannot obtain, and C3 adds the
gateway's own public URL to check against. And the gateway does not yet tie
a server's MCP session to the grant that opened it, so a server that keys
state on its session ID alone, rather than on the per-call decision, leaves
that state reachable by another grant that learns the ID; MCP removes
protocol-level sessions in revision 2026-07-28.
