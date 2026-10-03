# Magertron™ agent examples

Working code for building an agent on [Magertron™](https://magertron.com), the governance and orchestration platform for MCP and LLM servers.

Two things are here:

- **`magertron/`** — a small Go package with no dependencies outside the standard library. It handles credentials and the token exchange, the tool catalogue, governed tool calls with idempotency keys, and the refusal-handling rules.
- **`cmd/chat-agent/`** — a command-line agent built on it. You ask a question; Claude chooses tools; every tool call **and every model call** goes through Magertron™, where it is authorized, metered and audited. The agent holds no vendor API keys.

This code is the companion to the **Agent Developer Guide**. Section references below (§3, §5, …) point into it.

## What it demonstrates

| Guide | In the code |
|---|---|
| §1 Path A — Magertron™ issues your agent's token | `MAGERTRON_SA_TOKEN`, `magertron.StaticToken` |
| §1 Path B — your directory issues it | `MAGERTRON_IDP_*`, `magertron.ClientCredentials` |
| §3 Trade a long-lived token for a five-minute one | `magertron.Exchange` (subject only) |
| §4 Stateless and stateful MCP servers | `Client.session` |
| §4 Retrying without paying twice | `Idempotency-Key` on every `tools/call`, stable across retries |
| §5 Acting for a person | `magertron.Exchange` with `Subject` = the person, `Actor` = the agent |
| §6 Cache the credential, respect the expiry | `Exchange` caches until 30 s before the token's own `exp` |
| §6 Fetch the catalogue as the person | `identities.catalog` in `cmd/chat-agent` |
| §6 Never degrade to one identity | a failed delegated exchange fails the call |
| §6 Retry once on a stale 403 — and only once | `Client.withRetries` |
| §6 Which refusals to retry | `magertron.Classify` and `Kind` |
| §8 Tool results are untrusted input | the agent's system prompt |

## Requirements

- Go 1.25 or later
- A Magertron™ deployment, and from your platform team either:
  - **Path A:** a service-account token, or
  - **Path B:** a client ID, client secret, token URL and exchange audience for your directory
- An LLM server registered in Magertron™ for the model leg (your platform team gives you its path)

## Run it

```sh
go build -o chat-agent ./cmd/chat-agent

export MAGERTRON_URL=https://mcp.example.com
export MAGERTRON_LLM_PATH=/api/v1/llm/<namespace>/<llm-server>
```

**Path A — Magertron™ is the issuer:**

```sh
export MAGERTRON_SA_TOKEN="$(cat /path/from/your/secrets-manager)"
./chat-agent
```

**Path B — your directory is the issuer:**

```sh
export MAGERTRON_IDP_TOKEN_URL=https://your-tenant.example.com/oauth/token
export MAGERTRON_IDP_CLIENT_ID=...
export MAGERTRON_IDP_CLIENT_SECRET="$(cat /path/from/your/secrets-manager)"
export MAGERTRON_EXCHANGE_AUDIENCE=https://sts.example.com
./chat-agent
```

**Acting for a person** (either path): also set the person's token. On Path A an administrator or the developer portal issues it; on Path B it is the person's access token from your directory, issued for the exchange audience.

```sh
export MAGERTRON_PERSON_TOKEN="..."
```

The agent then fetches the catalogue as that person and makes every call with a delegated token: the call succeeds only where both the person and the agent are permitted, and the chargeback bills the person, with the agent shown alongside.

### All settings

| Variable | Required | Meaning |
|---|---|---|
| `MAGERTRON_URL` | yes | Gateway URL |
| `MAGERTRON_LLM_PATH` | yes | Path of the governed LLM server, e.g. `/api/v1/llm/<ns>/<server>` |
| `MAGERTRON_SA_TOKEN` | Path A | Service-account token |
| `MAGERTRON_IDP_TOKEN_URL`, `_CLIENT_ID`, `_CLIENT_SECRET` | Path B | Your directory's client-credentials grant |
| `MAGERTRON_EXCHANGE_AUDIENCE` | Path B | Exchange audience — a label, not a URL that is called |
| `MAGERTRON_PERSON_TOKEN` | no | Act for this person |
| `MAGERTRON_MODEL` | no | Model id (default `claude-sonnet-4-6`) |
| `MAGERTRON_INSECURE_SKIP_VERIFY` | no | `1` turns TLS verification **off** — only for a test cluster with a self-signed certificate |

## Using the package in your own agent

```go
mc, _ := magertron.New(magertron.Options{GatewayURL: "https://mcp.example.com"})

// The agent's own identity (Path A shown), exchanged for five-minute tokens.
agent := magertron.StaticToken(os.Getenv("MAGERTRON_SA_TOKEN"))
self := &magertron.Exchange{Client: mc, Subject: agent}

tools, err := mc.Catalog(ctx, self)
// ...
out, err := mc.CallTool(ctx, self, tools[0], json.RawMessage(`{"timezone":"UTC"}`))

var r *magertron.Refusal
if errors.As(err, &r) {
    switch r.Kind {
    case magertron.KindSpendLimit, magertron.KindToolApproval:
        // a human must act; tell someone, do not retry
    }
}
```

Retries that are safe are already done for you: a stale-roles 403 once with a fresh token, load-shedding 429s with backoff, and network failures — each with the same idempotency key, so the platform meters the call once.

## Security notes

- **TLS is verified by default.** `MAGERTRON_INSECURE_SKIP_VERIFY=1` exists for test clusters only; with it, anyone on the network path can read your tokens.
- **Tokens are never logged.** Keep it that way in your own code: log a token's length, not the token.
- **Keep long-lived credentials in a secrets manager**, never in source, images or committed environment files. A leaked service-account token is revoked and rotated by your platform team.
- **A person's token is never your agent's identity.** It is used only as the subject of an exchange.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Tests

```sh
go test ./...
```

The tests run the client against a fake gateway: delegated exchange fields, token caching, the retry rules, idempotency-key reuse, stateless sessions, and TLS verification by default.

## Compatibility

Tested against Magertron™ 4.0.x.

## License

Apache License 2.0 — see [LICENSE](LICENSE). The license covers this code. It does not grant rights to the Magertron™ name or logo; see [TRADEMARKS.md](TRADEMARKS.md).
