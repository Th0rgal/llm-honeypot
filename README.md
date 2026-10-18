# llm-honeypot

A tiny, dependency-free LLM honeypot in Rust.

It impersonates an unauthenticated OpenAI-/Ollama-style inference endpoint
(`/v1/models`, `/v1/chat/completions`, `/api/tags`, the usual LiteLLM admin
paths) and **logs every request** — source IP, User-Agent, any API key the
client presents, the requested model and the full prompt — as one JSON line per
request. It never runs a model: chat replies are a fixed, harmless string, so
the endpoint cannot be used to generate anything.

Internet-wide scanners discover self-hosted inference servers through
Certificate Transparency logs and port scans, then probe them for free,
unauthenticated compute. Point a tempting hostname (e.g. `llm.example.com`) at
this honeypot and watch who comes knocking.

## Design

- **Zero dependencies.** Rust standard library only. The release binary is a few
  hundred KB.
- **Safe by construction.** Replies are canned; the honeypot has no LLM, no
  shell-out, no outbound requests. It only accepts connections and writes logs.
- **Bounded.** Per-IP rate limiting, a cap on concurrent connections, read
  timeouts and a maximum request-body size keep it from becoming an amplifier or
  getting slowloris'd.
- **Behind a reverse proxy.** Binds loopback; the real client IP is read from
  `X-Forwarded-For` / `X-Real-IP` set by nginx/Caddy.

## Run

```sh
cargo build --release
HONEYPOT_ADDR=127.0.0.1:8099 HONEYPOT_LOG=/var/log/llm-honeypot/requests.jsonl \
  ./target/release/llm-honeypot
```

### Configuration (environment variables)

| Var | Default | Meaning |
|---|---|---|
| `HONEYPOT_ADDR` | `127.0.0.1:8099` | listen address |
| `HONEYPOT_LOG` | *(stdout)* | append JSON lines to this file |
| `HONEYPOT_RATE` | `30` | max requests per IP per window |
| `HONEYPOT_RATE_WINDOW_SECS` | `10` | rate-limit window |
| `HONEYPOT_MAX_CONN` | `128` | max concurrent connections |
| `HONEYPOT_MAX_BODY` | `4194304` | max request body bytes read/logged |
| `HONEYPOT_SERVER_NAME` | `uvicorn` | `Server:` header value |

Each log line looks like:

```json
{"ts":"2026-10-18T12:00:00Z","ip":"203.0.113.7","method":"POST","path":"/v1/chat/completions",
 "version":"HTTP/1.1","ua":"OpenAI-Python/1.0","api_key":"sk-...","model":"gpt-4o","stream":true,
 "body_len":123,"headers":[["Host","llm.example.com"],...],"body":"{\"model\":\"gpt-4o\",...}"}
```

## Reverse proxy (nginx)

[`deploy/nginx.conf`](deploy/nginx.conf) serves the honeypot on both HTTP and
HTTPS, forwards the client's TLS parameters (protocol, offered ciphers and
curves) as `X-Honeypot-TLS-*` headers so they land in the request log, and
writes its own JSON access log so requests nginx rejects before proxying (e.g.
oversized bodies) are recorded too.

A hardened systemd unit is in [`deploy/llm-honeypot.service`](deploy/llm-honeypot.service).

## Reporting

[`scripts/report.py`](scripts/report.py) prints a compact per-IP summary of the
log lines written since its last run (it keeps a byte-offset cursor), so you can
run it on a schedule to see new visitors incrementally. It enriches each new IP
with passive lookups only (PTR record, Team Cymru ASN via DNS), keeps a history
of every IP seen, and prints the prompts that were sent.

## Ethics

This is a **passive** defensive tool. It waits for unsolicited traffic to a host
you own and records it; it never scans, probes, or sends requests to anyone. The
canned reply follows no instruction, so the endpoint produces no usable content.
Captured prompts may contain third-party data — keep the log private and set a
short retention.

## License

MIT
