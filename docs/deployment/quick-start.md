<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Quick start

This gets a single-node garmr running on a **trusted, isolated host** for
evaluation. It is not a hardened production setup — read
[secure-deployment.md](secure-deployment.md) and
[../security/known-limitations.md](../security/known-limitations.md) before exposing
anything beyond loopback.

## 1. Build

```sh
cargo build --release
```

The default build is self-contained and needs no cloud key. Optional capabilities
are Cargo features, all **off by default**:

- `semantic` — embedding / semantic search (also needs a local model directory).
- `loki-compat` — a Loki push ingest endpoint.
- `flight` — an experimental Arrow Flight ingest endpoint.
- `mcp` — the `garmr-mcp` server binary.

For example, a node that wants semantic search plus Loki and Flight ingest:

```sh
cargo build --release --features "semantic loki-compat flight"
```

To drop the `znippy` (OpenZL) cold-storage codec for a more portable dependency
surface, build with `--no-default-features` (falls back to a pure-Rust
zstd-parquet archiver).

## 2. Configure

```sh
cp garmr.example.toml garmr.toml   # then edit paths, model, and rooms
export GARMR_CONFIG=./garmr.toml
```

`garmr.example.toml` is heavily commented. Key sections: `[store]` (warehouse /
state / retention), `[ingest]` (bind addresses), `[detect]` (rules, correlation,
app-audit, RBA), `[agent]` (LLM backend), `[route]` / `[route.egress]` /
`[route.router]` (throttling, egress allowlist, model routing), `[audit]`, and
`[environment]`. **Secrets never live in the config** — they come from the
environment (see step 4).

Default binds: the web console + read/query API on `127.0.0.1:3110` (loopback), and
the native ingest endpoint on `0.0.0.0:3100`.

## 3. Verify the whole loop offline

```sh
./target/release/garmr selftest
```

`selftest` exercises the full agent tool-loop offline against a canned case. To run
it against a local model, point `[agent]` at your OpenAI-compatible endpoint (see
[local-llm.md](local-llm.md)); no Anthropic key is needed.

## 4. Run it

Secrets are provided via environment variables, out of band:

```sh
# LLM backend (choose one):
export ANTHROPIC_API_KEY=...          # if using the Anthropic backend
# (a local backend needs no key — see local-llm.md)

# Notifications (optional):
export GARMR_MATRIX_TOKEN=...         # the garmr-bot access token

./target/release/garmr serve
```

`serve` runs the live pipeline (ingest, detect, triage, escalate) and hosts the
console + API. The API is unauthenticated on a **loopback** bind for local use;
binding the API to a non-loopback address **requires** `GARMR_API_TOKEN` or `serve`
refuses to start.

## 5. Send events

Point any collector that can POST JSON at the native endpoint. Each event is
`{ "host", "service", "source", "environment", "severity", "log_type", "message",
"ts"?, "fields"? }`; only `message` is required and the rest take sensible
defaults. For example, with Vector:

```toml
[sinks.garmr]
type = "http"
inputs = ["your_logs"]
uri = "http://garmr-node.example.internal:3100/ingest/v1/events"
encoding.codec = "json"           # a JSON array of canonical events
```

> **Before you expose ingest:** the native endpoint binds `0.0.0.0` and accepts
> unauthenticated POSTs by default, with no body/event-count/field-size limits.
> Keep it on a trusted network, configure `GARMR_COLLECTORS`, and put a proxy in
> front — see [secure-deployment.md](secure-deployment.md).

## 6. Inspect

Browse the console (`http://127.0.0.1:3110`) or use the CLI (offline analysis /
development):

```sh
garmr tail                          # recent events
garmr query "SELECT log_type, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC"
garmr hsearch "failed login from a new host"   # structured + full-text (+ semantic)
garmr cases list                    # triaged cases + verdicts
garmr cases show <id>               # one case with its full agent transcript
garmr audit verify                  # verify the tamper-evident ledger, offline
```

See [../cli-reference.md](../cli-reference.md) for every subcommand and
[first-run.md](../setup/first-run.md) for the guided setup checklist.

## Next steps

- [secure-deployment.md](secure-deployment.md) — authentication, secrets, recovery,
  and hardening.
- [local-llm.md](local-llm.md) — run the agent on a local model / GPU.
- [airgap.md](airgap.md) — the fully offline profile.
- [postgresql-pgaudit.md](postgresql-pgaudit.md) — ingest a PostgreSQL audit trail.
