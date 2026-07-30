<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Known limitations and security notes

garmr is **alpha** software for **isolated lab evaluation**. This page lists the
limitations a reviewer must know before deploying it, focused on the security
surface. It is honest about gaps rather than hiding them. Read it alongside
[status/alpha-status.md](../status/alpha-status.md) and the
[threat model](threat-model.md).

> **Bottom line:** do not expose garmr's ingest or API surfaces to an untrusted
> network, and do not rely on it as the sole security control for a production
> estate, without the mitigations below and your own security review.

## Ingest is not hardened for untrusted networks

garmr has two authentication planes that behave **differently**, and this asymmetry
is the most important thing to understand:

- The **query / web-console API** (`api_bind`, default `127.0.0.1:3110`) **fails
  closed** on a non-loopback bind: `garmr serve` refuses to start on a non-loopback
  address unless `GARMR_API_TOKEN` is set.
- The **ingest plane** (`ingest_bind`, default `0.0.0.0:3100`) does **not** fail
  closed and is the weak surface today.

### Native HTTP ingest does not fail closed without collector auth

- The native endpoint (`POST /ingest/v1/events`) binds to **`0.0.0.0:3100` by
  default** and, with no collectors configured, **accepts every POST
  unauthenticated**.
- Collector authentication (`GARMR_COLLECTORS`, per-collector bearer tokens) is
  **opt-in**, and even when enabled it is **not tied to the bind address** — there
  is no "refuse to serve on a non-loopback address without auth" guard on the
  ingest path (unlike the API plane).
- **Mitigation:** bind ingest to loopback or a trusted management interface, put it
  behind a reverse proxy / mTLS / firewall that enforces authentication, configure
  `GARMR_COLLECTORS` so events are source-bound, and keep it off any untrusted
  network. Configure authenticated collectors **before** enabling environment
  learning.

### Native ingest lacks request-body, event-count, and field-size limits

- The handler reads the whole request body and parses an **unbounded** array (or
  NDJSON stream) of events; individual fields are unbounded strings. There is **no
  configured** limit on body size, number of events per request, or per-field
  length. (The web framework's implicit default body limit is the only backstop,
  and it is not a garmr-enforced control over event count or field size.)
- **Impact:** a malicious or misconfigured client can submit very large payloads —
  a resource-exhaustion / denial-of-service surface.
- **Mitigation:** enforce size and rate limits at a reverse proxy in front of
  ingest; do not expose ingest to untrusted clients.

### Loki-compat ingest has no collector authentication at all

- The optional Loki push endpoint (`loki-compat` build, `/loki/api/v1/push`)
  performs **no** authentication — the collector-auth mechanism is not present on
  this path even when `GARMR_COLLECTORS` is set — and has the same absence of
  body/event/field limits.
- **Mitigation:** treat the Loki endpoint as trusted-network-only, behind a proxy
  that authenticates, or prefer the native endpoint with collectors.

### Arrow Flight ingest is experimental — treat it as disabled by default

- The Arrow Flight endpoint (`flight` build, `flight_bind`) is **off by default**
  (no bind unless explicitly configured) and should be treated as
  **disabled-by-default and experimental**.
- When enabled it inherits the **same optional, default-off** collector auth as
  native ingest and the **same absence of a non-loopback guard** and per-message
  size limits.
- **Mitigation:** leave `flight` unbuilt/unset unless you are evaluating it on a
  trusted, isolated segment.

## Unauthenticated denial-of-service surfaces

Two endpoints do disproportionate work relative to the privilege needed to reach
them. On a tokenless/loopback deployment (`GARMR_API_TOKEN` unset) the whole API is
unauthenticated; even with a token, the surfaces below are reachable by the
lowest-privilege principal.

### Audit status / verify re-verify the whole ledger per request

- `GET /api/audit/status` and `GET /api/audit/verify` run the **full offline ledger
  verification** on **every** request (cryptographic re-hashing that scales with
  ledger size), with **no caching and no rate limiting**, and they are **not
  gated to admin** — any authenticated read principal (or anyone, if no token is
  set) can poll them.
- **Impact:** an amplification / CPU-exhaustion surface that grows with ledger size.
- **Mitigation:** require a token, restrict who can reach the API, and rate-limit
  these paths at a proxy.

### Passkey login-finish writes a durable, unrated audit record per request

- `POST /auth/passkey/login/finish` is a **public (pre-auth)** endpoint. Every
  request — including failures — drives a durable, **fsync'd, non-rate-limited**
  append to the tamper-evident audit ledger, plus (once a public ceremony is
  obtained) signature-verification CPU.
- **Impact:** an unauthenticated request can force synchronous disk writes and
  unbounded ledger growth — a denial-of-service surface.
- **Mitigation:** keep the login surface off untrusted networks and rate-limit it
  at a proxy; monitor ledger growth.

## Capability caveats

- **External model use is optional and egress-controlled.** The Anthropic backend
  is not required; a local model (Ollama / llama.cpp / vLLM) is first-class and the
  only mode under air-gap. `GARMR_AIRGAP=1` overrides `[route.egress]` settings and
  denies all external egress. Free-text PII in a message body is **not**
  auto-classified — set `default_classification = "confidential"` for a PII
  deployment.
- **Semantic search is optional** and requires the `semantic` build plus a local
  embedding model (`GARMR_EMBED_MODEL`). Without it, hybrid search is structured +
  full-text only.
- **Feature-gated capabilities.** `loki-compat`, `flight`, `mcp`, and `semantic`
  are off in a default build; `znippy` (cold-storage codec) is on by default and
  can be dropped with `--no-default-features`.
- **HA is not distributed consensus.** It is one writer plus read-only followers
  pulling snapshots. The data-movement core is implemented and tested, but
  **cross-host failover and consistency under concurrent write load are
  UNVERIFIED** — exercised only on a single host. Do not rely on automatic
  failover.
- **Online backup capture is deferred.** Consistent backup requires `serve` stopped
  (the writer-lock interlock). Online / copy-on-write capture is designed but not
  drilled.
- **Response actions ship empty.** garmr includes **no** response capability by
  default; each action must be explicitly wired to an argv template, is opt-in, and
  requires human approval + independent re-validation. The executor subprocess is
  outside the egress chokepoint (the human approval is the gate there).

## The agent's residual risks

- The agent is read-only and propose-only, and log content is treated as data, not
  instructions — but a prompt-injected log line can still **skew summary prose**.
  It cannot trigger an action or an unauthorized retrieval, because the grounding
  flow has no tools and retrieval is safe by construction.
- The model's verdict is a **prediction**, not adjudicated truth. Do not treat a
  garmr verdict as an incident determination; a human decision and a post-incident
  outcome are separate records.

## What "reviewed configuration" means

Before any exposure beyond an isolated lab, at minimum:

1. Keep ingest, Loki, and Flight endpoints off untrusted networks; put
   authentication, size limits, and rate limits in front of them at a proxy.
2. Set `GARMR_API_TOKEN` (and distinct `GARMR_ADMIN_TOKEN`); register passkeys.
3. Configure `GARMR_COLLECTORS` and enable environment learning only afterward.
4. Set the model-routing classification floor for any PII/sensitive deployment, or
   run air-gapped (`GARMR_AIRGAP=1`).
5. Rate-limit the audit-status/verify and passkey-login paths.
6. Perform your own security review; this list is not exhaustive.
