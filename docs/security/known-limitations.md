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

> **Bottom line:** garmr's *native* ingest and its query API now fail closed on a
> non-loopback bind without authentication, and native ingest enforces its own
> request limits. The optional **Loki-compat** receiver does not — it is the
> weakest surface in the tree. Do not rely on garmr as the sole security control
> for a production estate without the mitigations below and your own security
> review.

Every claim below was checked against the code in this tree, with the file and
the covering test named. `scripts/check-doc-consistency.sh` re-checks the
load-bearing constants in CI so this page cannot silently drift from the code.

## The three authentication planes

garmr's listeners have **different** defaults and different guarantees. This
asymmetry is the most important thing to understand:

| Listener | Config key | Default | Fails closed off-loopback? | Per-request auth |
|---|---|---|---|---|
| Query / web-console API | `ingest.api_bind` | `127.0.0.1:3110` (loopback) | **Yes** — needs `GARMR_API_TOKEN` | Bearer token / passkey session |
| Native HTTP ingest | `ingest.ingest_bind` | `0.0.0.0:3100` | **Yes** — needs `GARMR_COLLECTORS` | Bearer collector token (when configured) |
| Loki-compat push | `ingest.loki_bind` | `0.0.0.0:3100` | **No** | **None** |
| Arrow Flight ingest | `ingest.flight_bind` | `None` (disabled) | **Yes** — needs `GARMR_COLLECTORS` | Bearer collector token (when configured) |
| Syslog UDP/TCP | `ingest.syslog_bind` | `None` (disabled) | **No** | **None** (protocol has none) |

Because native ingest defaults to `0.0.0.0:3100`, a default `garmr serve` on a
host with a routable interface **refuses to start** until you configure
`GARMR_COLLECTORS` or move the bind to loopback. That is intended behaviour, not
a bug.

## Native HTTP ingest — implemented controls

These are **implemented and tested**, not planned:

- **Fail-closed startup.** `garmr serve` refuses to start when `ingest_bind`
  resolves to any non-loopback address and no collectors are configured
  (`bind_auth_gate`, `crates/garmr-cli/src/serve.rs`). Tested by
  `loopback_without_auth_is_allowed`, `nonloopback_without_auth_is_refused`,
  `nonloopback_with_collector_auth_is_allowed`.
- **Bearer-token collector authentication.** With a non-empty `GARMR_COLLECTORS`
  registry every `POST /ingest/v1/events` must present a valid
  `Authorization: Bearer <token>`; an unknown token is `401`.
- **Authentication happens before decoding.** The bearer check runs before the
  body is parsed, so an unauthenticated request never reaches the JSON/NDJSON
  parser and never receives a parser-error message
  (`ingest_events`, `crates/garmr-ingest/src/server.rs`).
- **Source allowlisting with whole-batch rejection.** A collector may only assert
  the `source` values bound to it. If *any* event in a batch names a forbidden
  source the **entire batch** is rejected with `403` — a forged source never
  lands partially.
- **Server-stamped trusted collector identity.** The `collector_id` written with
  the batch is derived from the resolved token on the server; a client cannot
  assert its own identity.
- **Request limits**, enforced both at the transport layer and again inside the
  decoder (`crates/garmr-ingest/src/native.rs`):

  | Limit | Value | Constant |
  |---|---|---|
  | Request body | 8 MiB | `MAX_BODY_BYTES` |
  | Events per request | 50 000 | `MAX_EVENTS_PER_REQUEST` |
  | Single `message` | 256 KiB | `MAX_MESSAGE_BYTES` |
  | Single `fields` value | 64 KiB | `MAX_FIELD_VALUE_BYTES` |

  Each is covered by a unit test (`rejects_over_large_body`,
  `rejects_too_many_events`, `rejects_over_long_message`,
  `rejects_over_long_field_value`), and an over-limit batch is rejected
  wholesale rather than partially ingested.
- **Rate-limited denial auditing.** Repeated bad-token or forbidden-source POSTs
  are coalesced into one aggregated audit record per 60 s window per class, so a
  flood cannot force one synchronous ledger append per request. Authentication
  failures and source-binding violations are counted **separately** so a
  binding violation is never masked by a bad-token flood.

### Native ingest — remaining limitations

- **No transport encryption.** garmr speaks plain HTTP on the ingest port.
  Collector bearer tokens and event content are exposed to anyone who can
  observe the path unless you terminate TLS at a reverse proxy or carry it over
  a private/encrypted network (WireGuard, Tailscale, mTLS at a proxy).
- **No built-in rate limiting.** The size limits bound a *single* request; there
  is no cap on request *frequency*. An authenticated collector — or anyone, on a
  loopback/dev deployment — can issue requests as fast as the daemon accepts
  them. Rate-limit at the proxy.
- **The fail-closed gate has a documented override.** `GARMR_INGEST_ALLOW_UNAUTH=1`
  permits an unauthenticated non-loopback bind, with a loud warning. It exists
  for local development. Do not set it in a deployment.
- **Unauthenticated loopback development is a real, different posture.** With no
  `GARMR_COLLECTORS`, ingest on loopback accepts every POST unauthenticated and
  no collector identity, sequence tracking, or source binding applies. That is
  the development mode, not a deployment mode.

## Loki-compat ingest — the weakest surface

The optional Loki push endpoint (`loki-compat` build, `POST /loki/api/v1/push`,
`loki_bind` default `0.0.0.0:3100`) does **not** share native ingest's controls.
Verified in `run_loki` / `push` (`crates/garmr-ingest/src/server.rs`):

- **No authentication of any kind.** The collector registry is not consulted on
  this path even when `GARMR_COLLECTORS` is set. Batches are stored with no
  collector attribution (`collector_id: None`).
- **No fail-closed bind gate.** Unlike native and Flight ingest, the Loki
  listener is started unconditionally — a non-loopback `loki_bind` with no
  authentication is *not* refused.
- **No source allowlisting** and **no delivery-sequence tracking**.
- **No garmr-enforced body / event-count / field-size limits.** Only the web
  framework's default body cap applies; the native path's `MAX_*` constants are
  not applied here.

**Mitigation:** prefer the native endpoint. If you need Loki compatibility,
treat the endpoint as trusted-network-only, bind it to loopback or a management
interface, and put a proxy in front that authenticates and enforces size and
rate limits.

## Arrow Flight ingest — experimental, with real controls

The Arrow Flight receiver (`flight` build, `flight_bind`) is **off by default**
(`flight_bind` defaults to `None`) and is **experimental**. It is *not*
unauthenticated when a collector registry is configured. Verified in
`crates/garmr-ingest/src/flight.rs` and `serve.rs`:

**Fixed security issues / implemented controls**

- **Fail-closed startup**, identical to native ingest: a non-loopback
  `flight_bind` with no configured collectors is refused
  (`check_flight_bind_auth`; tested by `flight_nonloopback_without_auth_is_refused`).
- **Bearer-token collector authentication on `do_put`** against the same
  `GARMR_COLLECTORS` registry; an unknown token is `UNAUTHENTICATED`.
- **The legacy self-declared `garmr-collector-id` gRPC header is never trusted.**
  Identity is derived exclusively from the bearer token. Covered end-to-end by
  `flight_do_put_cannot_spoof_collector_identity`
  (`crates/garmr-ingest/tests/flight_e2e.rs`).
- **Server-derived collector identity** stamped on every appended batch.
- **Source allowlisting**: a batch whose `source` column contains a value the
  authenticated collector may not assert is rejected with `PERMISSION_DENIED`.
- **Stream resource limits**, enforced before any enrich/append work, each with
  an env override and unit tests (`flight_do_put_rejects_oversized_batch_and_accepts_normal`,
  `flight_do_put_aborts_stream_over_cumulative_caps`):

  | Limit | Value | Constant / override |
  |---|---|---|
  | Rows per batch | 1 000 000 | `MAX_FLIGHT_ROWS_PER_BATCH` / `GARMR_FLIGHT_MAX_ROWS_PER_BATCH` |
  | Batches per stream | 10 000 | `MAX_FLIGHT_BATCHES_PER_STREAM` / `GARMR_FLIGHT_MAX_BATCHES_PER_STREAM` |
  | Rows per stream | 50 000 000 | `MAX_FLIGHT_ROWS_PER_STREAM` / `GARMR_FLIGHT_MAX_ROWS_PER_STREAM` |
  | Next-frame receive timeout | 60 s | `FLIGHT_BATCH_RECV_TIMEOUT` / `GARMR_FLIGHT_BATCH_RECV_TIMEOUT_SECS` |

- **Explicit experimental warning** logged once per process when the receiver
  starts or a stream arrives.

**Remaining experimental limitations**

- Having these controls does **not** make Flight production-ready. The transport
  has had far less exposure than native ingest, and only the limit policy, the
  IPC round-trip, and collector-spoofing resistance are covered by tests — there
  is no soak or adversarial-fuzz coverage of the gRPC surface.
- **No transport encryption**: the gRPC server is plaintext h2c; there is no
  built-in TLS. Tokens and event data need an encrypted path.
- **No built-in rate limiting** on connection or stream establishment.
- With an **empty** collector registry (the default-off posture) a loopback
  Flight receiver accepts unauthenticated batches and stores them without
  collector attribution.
- Only `do_put` is implemented; every other Flight method returns
  `unimplemented`.

**Mitigation:** leave `flight` unbuilt and `flight_bind` unset unless you are
deliberately evaluating it on a trusted, isolated segment.

## PostgreSQL / pgAudit — what actually runs where

garmr contains a full PostgreSQL/pgAudit parser (`crates/garmr-ingest/src/pg.rs`)
that runs each statement through `garmr_sql::analyze` to produce canonical
actor / database / statement / object fields and a SQL fingerprint. **It is not
reached by the recommended collector path.** This is the most important
documentation correction on this page.

| Path | Build | What the receiver does |
|---|---|---|
| `garmr pgaudit-ship` → native `/ingest/v1/events` (**recommended collector**) | default | Ships each reassembled csvlog row as the event `message` with `source=postgres-csvlog`, `log_type=audit` and **no** `fields`. The native endpoint applies the **generic** field extractor (`src_ip` / `user` / `port` regexes) — the pgAudit CSV parser and SQL analysis do **not** run. |
| Loki push with stream label `source=postgres-csvlog` / `postgres-jsonlog` | `loki-compat` | Full pg adapter: canonical audit fields + SQL fingerprint. Runs on the **unauthenticated** Loki path (see above). |
| `garmr replay --format postgres-csvlog` / `postgres-jsonlog` | default | Full pg adapter — offline import only. |

Consequences you must plan for:

- Events shipped by `garmr pgaudit-ship` carry `log_type=audit`, so the
  application-audit plane *accepts* them, but `AuditRecord::from_event` reads
  canonical keys (`db_user`, `statement`, `object_table`, …) out of `fields` —
  which that path does not populate. The typed record is therefore largely
  **empty**, and access-policy evaluation, object-level detectors, and SQL
  fingerprinting have nothing to work on. The raw csvlog row is still stored,
  searchable, and queryable.
- Full pgAudit semantic analysis in a **live** path today requires a
  `loki-compat` build and the Loki receiver — which is the unauthenticated
  surface. That combination (rich parsing + no ingest authentication) is a real
  trade-off, not a recommendation.
- **This is partial wiring, and it is tracked as an alpha gap.** The fix is to
  route the native endpoint through the adapter registry by `source`; until then
  do not assume `pgaudit-ship` gives you object-level audit analytics.

## Denial-of-service surfaces

### Audit status / verify — now admin-gated, still uncached

- `GET /api/audit/status` and `GET /api/audit/verify` run the **full offline
  ledger verification** (`verify_dir`) on **every** request — cryptographic
  re-hashing that scales with ledger size.
- **Fixed:** both are now gated by `check_admin` **in the handler**
  (`crates/garmr-cli/src/api/admin.rs`), so a viewer/analyst principal cannot
  reach them, and on a deployment with no tokens configured they return `401`
  rather than running the scan. They stay mounted on the public read router so
  token-less and passkey-only deployments resolve them instead of 404-ing.
- **Remaining:** there is still **no caching and no rate limiting**. An
  authenticated *admin* (or a stolen admin token) can poll them and force
  repeated O(ledger) work. The scan runs on a blocking pool, so it competes with
  other work rather than blocking the runtime.
- **Mitigation:** keep admin credentials scarce; rate-limit these two paths at a
  proxy; monitor ledger size.

### Passkey login-finish — failure auditing now coalesced

- `POST /auth/passkey/login/finish` is a **public (pre-auth)** endpoint.
- **Fixed:** anonymous *failed* attempts no longer write one durable ledger
  record each. `FailedAuditThrottle` (`crates/garmr-cli/src/api/passkey.rs`)
  writes the first failure in each 60 s window durably and folds subsequent
  failures into a count carried by the next durable record; every failure is
  still traced.
- **Remaining:** each *successful* login still writes a durable audit record,
  and every request still costs ceremony lookup plus, once a ceremony is
  obtained, ECDSA signature-verification CPU. There is **no rate limiting** on
  the endpoint.
- **Mitigation:** keep the login surface off untrusted networks and rate-limit
  it at a proxy.

### Other work-amplification notes

- Full-text search over a high-cardinality live corpus can be expensive; broad
  queries are bounded by the API's query timeouts rather than by a cost model.
- The API has **no global rate limiter**. Every "rate-limit at a proxy"
  recommendation on this page is load-bearing.

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

## Supply-chain exceptions

`cargo deny check` passes. Standalone `cargo audit` reports four advisories that
`deny.toml` carries as **audited, individually justified exceptions** — each with
a reachability argument and a named clearing condition (`RUSTSEC-2026-0041`
lz4_flex, `RUSTSEC-2025-0132` maxminddb, `RUSTSEC-2026-0194` / `RUSTSEC-2026-0195`
quick-xml), plus unmaintained-crate warnings. Read `deny.toml` before trusting
the tree; the exceptions are not blanket suppressions.

Two further advisories are **reviewed but not visible to those tools**, and are
recorded as comments in `deny.toml` rather than as suppressions:
`RUSTSEC-2026-0221` (event-listener unsoundness, which `cargo deny` does not flag
against this graph) and **`CVE-2026-43868`** (thrift 0.17 memory allocation —
present only in GitHub's advisory database, so `cargo audit` and `cargo deny`
never see it and only Dependabot surfaces it). A green `cargo deny check` is
therefore *not* proof that no advisory applies; see
[../supply-chain.md](../supply-chain.md).

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

1. Configure `GARMR_COLLECTORS` for native ingest (the daemon enforces this on a
   non-loopback bind) and enable environment learning only afterward.
2. Keep the Loki, Flight, and syslog endpoints off untrusted networks — none of
   them authenticates the way native ingest does. Put authentication, size
   limits, and rate limits in front of them at a proxy.
3. Terminate TLS in front of every listener; garmr has no built-in TLS.
4. Set `GARMR_API_TOKEN` (and a distinct `GARMR_ADMIN_TOKEN`); register passkeys.
5. Set the model-routing classification floor for any PII/sensitive deployment, or
   run air-gapped (`GARMR_AIRGAP=1`).
6. Rate-limit the audit-status/verify and passkey-login paths.
7. Do not assume `garmr pgaudit-ship` yields object-level audit analytics — see
   the pgAudit section above.
8. Perform your own security review; this list is not exhaustive.
