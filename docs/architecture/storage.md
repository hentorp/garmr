<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Storage

garmr is **single-writer** by design: exactly one `garmr serve` process ingests,
detects, and owns the embedded stores. That is deliberate — it is why the storage
layer is simple and consistent — and it shapes everything on this page.

## The three stores

A node's durable state is three stores with no cross-store transaction:

- **Events warehouse** (`store.warehouse_dir`) — an embedded Apache Iceberg
  lakehouse (the vendored **skade** engine): immutable, content-addressed data
  files plus `catalog.redb`, the mutable snapshot pointer. Queried with DataFusion
  SQL. Self-compacting with crash recovery.
- **State DB** (`store.state_db`) — an embedded **redb** database holding cases,
  environment facts, registries, budgets, ingest-sequence state, and auth/session
  state.
- **Audit ledger** (`audit.dir`) — an append-only, BLAKE3-chained,
  ed25519-signed, offline-verifiable log (see below).

Because one process owns these, the raw-file CLI commands (`compact`, `backup`,
`restore`, `reindex`, offline `cold-query`) run when `serve` is **stopped**.
Querying while serving goes through the daemon's API/console, not the raw files —
the same exclusive-writer model as SQLite or a single Splunk/Elastic node.

## Event model and provenance

garmr stores one thin event type: a small set of canonical labels (host, service,
source, environment, severity, log_type) plus a `message` and a `fields`
key/value map that ingest normalizes. Higher-level views (for example the
application-audit record, see [application-audit.md](application-audit.md)) are
**lenses** over those canonical fields, not a second stored type.

Each stored event carries provenance:

- **`event_id`** — a content-derived BLAKE3 over the identifying fields, so the
  same logical event re-ingested (offline replay, a retry) yields the same id and
  deduplicates.
- **`raw_payload_hash`** — BLAKE3 of the raw message, so post-ingest tampering is
  detectable.
- **`collector_id` / `source_trust`** — the authenticated collector that delivered
  the row, when collector binding is enabled.
- Server-stamped **ingest time** in addition to the source-supplied event
  timestamp, so ordering and lag never depend on the source clock's honesty.

## Hot/cold tiering (retention)

Compaction runs on the single writer, so its cost must be bounded or it would grow
with total history and stall ingest. garmr keeps a bounded recent window hot and
seals older windows into an immutable cold tier:

1. **Seal** — a periodic pass seals `window_days`-sized windows older than
   `retention_days` into checksummed cold archives under `cold_dir` (the `znippy`
   archiver by default; the pure-Rust `plain` zstd-parquet archiver with
   `--no-default-features`).
2. **Prune** — the next compaction drops rows already sealed to cold, so the hot
   table converges to about `retention_days` of data.
3. **Query** — recent data is served hot; sealed history is thawed on demand via
   `GET /api/query/cold` (bounded range required) or, offline, `garmr cold-query`.

Cold archives are immutable and checksum-verified on read; a tampered or truncated
archive is refused, not silently returned. Lower `retention_days` for cheaper
compaction and more ingest headroom (at the cost of more queries hitting the
slower cold path). See [retention-and-scale.md](../retention-and-scale.md).

## The audit ledger

Every security-relevant action garmr takes emits an `AuditEvent` to one
append-only ledger where `record_hash = BLAKE3(canonical(envelope) ‖
previous_hash)`, ed25519-signed. `garmr audit verify` re-checks the whole chain
offline and exits non-zero on any tampering, so it is CI/monitoring friendly. For
high-risk administrative operations the change is **fail-closed on a durable audit
intent**: no acknowledgement is returned without a durable record.

The ledger records garmr's *own* actions (a tamper-evident record of what the
system was told to do). The integrity of the *ingested* audit stream garmr reasons
over is a separate concern — see the
[audit-log-poisoning](../security/threat-model.md) defenses.

## Governed persistence (versioned registry)

Artifacts that must be governed — models, prompts, toolsets, rules, detector
configs, and the application-audit domains (policies, catalog entries, monitoring
profiles) — are stored as **versioned registry records**. An artifact is an
immutable `RegistryRecord` identified by its BLAKE3 content digest; which version
is *live* is a separate, append-only stream of promotion events.

The hard invariant: **no artifact is live without a versioned record and an audit
event.** A promotion with an empty audit reference is inert on read, so a
hand-forged database row can never make a policy enforced. Rollback and retirement
are further appends. Registry-backed policy/catalog/monitoring enforcement is
config-gated (`GARMR_REGISTRY_POLICIES`, `GARMR_REGISTRY_CATALOG`,
`GARMR_REGISTRY_MONITORING`); unset, the file loaders are used unchanged. A
governance change (a registry promotion, or a plain policy-file edit) can be hot-
reloaded without restarting `serve`.

## Backup, restore, and HA

- **Backup** (`garmr backup create`, serve stopped) captures a signed,
  content-addressed image of the warehouse + state DB + audit ledger, bound to one
  recoverable point. Secrets are never captured (a create-time denylist fails
  closed if any secret path slipped in). **Treat the artifact as confidential** —
  it contains node state, including the session-cookie MAC key.
- **Restore** is fail-closed: verify-before-apply against an out-of-band trusted
  key, path-binding check, atomic swap with a `*.pre-restore-<ts>` rollback, and a
  post-swap resolvability probe. A restored node is a **read-only follower** until
  an audited `garmr backup promote`.
- **HA** is one writer, N read-only followers pulling shipped snapshots — **not**
  distributed consensus. The data-movement core is implemented and unit-tested;
  **cross-host failover and consistency under concurrent write load are UNVERIFIED**
  (exercised only on a single host). See [ha-design.md](../ha-design.md),
  [backup-design.md](../backup-design.md), and
  [status/alpha-status.md](../status/alpha-status.md).

## Status of the pieces

- Iceberg warehouse + redb state + full-text index — Implemented, runtime-wired.
- Hot/cold tiering — Implemented, config-gated (`[retention] enabled`).
- Audit ledger + offline verify — Implemented, runtime-wired.
- Governed registry (all kinds storable; policy/catalog/monitoring wired to a
  consumer) — Implemented; registry-backed enforcement config-gated.
- Backup/restore + single-host promotion — Implemented (minimum viable);
  online capture deferred.
- Multi-node HA failover — Experimental / unverified.
