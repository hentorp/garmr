# PostgreSQL / pgAudit ingestion — architecture (Phase 2 target)

Status: target design. **The canonical model it targets (Phase 1) is done**
(`crates/garmr-core/src/app_audit.rs`); the adapter that populates it from
PostgreSQL/pgAudit is the Phase-2 deliverable. See
[application-audit-analytics.md](application-audit-analytics.md) for the product
framing and [access-audit.md](../access-audit.md) for the shipped register audit
contract this generalizes.

## 1. Goal

Turn a PostgreSQL audit trail into canonical [`AuditRecord`] fields with **no
downstream code changes**. The adapter's only job is normalization: it folds
PostgreSQL/pgAudit vocabulary onto the storage-canonical keys in
`app_audit.rs::keys` (`app_audit.rs:41`), exactly as `garmr-ingest` already folds
register aliases. Once written, an event is read by the typed lens
(`AuditRecord::from_event`, `app_audit.rs:554`), the correlation SQL, per-actor
RBA, and the entity pivots — none of which know it came from Postgres.

The invariant from Phase 1 holds: **normalization happens once, at ingest.** The
core lens performs only ordered-candidate alias resolution (`app_audit.rs::first`,
`app_audit.rs:499`); it never re-parses. So the adapter must emit canonical keys
(or a known alias the lens already accepts, `app_audit.rs:899-939`).

## 2. Supported input formats (target)

| Format | Path | Notes |
|--------|------|-------|
| CSV log (`log_destination = csvlog`) | file tail / offline import | fixed column order; robust field mapping |
| JSON log (`jsonlog`, PG 15+) | file tail / offline import | one object per line |
| syslog | existing syslog receiver | multiline reassembly required |
| pgAudit **SESSION** logging | any of the above | statement-level audit in the message body |
| pgAudit **OBJECT** logging | any of the above | per-object (table) audit rows |
| `log_line_prefix` metadata | prefix parser | user/db/host/session/txid extracted from the prefix |
| offline import | `garmr` import command | air-gap friendly; replay-safe via content id |
| canonical HTTP ingest | native `/ingest/v1/events` | pre-normalized JSON — the recommended shipper path |

The recommended production path is the same as the register flagship: ship
already-normalized JSON with `log_type=audit` over the native ingest endpoint (or
Loki push), so the collector — not garmr — owns the parser. The file/CSV/syslog
parsers exist for deployments that cannot change the producer.

## 3. Fields extracted → canonical keys

The adapter maps pgAudit / `log_line_prefix` fields onto the Phase-1 canonical
keys. A representative mapping (all keys defined in `app_audit.rs:41-124`):

| PostgreSQL source | Canonical key | `AuditRecord` field |
|-------------------|---------------|---------------------|
| `session_user` | `db_user` / `authenticated_identity` | `actor.actor_id` / `actor.authenticated_identity` |
| `current_user` (after `SET ROLE`) | `effective_identity` | `actor.effective_identity` |
| database name (`%d`/`datname`) | `database` | `context.database` |
| schema | `database_schema` | `context.database_schema` |
| client host/addr (`%h`) | `client_host` / `client_ip` | `context.client_host` / `context.client_ip` |
| application name (`%a`) | `client_application` | `context.client_application` |
| session id (`%c`), txid (`%x`) | `session_id` / `transaction_id` | `context.session_id` / `context.transaction_id` |
| pgAudit statement class | `action` / `query_type` | `action.action` / `action.query_type` |
| pgAudit object name | `object_name` / `object_table` | `action.object_name` / `action.object_type` |
| full SQL text | `statement` | `action.statement` |
| `SQLSTATE` | `error_code` | `action.error_code` |
| `SQLSTATE` class (`00000`/`42501`) | `outcome` | `action.outcome` (via `Outcome::parse`) |
| rows / duration | `rows_read` / `duration_ms` | `action.rows_read` / `action.duration_ms` |

Two derivations are automatic in the lens and need not be emitted:

- **`query_type`** is parsed from `query_type` else from `action`
  (`app_audit.rs:611`), tolerant of spellings (`QueryType::parse`,
  `app_audit.rs:240`); `COPY`/`EXPORT`/`UNLOAD` all fold to `QueryType::Copy`.
- **`privilege_operation` / `privileged_access`** are inferred when the statement
  is `GRANT`/`REVOKE`/`SET ROLE` (`app_audit.rs:638,660`, `QueryType::is_privilege`),
  so a privilege change is flagged even without an explicit flag.

`Outcome::parse` (`app_audit.rs:189`) maps `00000` → `Success` and `42501`
(`insufficient_privilege`) → `Denied`, so a **permission-denied** row is a
first-class negative outcome (`Outcome::is_negative`, `app_audit.rs:210`) — the
raw material for failed-access UEBA and policy-violation detection.

## 4. Multiline handling

pgAudit statements (and `STATEMENT:`/`DETAIL:` continuations) span multiple log
lines. The adapter must reassemble a logical record before mapping:

- CSV/JSON logs are already one record per row — no reassembly.
- syslog/text logs use `log_line_prefix` as the record boundary: a line that does
  not start with a new prefix is a continuation of the previous record.
- The full reassembled SQL becomes `statement`; the statement text is treated as
  **data, never instructions** everywhere downstream (the `ask`/triage prompts say
  so explicitly, `crates/garmr-agent/src/ask.rs:69`).

## 5. Parser health metrics (target)

The adapter emits health counters so a silently-broken parser is visible (and so a
detector can abstain rather than misfire on garbage):

- lines read / records emitted / records dropped,
- multiline reassembly failures,
- unmapped-field rate and unknown-format rate,
- lag between source time (`event_ts`) and ingest time (`ingest_time`,
  `schema.rs:56`) — the ingest-lag signal.

These feed the Collectors page ([webui-information-architecture.md](webui-information-architecture.md))
and the ingest-health surface that the Phase-12 per-collector sequence tracker
already backs (`crates/garmr-store/src/state/ingest_seq.rs`).

## 6. Raw-payload digest & provenance

Every stored event already carries provenance from Event V2 (`schema.rs`):

- **`raw_payload_hash`** = BLAKE3 of the raw message (`schema.rs:98,153`) — the
  parser's input is fingerprinted, so a re-parse or a tamper is detectable.
- **`event_id`** = content-derived BLAKE3 over the identifying fields
  (`event_id_for`, `schema.rs:80`) — the same logical audit row re-ingested
  (offline replay, retry) yields the same id, which is the dedup key.
- **`parser_name`**, **`source_trust`**, **`collector_id`** — the collector that
  delivered the row (`schema.rs:64-73`); an authenticated pgAudit collector stamps
  `source_trust = "authenticated"` (see
  [../threat-models/audit-log-poisoning.md](../threat-models/audit-log-poisoning.md)).

The adapter should populate `parser_version` / `schema_version`
(`app_audit.rs:122-123`) so a parser regression is attributable to a version.

## 7. What the adapter must NOT do

- It must not hold a watchlist or a self-access map — those stay **app flags**
  (`watched`, `is_self`, `app_audit.rs:58-60`), so garmr never mirrors sensitive
  lists (data minimization, per [access-audit.md](../access-audit.md) §7).
- It must not classify sensitivity by inspecting SQL — `data_classification` is an
  operator/collector-supplied tag (`app_audit.rs:116`); the model router's fence
  reads it (see [model-routing.md](model-routing.md)).
- It must not re-implement alias folding in the core; the core lens is a no-I/O
  leaf (`domain.rs:9-16`).

[`AuditRecord`]: ../../crates/garmr-core/src/app_audit.rs
