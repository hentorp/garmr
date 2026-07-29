# Threat model — audit-log poisoning

Scope: an adversary who forges, injects, or tampers with **application-audit
events** to hide their own activity, fabricate activity by others, or frame an
innocent actor. Distinct from
[../threat-model-audit-integrity.md](../threat-model-audit-integrity.md), which
covers garmr's own tamper-evident ledger of *its* actions; this covers the
integrity of the ingested audit *stream* garmr reasons over.

Companion: [baseline-poisoning](baseline-poisoning.md),
[insider-risk](insider-risk.md). Design:
[../architecture/postgresql-audit.md](../architecture/postgresql-audit.md),
[../architecture/application-audit-analytics.md](../architecture/application-audit-analytics.md).

## Assets

- The **fidelity** of the audit stream: that a stored `AuditRecord` reflects a real
  action by the named actor on the named resource.
- The **completeness** of the stream: that missing events are detectable, not
  silent.
- The **attribution** of each event to a real, authenticated source.

## Adversaries and capabilities

| Adversary | Capability |
|-----------|-----------|
| Log injector | can write to a log file / send to the ingest endpoint |
| Credential holder | holds an ingest credential (a compromised shipper) |
| Application insider | can cause real-but-misleading audit rows (e.g. act as a shared account) |
| Disk/transport tamperer | can alter events in flight or at rest before ingest |
| Framing adversary | wants a *forged* row attributed to another actor |

## Attack → defense

### 1. Tamper with a stored event after ingest

- **Defense.** Every stored event carries `raw_payload_hash` = BLAKE3 of the raw
  message (`crates/garmr-store/src/schema.rs:98,153`) and a content-derived
  `event_id` = BLAKE3 over the identifying fields (`event_id_for`,
  `schema.rs:80`). Altering the message or the identifying fields changes the
  hash/id, so post-ingest tampering is detectable and a replay of the *same*
  logical event is idempotent (same id ⇒ dedup, `schema.rs:78`).

### 2. Hide the fact that garmr itself was told to act (or not act) on an event

- **Defense.** Every security-relevant action garmr takes is recorded in the
  tamper-evident, BLAKE3-chained, signed audit ledger (`crates/garmr-audit/`;
  `record_hash = BLAKE3(canonical(envelope) ‖ previous_hash)`,
  [../threat-model-audit-integrity.md](../threat-model-audit-integrity.md) §36).
  A sensitive query/export/decision cannot be silently un-recorded (fail-closed
  outbox for high-risk operations). This bounds an attacker who compromises garmr,
  not just the upstream producer.

### 3. Drop events to hide activity (deletion / truncation of the feed)

- **Defense.** Per-collector **ingest sequence tracking**
  (`crates/garmr-store/src/state/ingest_seq.rs`): an authenticated collector stamps
  each batch with a monotonic seq inside an epoch (`X-Garmr-Seq`/`X-Garmr-Epoch`,
  `ingest_seq.rs:1-6`). After durable persistence the server classifies the
  observation; a hole that survives the bounded `missing` set is a **confirmed
  gap** (`SeqVerdict::Gap`, `ingest_seq.rs:70`) audited as `ingest.seq_anomaly`
  (`crates/garmr-audit/src/event.rs:219`). The classifier is reorder-tolerant so a
  pipelined out-of-order batch is not a false gap (`ingest_seq.rs:8-22`), while a
  real dropped tail is caught. Deleting from the downstream warehouse breaks the
  `event_id`/`raw_payload_hash` provenance and (for garmr's own actions) the ledger
  chain.

### 4. Forge events / spoof a source to frame another actor or launder novelty

- **Defense: authenticated collector binding (Phase 12).** Before binding, the
  source identity was the shipper-**self-declared** `event.source` string, so one
  collector could present as many sources (`environment.rs:1053-1061`). Phase 12
  binds it: a collector authenticates with a per-collector bearer token
  (`GARMR_COLLECTORS`, secret from env — never config or logs), each accepted event
  is stamped with the **trusted collector id** and `source_trust = "authenticated"`
  (`schema.rs:64-73,159`), and the env learner keys on that id
  (`derive_candidates_bound`, `environment.rs:1094`). Consequences:
  - one compromised collector can forge only **its own single source**, never N;
  - **unauthenticated** events (NULL collector id) are **dropped** by the learner
    in bind mode, not folded onto a shared sentinel (`environment.rs:1115`);
  - an authenticated collector that asserts a source outside its allowlist is
    audited as `ingest.source_denied` (`event.rs:214`), separate from and
    separately rate-limited against `ingest.auth_denied` (`event.rs:211`), so a
    bad-token flood cannot mask a spoof attempt.

  A forged row still cannot be attributed to a *different authenticated collector*
  without that collector's token; and a framing row that names another actor is
  weighed against the framed actor's own trusted baseline
  ([baseline-poisoning](baseline-poisoning.md)) rather than taken at face value.

### 5. Feed malformed events to blind the detectors

- **Defense.** **Parser health metrics**
  ([../architecture/postgresql-audit.md](../architecture/postgresql-audit.md) §5):
  drop rate, unmapped-field rate, reassembly failures, and ingest lag are surfaced,
  and a degraded parser drives baselines to the `Degraded` maturity state (abstain)
  rather than emitting garbage findings
  ([../architecture/user-behavior-analytics.md](../architecture/user-behavior-analytics.md) §4).
  The typed lens is forward-compatible (unknown enum values → `Unknown`/`Other`,
  `app_audit.rs:142,235`), so a novel/garbage field never crashes the pipeline.

## Residual risks (documented, not hidden)

- **Real-but-misleading events.** An insider who genuinely acts as a shared
  service account produces *authentic* audit rows; integrity controls cannot
  distinguish "real misuse" from "real use" — that is the job of UEBA + policy
  ([insider-risk](insider-risk.md)), not this layer.
- **Binding governs future learning only.** Collector binding does not
  retroactively re-attribute facts learned before it was enabled — **configure
  `GARMR_COLLECTORS` before enabling `environment.learn`**
  ([../architecture/environment-model.md](../architecture/environment-model.md) §"Authenticated
  source binding").
- **Pre-ingest tampering by the source host.** If the producer host is fully
  compromised, it can emit self-consistent forged rows under its own valid
  collector token; the residual is bounded to that one source's scope, detectable
  as behavioural deviation, but not prevented by integrity controls alone.
- **Clock trust.** `event_ts` is source-supplied; `ingest_time` (`schema.rs:56`)
  is server-stamped, so ordering and lag never depend on the source clock's
  honesty.
