# Adaptive-audit SOC — architecture

Status: living document (branch `feature/adaptive-audit-soc`). Grounded in the
current implementation; updated as each phase lands. See
[ADR-0001](../adr/0001-adaptive-audit-soc-initiative.md) for the framing decision
and the seven non-negotiable invariants.

## 1. Where garmr is today (baseline)

garmr is a single-writer daemon (`garmr serve`) over three storage tiers:

- **Events warehouse** — skade/Iceberg parquet, one append actor
  (`crates/garmr-store/src/events/mod.rs:99,233`). Schema is a fixed 9-column
  Arrow table (`crates/garmr-store/src/schema.rs:19`): `event_ts, host, service,
  source, environment, severity, log_type, message, fields` (the last a
  JSON-string column). **No event id, no provenance, no schema version.**
- **State store** — embedded redb, 12 insert-overwrite tables
  (`crates/garmr-store/src/state/mod.rs:37-60`): cases, suppression, budget,
  baselines (dead), cold_archives, hunts, proposals, actions, templates,
  cold_meta, silences, auth. **Every write overwrites by key; no history, no
  version, no hash chain.**
- **Full-text index** — Tantivy (`crates/garmr-search`); **semantic vectors** —
  a flat header-less file scanned linearly (`crates/garmr-embed/src/store.rs:136`).

Detection is deterministic (Sigma + correlation TOML + frequency/template
baselines + RBA). A **read-only LLM triage agent** (`crates/garmr-agent`) emits a
single `Verdict` (`crates/garmr-core/src/case.rs:54`). A **separate response
executor** (`crates/garmr-agent/src/executor.rs`) is the only code that changes
external system state, behind human approval + independent re-validation.

### The five structural gaps this initiative closes

1. **No tamper-evident audit.** Everything called "audit" is either an in-record
   `Vec<…>` in a mutable redb blob or an ephemeral `tracing` line to stdout
   (`crates/garmr-cli/src/main.rs:109`). Nothing is hash-chained or signed. Auth
   successes/failures and ad-hoc `ask` interactions are not persisted at all.
2. **Prediction conflated with ground truth.** One `Verdict`, filled only by the
   LLM, is consumed as adjudicated truth in RBA (`crates/garmr-analytics/src/risk.rs:108`),
   case state, institutional memory (`search_cases`), the graph, and the executor
   gate. There is no `AnalystDecision`/`IncidentOutcome` type and no feedback path.
3. **Unguarded learning surfaces.** Frequency and template baselines learn from
   raw history with no exclusion of open/malicious cases
   (`crates/garmr-analytics/src/baseline.rs:97`, `anomaly.rs:239`).
4. **Narrow air-gap switch.** `GARMR_AIRGAP` (`crates/garmr-cli/src/main.rs:39`)
   only closes the IOC-feed loop and sets a no-op flag; LLM APIs, Matrix, webhook,
   SMTP, external MCP, and S3 all stay live.
5. **No versioning / migration framework.** No `schema_version` anywhere; bumping
   the events schema silently halts ingest on an existing warehouse (skade
   `table_or_create` ignores the passed schema — the fix is the uncalled
   `Table::ensure_schema`, `vendor/skade/skade/src/table.rs:483`).

## 2. Target: planes, not just crates

The platform is organized into cooperating **planes**, each with a clear trust
level and write discipline.

```
                        ┌──────────────────────────────────────────┐
   collectors ─────────▶│  Ingest plane   (Event V2 + provenance)   │
   (spool, mTLS, seq)   └───────────────┬──────────────────────────┘
                                        ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  Data plane:  events warehouse · full-text · vector(HNSW) ·     │
   │               cases · environment model (bitemporal)            │
   └───────┬───────────────────────────────┬───────────────────────┘
           ▼                                ▼
   ┌───────────────────┐          ┌────────────────────────────────┐
   │ Detection plane   │          │  Agentic plane (READ-ONLY)      │
   │ ensemble + drift  │          │  hybrid search (Query IR),      │
   │ → SecurityFinding │          │  triage → AgentPrediction       │
   └───────┬───────────┘          └───────────────┬────────────────┘
           ▼                                       ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  Decision plane:  AnalystDecision · IncidentOutcome · Feedback  │
   └───────┬───────────────────────────────────────────────────────┘
           ▼
   ┌───────────────────┐   propose → validate → evaluate → approve  │
   │  Change plane      │   → apply → audit → rollback (uniform;     │
   │  (proposals+apply) │    generalizes executor.rs; no model bypass)│
   └───────┬───────────┘
           ▼
   ┌───────────────────┐   ┌───────────────────┐  ┌────────────────┐
   │ Learning plane     │   │  Model router      │  │ Egress chokept │
   │ (offline, gated)   │   │ (local GPU + ext)  │  │ (GARMR_AIRGAP) │
   └───────────────────┘   └───────────────────┘  └────────────────┘
                    all planes ──▶ Audit ledger (garmr-audit): append-only,
                                   BLAKE3-chained, signed, offline-verifiable
```

Two cross-cutting services sit under everything:

- **Audit ledger (`garmr-audit`)** — every security-relevant action in every
  plane emits an `AuditEvent` to one append-only, hash-chained, signed ledger.
  For high-risk administrative operations the change is **fail-closed on a
  durable audit intent** (outbox): no acknowledgement without a durable record.
- **Egress chokepoint** — one `EgressPolicy` gate at client-construction time;
  `GARMR_AIRGAP=1` denies every outbound class and is unoverridable by other
  config. See [model-routing.md](model-routing.md).

### Hybrid agentic search (Phase 6, done — retrieval)

The agentic plane retrieves through a typed **Query IR** (`garmr-query`), not raw
SQL. A `HybridQuery` carries a structured filter (typed per-column predicates +
`fields` key=value + a numeric time range), an optional full-text clause, and an
optional semantic clause, plus fusion config. It is **safe by construction**: the
structured filter compiles to a single bounded read-only `SELECT` whose table,
columns, projection, `ORDER BY` and `LIMIT` are all compile-time constants and
whose every value reaches SQL only inside a doubled-quote literal (`fields`
key=value additionally `LIKE`-escaped on both key and value) — so no
model-authored string is ever an injection/exfil surface. The compiled string is
still re-checked with `reject_non_readonly` and run under a timeout (defense in
depth). This *shrinks* the read plane's largest injection surface (the older
`ask` raw-SQL path).

The three signals — structured (the gate), full-text (Tantivy BM25), semantic
(local embedding cosine) — are fused with **Reciprocal Rank Fusion** (rank-only,
so heterogeneous scores need no calibration), with per-result provenance
(`[S]`/`[F]`/`[V]`). The semantic index groups by `(host, service, message)`, so
a semantic hit reinforces *all* events sharing that triple rather than a single
timestamp it can't name. Surfaces: the read-only `hybrid_search` agent tool,
`POST /api/hsearch`, and `garmr hsearch`.

**ANN decision:** brute-force cosine over the bounded (≤100k) in-RAM vector
window is kept — exact, dependency-free, and fast at one-person-SOC scale. HNSW
would be approximate, cost more per 900s index rebuild, and add a dependency that
must never be mandatory (invariant #5). The `SemanticSearch` trait is the drop-in
seam for an optional `hnsw` `SemanticSearch` impl if the corpus outgrows the
window or a latency SLO appears. Base build (no `semantic` feature) = structured
+ full-text, no candle edge.

## 3. The uniform change pipeline

Invariant #2: the LLM may only ever write a **Proposal**. Every protected change
— enable a rule, move a threshold, change a baseline, promote a model/prompt,
silence an alert, run a response, export sensitive data, change egress policy —
travels the same path:

```
propose → validate → evaluate → human approval → apply → audit → rollback
```

This **generalizes the existing executor** (`crates/garmr-agent/src/executor.rs`),
which already demonstrates the hard parts and must not be weakened:

- Independent **re-validation at apply time** that never trusts the stored
  proposal (`executor.rs:185`).
- **At-most-once** claim: the state flips `Approved→Executing` and is persisted
  *before* any side effect (`executor.rs:97`); a crash leaves it claimed for
  human reconciliation, never silently re-run.
- **Reversibility** gate + **evidence attestation** (the change must be justified
  by the case's own evidence, `executor.rs:220`).
- A full **audit vector** per transition (`crates/garmr-store/src/state/actions.rs:127`).

Every proposal type (rule, threshold, baseline promotion, prompt, model, lesson,
silence, response, egress-policy) reuses this shape. Approvals are RBAC-gated
(`check_admin`, `crates/garmr-cli/src/api/auth.rs:14`) and produce an
`AuditEvent`. Rollback restores the previous signed release/record.

## 4. Prediction vs. decision vs. outcome (the load-bearing split)

Three immutable, append-only record types replace the single mutable `Verdict`:

- **`AgentPrediction`** — what the model concluded (model+prompt+toolset digests,
  disposition, severity, model + calibrated confidence, rationale, evidence refs,
  proposed actions, token/latency/cost, stop reason, schema-validation result).
- **`AnalystDecision`** — what a human decided (principal, disposition, reason
  codes, accepted/rejected evidence, "prediction correct?", "evidence missed?",
  `supersedes` for corrections). Never overwrites a prior decision.
- **`IncidentOutcome`** — the post-incident ground truth, including
  false-negatives that never generated a case.

RBA and all learning consume **trusted outcome first, discounted prediction
otherwise, and never give positive learning weight to an unresolved
self-prediction**. A derived current-case view is materialized on top of the full
history. This disentangles the eight conflation sites enumerated in the recon
(chief among them `risk.rs:108`, `agent.rs:282`, `render.rs:14`, `executor.rs:208`).

## 5. Data provenance (Event V2)

Event V2 is **backward compatible and additive**. New provenance columns
(`event_id`, `schema_version`, `event_class/category/activity`, times
[event/observed/ingest], `collector_id/sequence`, `source_event_id`, site/zone,
`parser_name/version`, `normalizer_version`, `raw_payload_hash`, `source_trust`,
`data_classification`, typed attrs) are added such that:

- the events Arrow schema is evolved **only** via `Table::ensure_schema` at
  startup (after `heal_table`, before serving) — otherwise ingest halts on
  existing warehouses (recon risk #1);
- all new struct/JSON fields are `#[serde(default)]`; no enum variant is renamed
  (recon risk #6);
- the six-label model remains readable through compatibility views, and existing
  Sigma/ECS mappings keep working;
- new wire fields are staged receiver-first because native ingest is
  `deny_unknown_fields` (recon risk #3).

Stable `event_id`s make every retrieval result and audit reference immutable and
reproducible.

## 6. Phase map and status

| Phase | Deliverable | Doc | Status |
|-------|-------------|-----|--------|
| — | Air-gap kill-switch + egress chokepoint (invariant #1) | [model-routing](model-routing.md) | **done** |
| 1 | Tamper-evident audit ledger (`garmr-audit`) | [threat-model-audit-integrity](../threat-model-audit-integrity.md) | **done** |
| 2 | Event V2 + provenance | this doc §5 | **done** (core) |
| 3 | Prediction / decision / outcome split | this doc §4 | **done** |
| 4 | Model/prompt/detector/dataset registries | [learning-plane](learning-plane.md) | **done** |
| 5 | Temporal environment model | [environment-model](environment-model.md) | **done** |
| 6 | Hybrid agentic search (Query IR + fusion) | this doc §2 | **done** (retrieval) |
| 7 | Detector ensemble + drift + domain-neutral core | [environment-model](environment-model.md) | **done** (MLP) |
| 8 | Safe learning plane (`garmr-learning`) | [learning-plane](learning-plane.md) | **done** (MLP) |
| 9 | Agent mistake learning (episodic/semantic/procedural) | [learning-plane](learning-plane.md) | **done** (MLP) |
| 10 | Model router (local GPU + optional external) | [model-routing](model-routing.md) | **done** (MLP) |
| 11 | Air-gap bundles + supply chain | [supply-chain](../supply-chain.md) | **done** (MLP) |
| 12 | Collector reliability | [environment-model.md](environment-model.md) | done (authenticated collectors + env-source binding + ingest sequence) |
| 13 | HA, backup, restore | [backup-design.md](../backup-design.md) | done (single-host drill; online capture + multi-node failover deferred) |
| 14 | UI + explainability + security hardening | — | done (API: security headers/CSP/CSRF/auth-tier/posture + explainability read; egui: bearer auth + 5 read panes + "Why" pane) |

Each phase lands as compiling, tested, documented code (gate: `cargo fmt --all
--check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace --all-features`) before the next begins. The default
build stays self-contained and usable with no LLM (invariant #5).
