# Application-audit analytics & UEBA — architecture

Status: living document (branch `feature/application-audit-ueba`). Grounded in the
current implementation; updated as each phase lands. Phase 1 (the canonical
[`AuditRecord`] model) is committed (`b937e2f`); everything downstream is target
design and is labelled as such.

This is the **master doc** for the audit-first evolution. It builds directly on
the completed adaptive-audit SOC initiative — see
[adaptive-audit-soc.md](adaptive-audit-soc.md) and
[ADR-0001](../adr/0001-adaptive-audit-soc-initiative.md) for the planes (ingest,
data, detection, agentic, decision, change, learning), the seven non-negotiable
invariants, and the tamper-evident audit ledger. The register access-audit
flagship it generalizes is [access-audit.md](../access-audit.md).

## 1. Product direction: audit-first security analytics + UEBA

garmr already ingests logs, detects, opens cases, and triages. The next step is to
make **application-audit records** — not just host/network telemetry — a
first-class object, and to reason about **user and entity behaviour** (UEBA) over
them. The target scope is deliberately generic: any application that emits an
audit trail, including

- **PostgreSQL / pgAudit** (the anchor adapter, Phase 2),
- line-of-business and case-management applications,
- data-science / notebook environments (Jupyter, warehouse query engines),
- population/person and asset **registers** (the register flagship),
- document- and record-management systems,
- **APIs** (access logs with actor/resource/outcome),
- **IAM** (grants, role switches, privilege changes),
- **OT/ICS** operator actions.

The unifying model is: *who* (actor / effective identity) did *what*
(action / statement) to *which resource* (object / subject / record), *under which
justification*, and *how sensitive* it was. That is exactly the shape of the
canonical [`AuditRecord`] (`crates/garmr-core/src/app_audit.rs:487`).

## 2. The classification taxonomy the platform must distinguish

A trustworthy audit analytics platform must keep apart concepts a naïve system
collapses into "alert". These are **distinct types, never silently coerced** (the
confusable-concepts discipline, extended from
[threat-model-learning-and-poisoning.md](../threat-model-learning-and-poisoning.md)):

| # | Concept | Meaning | Who decides |
|---|---------|---------|-------------|
| 1 | **Explicit policy violation** | A forbidden action occurred | the policy engine (deterministic) |
| 2 | **Behavioral anomaly** | Deviates from an established, trusted baseline | UEBA detectors |
| 3 | **Novel behavior** | Never-before-seen, no baseline yet to deviate from | UEBA (abstains until baseline exists) |
| 4 | **Expected operational change** | A maintenance window / change record explains it | the environment model |
| 5 | **Concept drift** | The world legitimately changed; baseline is stale | drift signal (no auto-retune) |
| 6 | **Weak risk indicator** | Individually sub-threshold; accrues via RBA | the risk loop |
| 7 | **Confirmed security finding** | The detection plane's adjudicated output | `SecurityFinding` → `Detection` |
| 8 | **Confirmed incident** | Post-incident ground truth | `IncidentOutcome` (human) |

Two invariants govern the taxonomy:

> **A forbidden action stays forbidden no matter how frequent.** Frequency,
> baselines, and "everyone does it" can only ever *raise* attention, never
> legitimize an explicit policy violation. The policy engine (Phase 5) sits
> **beside**, not downstream of, the anomaly plane; an explicit deny overrides any
> learned "this is normal now" (see [access-policy-engine.md](access-policy-engine.md)).

> **Novelty ≠ anomaly ≠ drift ≠ finding.** A first sighting is not a deviation; a
> deviation is not proof of malice; the world changing is not an attack. Each is a
> separate signal with its own evidence and its own promotion rule.

## 3. How this builds on the existing architecture

Nothing here is a parallel pipeline. Each piece reuses a load-bearing seam that
already exists and is tested:

- **Thin `Event` + `fields` map.** garmr stores ONE event type — a six-label log
  line plus a `fields: BTreeMap<String,String>` of ingest-normalized keys
  (`crates/garmr-store/src/schema.rs:33`). Audit records are not a second stored
  type.
- **The typed `AuditRecord` lens (Phase 1, done).** `crates/garmr-core/src/app_audit.rs`
  is a *lens* over an `Event`'s already-canonical fields, not a new event. It reads
  the canonical keys directly (`AuditRecord::from_event`, `app_audit.rs:554`) and
  writes them back with `to_fields` (`app_audit.rs:681`), so a synthesized record
  round-trips and stays readable by `AccessProjection` (`domain.rs:94`), the
  correlation SQL, and the entity pivots. The storage-canonical keys live in
  `app_audit.rs::keys` (`app_audit.rs:41`).
- **The access-audit vocabulary.** The register capability's canonical keys
  (`db_user`, `target_person`, `object_table`, `action`, `statement`,
  `ticket_ref`, `client_addr`, `watched`, `is_self`) are preserved verbatim as the
  legacy storage keys (`app_audit.rs:42-60`); the audit-first model only *adds*
  richer keys (identity/context/action/justification/classification groups).
- **SecurityFinding → Detection → case pipeline.** UEBA detectors emit a
  `SecurityFinding` (`crates/garmr-core/src/finding.rs:117`) that lowers to a
  `Detection` via `into_detection` (`finding.rs:156`), flowing through the SAME
  case → triage → propose → human-approve path as every other signal. Detectors
  produce findings; they do not act.
- **RBA (weak-signal accumulation).** The per-actor risk loop already scores each
  `db_user` (`crates/garmr-analytics/src/risk.rs:351`, `score_staff`), opening a
  `garmr-risk-user-<actor>` case when decayed low-and-slow misuse crosses a
  threshold (`risk.rs:372`). This is the substrate for taxonomy row 6.
- **The bitemporal environment model.** Trusted facts (valid-time ×
  transaction-time, with the anti-poisoning promotion gate) provide the "normal"
  UEBA compares against (`crates/garmr-core/src/environment.rs`; see
  [environment-model.md](environment-model.md)).
- **The champion/challenger learning plane.** Offline, trusted-labels-only,
  content-addressed datasets and human-gated promotion
  (`crates/garmr-learning`; see [learning-plane.md](learning-plane.md)) is how
  UEBA models improve without online poisoning.
- **The egress chokepoint.** One `EgressPolicy` gate governs every outbound class;
  data-classification-aware model routing keeps restricted audit data off external
  models (see [model-routing.md](model-routing.md) and
  [../threat-models/sensitive-search-and-export.md](../threat-models/sensitive-search-and-export.md)).

## 4. Phase map (audit-first UEBA evolution)

This numbering is the branch's own sequence, distinct from the completed 14-phase
adaptive-audit initiative it sits on. **Only Phase 1 is implemented.** Phases 2, 3,
5, and 8 are already referenced by number in the Phase-1 code
(`app_audit.rs:17,216,439,888`); the remaining phase numbers are a proposed
sequence and may be reordered.

| Phase | Deliverable | Doc | Status |
|-------|-------------|-----|--------|
| 1 | Canonical domain-neutral `AuditRecord` lens | this doc §3 | **done** (`b937e2f`) |
| 2 | PostgreSQL / pgAudit ingestion adapter | [postgresql-audit](postgresql-audit.md) | target |
| 3 | SQL / statement analyzer (authoritative `statement_type`, fingerprints) | [postgresql-audit](postgresql-audit.md) | target |
| 4 | Audit-record investigation pivots (Users / Applications / Resources) | [webui-information-architecture](webui-information-architecture.md) | target |
| 5 | Explicit access-policy engine (subjects/resources/conditions/effects) | [access-policy-engine](access-policy-engine.md) | target |
| 6 | Hybrid investigation search (unify `ask` onto the typed Query IR) | [hybrid-investigation-search](hybrid-investigation-search.md) | target |
| 7 | Multidimensional UEBA baselines + maturity states | [user-behavior-analytics](user-behavior-analytics.md) | target |
| 8 | UEBA behavioral detectors (missing-justification, bulk, off-hours, self, peer) | [user-behavior-analytics](user-behavior-analytics.md) | target |
| 9 | Peer-group analytics + service-account profiling | [user-behavior-analytics](user-behavior-analytics.md) | target |
| 10 | Weak-signal RBA accumulation for audit actors | [user-behavior-analytics](user-behavior-analytics.md) | target |
| 11 | Concept-drift vs expected-change discrimination for audit baselines | [environment-model](environment-model.md) | target |
| 12 | Policy simulation / backtest over history | [access-policy-engine](access-policy-engine.md) | target |
| 13 | Data-classification-aware routing for audit/PII (egress ceiling) | [model-routing](model-routing.md) | target |
| 14 | Export / COPY / bulk-read controls + search authorization | [sensitive-search-and-export](../threat-models/sensitive-search-and-export.md) | target |
| 15 | Audit-integrity for application-audit collectors (source binding) | [audit-log-poisoning](../threat-models/audit-log-poisoning.md) | target |
| 16 | WebUI information architecture (Users/Applications/Resources/Policies/Learning) | [webui-information-architecture](webui-information-architecture.md) | target |
| 17 | Additional collectors (business apps, case-mgmt, Jupyter, APIs, IAM, OT) | [postgresql-audit](postgresql-audit.md) | target |
| 18 | Learning-plane extension to UEBA challengers | [learning-plane](learning-plane.md) | target |
| 19 | Hardening, air-gap audit bundles, docs | [supply-chain](../supply-chain.md) | target |

Each phase lands as compiling, tested, documented code (gate: `cargo fmt --all
--check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace --all-features`) before the next begins, and the default
build stays self-contained and usable with no LLM (invariant #5).

## 5. Threat models

The audit-first surface adds three adversary classes on top of the existing
learning/poisoning and audit-integrity models:

- **[audit-log-poisoning](../threat-models/audit-log-poisoning.md)** — forging,
  injecting, or tampering with audit events to hide activity or frame others.
- **[baseline-poisoning](../threat-models/baseline-poisoning.md)** — slowly
  training "normal" to include misuse.
- **[insider-risk](../threat-models/insider-risk.md)** and
  **[sensitive-search-and-export](../threat-models/sensitive-search-and-export.md)**
  — the authorized user who abuses access, and the auditor who becomes a
  surveillance layer.

[`AuditRecord`]: ../../crates/garmr-core/src/app_audit.rs
