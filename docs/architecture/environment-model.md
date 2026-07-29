# Temporal environment model — architecture

Status: initial (expanded in Phases 5 and 7). Covers the persistent, bitemporal
knowledge model of the monitored environment and the domain-neutral core it
replaces the current heuristics with.

## Purpose

Give detection, triage, and scoring a **learned, trustworthy model of "normal"**
for this environment — without letting an attacker (or an open case) teach it.
Replaces the current stateless, unversioned assumptions: two divergent hardcoded
host classifiers (`crates/garmr-graph/src/build.rs:259`,
`crates/garmr-map/src/main.rs:92`) and the unguarded baselines.

## Entities and relations

Entities: Asset, Host, Device, NetworkInterface, IP, MAC, Identity, ServiceAccount,
Group, Role, Process, Binary, Software, Service, Application, Database, Container,
Cluster, Certificate, NetworkZone, DataSource, Rule, Case, Incident, ChangeRecord,
Owner.

Relations (typed): runs_on, connects_to, authenticates_to, administers, member_of,
belongs_to_zone, depends_on, uses_certificate, owned_by, observed_by,
triggered_case, changed_by, communicates_with.

Each fact/relation carries: stable id, first_seen, last_seen, observation_count,
source refs, confidence, source trust, observed-vs-asserted, `valid_from`/
`valid_to`, `learned_from`, and a **promotion state**:

```
Unknown → Candidate → Trusted → (Suspicious | KnownMalicious) → Retired
```

## Anti-poisoning discipline (the core rule)

**An open security case or a known-compromised asset must never automatically
teach the trusted normal baseline.** Enforced by:

- Candidate **quarantine** and **delayed promotion** to Trusted.
- Maintenance-window and change-record awareness (expected change ≠ anomaly).
- Explicit analyst approval for promotion of high-impact facts.
- Automatic expiry; conflict handling; **source-trust weighting** and **per-source
  influence caps** (no single source/host/window dominates).
- **Bitemporal history** (valid-time × transaction-time): current-state
  materialization for queries, plus historical-state ("what did we believe at time
  T?") queries.
- Import from offline inventory files (air-gap friendly).

### Authenticated source binding (Phase 12)

The per-source influence cap is only as trustworthy as the *source identity* it
counts. Before Phase 12 that identity was the shipper-**self-declared**
`event.source` string: one collector could declare arbitrarily many distinct
sources and so evade the distinct-source cap — the residual poisoning vector
flagged when Phase 5 shipped.

Phase 12 closes it. A collector authenticates the native ingest connection with a
per-collector bearer token (`GARMR_COLLECTORS`, secret from env — never config or
logs, mirroring `GARMR_USERS`). Each accepted event is stamped with the **trusted
collector id** and `source_trust = "authenticated"`. When collectors are
configured, the learner keys observations on that collector id
(`derive_candidates_bound`), so:

- one compromised collector can forge only its own single source, never N; and
- events that arrive **unauthenticated** (NULL collector id) are **dropped** by
  the learner — not folded onto a shared sentinel source, which would itself be a
  poisoning channel.

**Default-off:** with no collectors configured the endpoint stays unauthenticated
and the learner uses the self-declared source exactly as before — byte-identical.

**KNOWN LIMITATION / rollout precondition.** Binding governs *future* learning
only; it does not retroactively re-attribute facts already learned. If
`environment.learn` ran against unauthenticated ingest **before** collectors were
configured, self-declared-source Candidate/Trusted facts may already exist.
Therefore: **configure `GARMR_COLLECTORS` before enabling `environment.learn`** on
a deployment that will use authenticated ingest. To convert an existing
deployment, disable `environment.learn`, configure collectors, demote or expire
the pre-binding facts, then re-enable learning so all fresh facts are
collector-bound. Detection (`env_detect_loop`) reads the resulting Trusted view
and is unaffected by the switch beyond that.

In bind mode the learner keys observations on the **collector id**, so also
**re-key `[environment].source_trust` from source names to collector ids** — an
entry that matches no active collector id will not apply, and that collector
falls back to `default_source_trust` (with the `default_source_trust = 0.0`
allowlist-hardening pattern, that halts all promotion). `garmr serve` logs a
startup warning naming any `source_trust` key that matches no configured
collector id.

## Domain-neutral core (Phase 7)

The generic core speaks: **Actor, Identity, DataSubject, Resource, Asset, Service,
Session, AccessOperation, Finding.** Register-specific concepts move to an
**optional domain profile**. The seam already exists — register vocabulary lives
in the free-form `fields` map keys and two graph kinds, not in the six neutral
event labels:

| Register concept | file:line | Generic replacement |
|------------------|-----------|---------------------|
| `db_user` | `crates/garmr-ingest/src/fields.rs:233` | Actor.id |
| `target_person` | `crates/garmr-ingest/src/fields.rs:241` | DataSubject.id |
| `object_table` | `crates/garmr-ingest/src/fields.rs:254` | Resource |
| `ticket_ref` | `crates/garmr-ingest/src/fields.rs:263` | Justification.ref |
| `KIND_STAFF` / `KIND_PERSON` | `crates/garmr-graph/src/model.rs:15` | Actor / DataSubject kinds |
| `staff_page` / `person_page` | `crates/garmr-agent/src/entity.rs:307,377` | actor/subject access pages |
| `score_staff` (synth host `registerlookup`) | `crates/garmr-analytics/src/risk.rs:216` | per-Actor risk |
| 5× `correlations/reg-*.toml` | — | domain-profile ruleset |

The two hardcoded device-type classifiers fold into **one config/inventory-driven
`Asset.role` classifier**; heuristics remain only as a **low-confidence fallback**
when inventory/evidence is absent. The implicit `log_type` vocabulary
(`system|firewall|app|security_alert|cluster|audit` + synthetic
`anomaly|risk|baseline`) is formalized.

## Relationship to detection (Phase 7)

The environment model feeds new-edge/graph-rarity detectors, peer-group deviation,
identity/service-account behavior, and asset-criticality weighting in the ensemble
score — all reading **Trusted** facts, never Candidate/Suspicious, for "normal".

### Phase 7 — done (MLP)

Shipped: the domain-neutral core types (`Actor`/`DataSubject`/`Resource`/…,
`AccessProjection`, `DomainProfileKind`), the unified `resolve_asset_role`
(Trusted role fact wins; the shared `heuristic_role` is the low-confidence
fallback — collapsing the three divergent host classifiers into one),
`SecurityFinding` + the pure ensemble scorer (`assess`, monotonic-up
asset-criticality so a poisoned criticality can only over-alert, never hide), the
`TrustedView` (the single Trusted-only gate) + the `env_edge` detector (new-peer /
new-identity vs the Trusted baseline — each rarity axis abstains until it has its
OWN baseline: new-edge needs the host's Trusted host-fact baseline, new-identity a
Trusted identity baseline of known accounts, so neither floods on an empty model),
the additive
`findings` store + `GET /api/findings` + `garmr findings`, and a detection-only
drift signal (reuses `verify_environment`; no auto-retune). Default OFF
(`environment.detect.enabled`).

**Trusted-only, by one filter.** Every detector read goes through `TrustedView`,
which filters to `FactState::Trusted`; `role_of`/`criticality_of` read Trusted
facts ONLY, never the (attacker-influenceable) heuristic. So a Candidate /
Suspicious / forged fact can never drive or suppress a detection.

**Phase-12 precondition.** The `env_edge` new-peer check is *suppressive* (a
Trusted "known peer" hides that peer). With `environment.learn = false` (default)
the Trusted baseline is human-promoted / imported and safe. Enabling
`environment.learn` in a hostile ingest environment requires the authenticated
env-source binding (Phase 12) first, because `event.source` is shipper-declared —
serve warns loudly when `learn && detect` are both on.

Deferred: full multi-family fusion (folding the five existing producers),
peer-group deviation, a service-account behavioral profiler, calibrated/probabilistic
scoring (needs labelled outcomes — Phase 8/9), drift-driven auto-retuning (Phase 8),
the physical relocation of `reg-*.toml` → `profiles/register/` and generalizing
`KIND_STAFF`/`KIND_PERSON` (the data seam + neutral types already establish the
boundary), and the garmr-map classifier code-fold (a separate WASM workspace).
