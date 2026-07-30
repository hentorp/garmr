# User & entity behaviour analytics (UEBA) — architecture (Phases 7-10 target)

Status: target design. Builds on the Phase-1 canonical [`AuditRecord`]
(`crates/garmr-core/src/app_audit.rs`, done), the bitemporal environment model
(`crates/garmr-core/src/environment.rs`, done), the detection ensemble +
`TrustedView` (`crates/garmr-analytics/src/envdetect.rs`, done), and per-actor RBA
(`crates/garmr-analytics/src/risk.rs`, done). See
[application-audit-analytics.md](application-audit-analytics.md) for the taxonomy
this implements.

## 1. Principle

UEBA answers "is this behaviour normal for **this** actor / role / peer group?"
against a **learned, trusted** baseline — and it does so without letting an
attacker teach the baseline (the whole of
[../threat-models/baseline-poisoning.md](../threat-models/baseline-poisoning.md)).
It never overrides the explicit policy engine:

> **Frequency never legitimizes a forbidden action.** UEBA can only *raise*
> attention. A behaviour that the policy engine forbids (see
> [access-policy-engine.md](access-policy-engine.md)) is a policy violation
> regardless of how baseline-normal it has become. Asset-criticality weighting in
> the ensemble is deliberately **monotonic-up** for the same reason
> (`role_criticality` is used only to raise, `domain.rs:223`; `finding.rs:110`).

## 2. Multidimensional baselines

A baseline is a distribution of observed values on one **dimension** for one
**subject**, with a maturity state and provenance. The dimensions (all projectable
from the `AuditRecord` today):

- **user × {application, database, schema, resource, query-fingerprint,
  operation, client, source-host, time-of-day, weekday, volume,
  distinct-records}** — the core per-actor profile. `statement_fingerprint`
  (`app_audit.rs:96`, authoritative from the Phase-3 analyzer) is the
  query-fingerprint axis; `rows_read`/`bytes_read` (`app_audit.rs:98-101`) drive
  volume; distinct `subject_id`/`record_id` drives distinct-records.
- **role × {resource, query-type}** — what a role legitimately touches
  (`actor.actor_role`, `app_audit.rs:312`).
- **peer-group × application** — the cohort an actor is compared against.
- **service-account patterns** — service accounts are near-deterministic; their
  baselines are tight and a deviation is high-signal (`actor.service_account` /
  `ActorType::ServiceAccount`, `app_audit.rs:135,317`).
- **application × expected-users** — which identities *should* appear in an app.

Each dimension is one baseline per subject; a finding cites which dimension(s)
deviated, so an alert is explainable ("actor X read 40× their median distinct
records on `persons`, off-hours, from a new client").

## 3. Candidate → trusted promotion (reuse, not reinvent)

A behavioural baseline is a fact about the environment, so it reuses the
environment model's fact / transition / gate machinery
(`environment.rs`) rather than a parallel learner:

- A newly-observed behaviour is a **Candidate** observation
  (`derive_candidates` / `derive_candidates_bound`, `environment.rs:1063,1094`),
  attributed to a **bounded, authenticated source id** (the collector id, not the
  self-declared `event.source` — `environment.rs:1094`).
- It becomes part of the **trusted** baseline only through the anti-poisoning gate:
  `may_auto_promote` requires both `hard_blocks` and `auto_blocks` empty
  (`environment.rs:990`); an analyst can clear the auto blocks but never the hard
  blocks (`may_analyst_promote`, `environment.rs:996`).
- Detectors read the baseline through `TrustedView` (`envdetect.rs:23`), which
  filters to `FactState::Trusted` — a Candidate / Suspicious / forged baseline can
  never be read as "normal".

The hard blocks (`environment.rs:943`) — an open/malicious case touching the
entity, or a compromised entity — mean **misuse under investigation can never
teach the baseline**. The auto blocks (`environment.rs:956`) add quarantine,
minimum observations (`min_observations`, default 5), minimum **distinct** sources
(`min_distinct_sources`, default 2), the per-source influence cap
(`max_single_source_share`, default 0.8, `environment.rs:919`), high-impact
analyst-approval floor (`is_high_impact`, `environment.rs:872`), and contested-value
holds (`ConflictNeedsHuman`).

## 4. Maturity states

A baseline dimension carries a maturity state so a detector knows whether it may
speak. This layers on the fact promotion state
(`Unknown → Candidate → Trusted → Suspicious/KnownMalicious → Retired`) with a
behavioural read:

| State | Meaning | Detector behaviour |
|-------|---------|--------------------|
| **Empty** | no observations yet | abstain |
| **Learning** | observations accruing, quarantine not met | abstain |
| **Candidate** | thresholds met, not yet promoted | abstain (or shadow only) |
| **Stable** | trusted, low variance | full deviation scoring |
| **Drifting** | change-point detected; may be concept drift | flag drift, do not score as malice |
| **Degraded** | parser health / volume collapse | abstain + surface health |
| **Suspicious** | baseline touched by an adverse case | excluded from "normal" |

The **abstain-until-baseline** rule is already the shipped discipline: `env_edge`
new-edge/new-identity axes each abstain until they have their OWN trusted baseline
(`envdetect.rs:132-187`; `identity_baseline_size`, `envdetect.rs:87`), precisely so
an empty model does not flag every actor as novel. This is taxonomy row 3 (novel
behaviour) kept distinct from row 2 (anomaly): **no baseline → novel, not
anomalous → abstain**, never a flood.

## 5. Peer-group comparison

An actor is compared against a cohort (role, team, application-user set) so an
individual who is anomalous *relative to peers* is flagged even when their absolute
volume looks unremarkable. Peer grouping is derived from trusted facts
(`actor.actor_role`, `actor.actor_groups`, `app_audit.rs:312-315`; the
`application × expected-users` baseline), never from attacker-influenceable event
content. A peer-group deviation is a `SecurityFinding` with the cohort recorded in
`env_basis` (`finding.rs:100`) so the comparison is auditable.

## 6. Emission & accumulation

- A UEBA deviation is a `SecurityFinding` (`finding.rs:117`) that lowers to a
  `Detection` (`finding.rs:156`) and flows through the unchanged case pipeline —
  UEBA never opens a second path to a case.
- Sub-threshold deviations (taxonomy row 6) accumulate through **per-actor RBA**:
  `score_staff` groups by `db_user` and opens `garmr-risk-user-<actor>`
  (`risk.rs:351,372`) when the decayed sum crosses `risk_threshold`. Weak signals
  that never individually page still surface a low-and-slow actor (the
  low-and-slow enumeration case in
  [../threat-models/insider-risk.md](../threat-models/insider-risk.md)).
- Learning (retuning score bands / criticality) is **offline, trusted-labels-only,
  champion/challenger, human-promoted** (`crates/garmr-learning`; see
  [learning-plane.md](learning-plane.md)); a UEBA challenger is refused if it
  raises dangerous false negatives.

## 7. What UEBA must not do

- Never treat a Candidate/Suspicious baseline as normal (the `TrustedView` gate).
- Never learn from behaviour under an open/malicious case (the hard blocks).
- Never lower a policy violation to "normal" because it is frequent (§1).
- Never emit a deviation without an established baseline (abstain, §4) — a novelty
  is not an anomaly.

[`AuditRecord`]: ../../crates/garmr-core/src/app_audit.rs
