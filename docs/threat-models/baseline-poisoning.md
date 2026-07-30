# Threat model — baseline poisoning

Scope: an adversary who slowly trains garmr's notion of "normal" to include their
own misuse, so that later abuse reads as baseline-normal and never alerts. This is
the UEBA-specific facet of the platform-wide learning threat model
([../threat-model-learning-and-poisoning.md](../threat-model-learning-and-poisoning.md));
it focuses on the **behavioural baselines** and the **environment facts** that
UEBA compares against.

Design: [../architecture/user-behavior-analytics.md](../architecture/user-behavior-analytics.md),
[../architecture/environment-model.md](../architecture/environment-model.md),
[../architecture/learning-plane.md](../architecture/learning-plane.md).

## Assets

- The **trusted behavioural baseline** (per user / role / peer-group / service
  account).
- The **trusted environment facts** (known peers, known identities, asset roles).
- The **supervised label set** used to retune detectors.

## Adversaries and capabilities

| Adversary | Capability |
|-----------|-----------|
| Slow-ramp insider | can perform real actions and repeat them until "normal" |
| Log injector | can inject events to inflate an observation count |
| Novelty launderer | fires a novel behaviour once to make it "known" |
| Compromised collector | can attribute observations to a source it controls |
| Label poisoner | can enter feedback / decisions (a malicious analyst) |

## Attack → defense

### 1. Slow-ramp normalization ("do it enough and it's normal")

- **Defense: candidate-vs-trusted split + the promotion gate.** A newly-observed
  behaviour is only a **Candidate** (`derive_candidates`, `environment.rs:1063`);
  it becomes part of the *trusted* baseline only through `may_auto_promote`, which
  requires BOTH `hard_blocks` and `auto_blocks` empty (`environment.rs:990`). The
  auto blocks (`environment.rs:956`) impose:
  - **quarantine** — a Candidate must age past `quarantine` (default 24h) before it
    can auto-promote (`environment.rs:966`);
  - **`min_observations`** (default 5) and **`min_distinct_sources`** (default 2,
    `environment.rs:970-975`) — a single burst from one source cannot promote;
  - the **influence cap** — no single source's trust-weighted share of the evidence
    may exceed `max_single_source_share` (default 0.8, `influence_cap_exceeded`,
    `environment.rs:919`), so one source/host cannot dominate a fact.

  A ramp is additionally a change-point in the baseline (the `Drifting` maturity
  state, [../architecture/user-behavior-analytics.md](../architecture/user-behavior-analytics.md) §4),
  scored as drift, not silently absorbed.

### 2. Poison while under investigation

- **Defense: inviolable hard blocks.** `hard_blocks` (`environment.rs:943`) refuse
  promotion when an **open or malicious case touches the entity** or the **entity
  is compromised** — and these are cleared by *no one*, not even an analyst
  (`may_analyst_promote` still enforces the hard blocks, `environment.rs:996`). So
  misuse currently under investigation can never teach the trusted baseline
  (test, `environment.rs:1618`).

### 3. Forge a "known" fact to suppress a future finding

- **Defense: the `TrustedView` single poison gate.** Every environment read for
  detection goes through `TrustedView`, which filters to `FactState::Trusted`
  (`crates/garmr-analytics/src/envdetect.rs:23,40`). A Candidate / Suspicious /
  KnownMalicious / forged (empty-audit) fact can NEVER be read as "normal" — the
  poison-safety of the whole detection plane reduces to this one filter plus the
  promotion gate (`envdetect.rs:6-10`). A concrete test: an attacker's forged
  Candidate "known edge" injected to hide a real new peer neither fires nor
  suppresses, because the Candidate is filtered out of the Trusted view
  (`envdetect.rs:372`). Role/criticality reads are Trusted-only too
  (`role_of`/`criticality_of`, `envdetect.rs:99,107`) — never the
  attacker-influenceable heuristic (`domain.rs:170`).

### 4. Novelty laundering ("fire it once so it's known")

- **Defense.** Promotion is gated on **case outcome and the promotion gate, not
  first sighting**; novelty abstains until a baseline exists rather than treating a
  first sighting as either normal or malicious (the abstain-until-baseline rule,
  `envdetect.rs:132-187`; `identity_baseline_size`, `envdetect.rs:87`). Quarantine
  + expiry + influence caps mean one sighting cannot become trusted.

### 5. Label poisoning (teach the retuner wrong labels)

- **Defense: trusted-labels-only datasets.** The learning plane keeps a training
  row ONLY when `resolve_trusted` yields an `IncidentOutcome` or `AnalystDecision`
  (`crates/garmr-learning/src/dataset.rs:4-10`); a prediction / shadow / unresolved
  label is dropped as an `UntrustedLabel` exclusion. **No training from unresolved
  self-predictions** — RBA and learning consume trusted outcome first, discounted
  prediction otherwise, and never give positive weight to an unresolved
  self-prediction (`learning-plane.md`; `risk.rs`). The Phase-5 poison exclusion is
  applied **only to benign rows** so it can never strip the positive (adverse)
  class the dangerous-FN guard needs (`dataset.rs:11-19`). Promotion of a retuned
  detector is offline, human-approved, and refused if it raises dangerous false
  negatives (`learning-plane.md`).

### 6. Attribute observations to fake distinct sources (defeat the distinct-source cap)

- **Defense: authenticated collector binding (Phase 12).** The distinct-source
  count keys on the trusted collector id, not the self-declared `event.source`
  (`derive_candidates_bound`, `environment.rs:1094`), so one compromised collector
  is one source. See
  [audit-log-poisoning](audit-log-poisoning.md) §4.

## The overriding invariant

> **Forbidden-by-policy is never learnable as normal.** The access-policy engine
> ([../architecture/access-policy-engine.md](../architecture/access-policy-engine.md))
> is evaluated separately from and authoritative over the baseline: a policy `Deny`
> is a violation no matter how baseline-normal the action has become. No promotion,
> influence, or frequency can convert an explicit policy violation into "normal"
> (the invariant from
> [../architecture/application-audit-analytics.md](../architecture/application-audit-analytics.md) §2).

## Residual risks

- A patient adversary who also controls the analyst *and* stays under every
  influence cap can bias slowly; mitigated by holdouts, drift monitoring, and audit
  of every promotion — bounded, not eliminated
  ([../threat-model-learning-and-poisoning.md](../threat-model-learning-and-poisoning.md)).
- Offline inventory import trusts the inventory source; its trust level is recorded
  and capped like any other source, and inventory facts get only the shorter
  `asserted_quarantine` (`environment.rs:794`).
- `environment.learn` in a hostile ingest environment requires collector binding
  first — serve warns loudly when `learn && detect` are both on without it
  ([../architecture/environment-model.md](../architecture/environment-model.md)).
