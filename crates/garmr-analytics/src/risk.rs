// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Risk-based alerting (RBA, M4) — "many weak signals on one host" as ONE case.
//!
//! Single detections are binary and independently deduped, so an attacker who
//! stays under every rule's escalation bar (a few mediums here, an odd
//! new-template there) never trips a page. RBA fixes that: it accumulates a
//! decaying risk score PER HOST from the cases already in the store and, when a
//! host crosses a threshold, emits ONE synthetic [`Detection`] — the same case
//! path as Sigma, correlation, hunts and anomaly. garmr is the SIEM, so there
//! is no push-back to an upstream log store.
//!
//! garmr scores from CASES, not raw detections (the warehouse prototype had no
//! case layer and scored the lake). Each case's disposition is resolved through
//! the Phase-3 trust precedence (`garmr_core::resolve_trusted`): a final incident
//! **outcome** or human **analyst decision** counts at full weight; an unreviewed
//! agent **prediction** (or, on a store with no Phase-3 records, the shadow
//! verdict) is DISCOUNTED by `prediction_discount`; an in-flight case gets `0.5`
//! partial credit; and an unresolved self-generated (`garmr-risk-*`) case counts
//! zero. So a benign-adjudicated case contributes nothing, a trusted-malicious
//! one contributes double, and unreviewed model output can no longer dominate the
//! score on its own. Each case's weight is `level_weight × resolved_multiplier ×
//! time_decay`, summed over a host's cases in the last [`WINDOW_HOURS`].
//!
//! Feedback guard: risk cases (rule id `garmr-risk-*`) are themselves excluded
//! from scoring, so a raised risk case can't inflate the score that raised it.
//!
//! KNOWN LIMITATIONS (design boundaries, not bugs — RBA is one signal among
//! many, tunable and extendable):
//! - **Per-host only.** Risk accrues on the event's `host`. A low-and-slow
//!   actor who spreads weak signals across many hosts (or one source IP hitting
//!   many hosts) accumulates on no single object and slips RBA. Per-IP / per-
//!   user risk objects are the natural next slice; host is the always-present
//!   entity and the right first cut.
//! - **Unreviewed judgement is discounted, not authoritative.** An unreviewed
//!   agent prediction/shadow verdict counts at `prediction_discount` (default
//!   0.5), so a single mis-triage moves the score by half, not all — and a human
//!   analyst decision or incident outcome overrides it at full weight. A benign
//!   *trusted* judgement still zeroes a case (don't page on adjudicated-benign
//!   noise); a benign unreviewed one likewise contributes zero.
//! - **Untriaged = partial credit (0.5×).** A fast burst can raise a host
//!   before the agent finishes (a feature — catch fast movers), at the cost of
//!   a transient risk case that self-corrects on the next scoring pass once the
//!   cases triage benign.
//! - **Risk-case level is a snapshot.** The high-vs-critical level is set when
//!   the risk case opens; while it stays open, a host climbing from ≥threshold
//!   to ≥2×threshold bumps the case but does not re-escalate the level until
//!   the case closes and re-alerts. The agent's own verdict severity drives
//!   escalation in the meantime.
//! - **Cases are not pruned.** Closed risk cases accumulate like all cases
//!   (garmr has no case retention yet); score_hosts filters them cheaply, but
//!   they persist in the store.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use garmr_core::{
    resolve_trusted, AgentPrediction, AnalystDecision, Case, CaseDecisionView, Detection,
    Disposition, Event, IncidentOutcome, TrustSource, TrustedJudgement,
};

/// The window over which case risk accumulates. Fixed (not a knob): the decay
/// half-life is the real tuning surface. Set wide enough that the hard cutoff
/// is a smooth tail, not a cliff — at the default 12h half-life a case at 72h
/// has already decayed to ~1.5% of its weight, so dropping it changes little,
/// whereas a 24h cutoff would abruptly discard a case still worth ~25%.
pub const WINDOW_HOURS: f64 = 72.0;

/// The RBA knobs (from `[detect]` config).
#[derive(Debug, Clone, Copy)]
pub struct RiskParams {
    /// Score at which a host opens a risk case.
    pub threshold: f64,
    /// Hours for a case's contribution to halve.
    pub halflife_hours: f64,
    /// Re-alert suppression window for a host's risk case (seconds).
    pub realert_secs: u64,
    /// How much an unreviewed agent prediction / shadow verdict counts relative
    /// to a trusted human/incident outcome (which counts at 1.0). Default 0.5.
    pub prediction_discount: f64,
}

/// One case's contribution to a host's score.
#[derive(Debug, Clone)]
pub struct Contributor {
    pub case_id: String,
    pub rule_id: String,
    pub level: String,
    /// Post-decay, post-disposition contribution to the host score.
    pub contribution: f64,
    /// Where the disposition that weighted this case came from (trusted outcome,
    /// analyst decision, discounted prediction, or unresolved) — explainability.
    pub trust: TrustSource,
    /// ATT&CK tags carried by the case that contributed. Kept so the raised risk
    /// incident can report the UNION of what actually fed it rather than a
    /// hardcoded technique: RBA is an aggregation, so its coverage claim must be
    /// whatever its inputs claimed, or the matrix stops describing reality.
    pub attack: Vec<String>,
}

/// A risk subject and its accumulated risk. The subject is a host by default;
/// with `kind = "staff"` it is a register caseworker (a `db_user`), so the same
/// decayed-sum machinery does per-person insider-misuse RBA as well as per-host.
#[derive(Debug, Clone)]
pub struct RiskObject {
    /// Which entity `host` names: `"host"` or `"staff"` (a db_user).
    pub kind: String,
    /// The subject: a host name, or (for `kind = "staff"`) the acting db_user.
    pub host: String,
    pub score: f64,
    /// Contributing cases, highest contribution first.
    pub contributors: Vec<Contributor>,
}

/// Rule-declared severity → base weight. The single source of truth now lives in
/// garmr-core (shared with the Phase 7 ensemble score so RBA and findings use one
/// scale); this delegates so every call site stays unchanged.
fn level_weight(level: &str) -> f64 {
    garmr_core::level_weight(level)
}

/// Disposition → base multiplier. Benign zeroes a case out (RBA's whole point is
/// not to accumulate adjudicated-benign noise).
fn base_mult(d: Disposition) -> f64 {
    match d {
        Disposition::Malicious => 2.0,
        Disposition::Suspicious => 1.0,
        Disposition::NeedsHuman => 1.0,
        Disposition::Benign => 0.0,
    }
}

/// Resolve a case's [`TrustedJudgement`] into a risk multiplier (Phase 3):
/// - a trusted incident **outcome** or **analyst decision** counts at full
///   `base_mult`;
/// - an unreviewed **prediction** (or the shadow verdict) is discounted by
///   `prediction_discount` (benign still contributes zero);
/// - an in-flight (**unresolved**) case gets `0.5` partial credit so a fast
///   burst can raise a host before the agent finishes;
/// - an **unresolved self-generated** (`garmr-risk-*`) case contributes zero —
///   the system's own unreviewed output must never feed the score that raised it.
fn resolved_mult(j: &TrustedJudgement, params: &RiskParams) -> f64 {
    // A misconfigured non-finite discount must never poison a score to NaN/inf
    // (the `mult <= 0.0` / `contribution <= 0.0` guards below are both false for
    // NaN, so it would otherwise be summed in). Mirror the `decay` is_finite
    // guard and bound the discount to [0, 1].
    let discount = if params.prediction_discount.is_finite() {
        params.prediction_discount.clamp(0.0, 1.0)
    } else {
        0.5
    };
    match j.source {
        TrustSource::Outcome | TrustSource::AnalystDecision => {
            j.disposition.map(base_mult).unwrap_or(0.0)
        }
        TrustSource::DiscountedPrediction => j.disposition.map(base_mult).unwrap_or(0.0) * discount,
        TrustSource::Unresolved => 0.5,
        TrustSource::UnresolvedSelfGenerated => 0.0,
    }
}

/// A per-case index of resolved judgements, computed once per scoring pass.
///
/// `build` resolves EVERY case with the strict trust precedence (outcome >
/// decision > discounted prediction > shadow verdict > unresolved). The shadow
/// verdict is passed through, so a store with no Phase-3 records reproduces the
/// legacy disposition weighting (× `prediction_discount` on non-benign) rather
/// than collapsing every case to the unresolved `0.5`.
#[derive(Debug, Clone, Default)]
pub struct OutcomeIndex {
    by_case: BTreeMap<String, TrustedJudgement>,
}

impl OutcomeIndex {
    pub fn build(
        cases: &[Case],
        outcomes: &[IncidentOutcome],
        decisions: &[AnalystDecision],
        predictions: &[AgentPrediction],
    ) -> Self {
        // Pre-group each record slice by `case_id` ONCE (O(records)), so every
        // case is resolved with O(1) map lookups instead of three full linear
        // scans. This was O(cases × records) — the risk board's quadratic (a
        // `.iter().filter(case_id == c.id)` per record kind, per case). Zero-cpu:
        // the same slices are no longer re-scanned once per case. Each per-case
        // Vec preserves slice order (records pushed in iteration order), so every
        // `CaseDecisionView` is byte-identical to the old per-case `filter`, and
        // `resolve_trusted` therefore returns the identical judgement.
        use std::collections::HashMap;
        let mut preds: HashMap<&str, Vec<AgentPrediction>> = HashMap::new();
        for p in predictions {
            preds.entry(p.case_id.as_str()).or_default().push(p.clone());
        }
        let mut decs: HashMap<&str, Vec<AnalystDecision>> = HashMap::new();
        for d in decisions {
            decs.entry(d.case_id.as_str()).or_default().push(d.clone());
        }
        let mut outs: HashMap<&str, Vec<IncidentOutcome>> = HashMap::new();
        for o in outcomes {
            if let Some(cid) = o.case_id.as_deref() {
                outs.entry(cid).or_default().push(o.clone());
            }
        }

        let mut by_case = BTreeMap::new();
        for c in cases {
            let view = CaseDecisionView {
                case_id: c.id.clone(),
                predictions: preds.get(c.id.as_str()).cloned().unwrap_or_default(),
                decisions: decs.get(c.id.as_str()).cloned().unwrap_or_default(),
                outcomes: outs.get(c.id.as_str()).cloned().unwrap_or_default(),
                false_negatives: Vec::new(),
            };
            by_case.insert(c.id.clone(), judge(c, &view));
        }
        OutcomeIndex { by_case }
    }

    /// The judgement for a case — precomputed, or (defensively) recomputed from
    /// the shadow verdict alone for a case the index has not seen.
    pub fn resolve(&self, c: &Case) -> TrustedJudgement {
        if let Some(j) = self.by_case.get(&c.id) {
            return *j;
        }
        resolve_case(c, &[], &[], &[])
    }
}

/// Resolve one case: assemble its records into a view and apply the core
/// precedence, with the case's shadow verdict as the fallback.
fn resolve_case(
    c: &Case,
    outcomes: &[IncidentOutcome],
    decisions: &[AnalystDecision],
    predictions: &[AgentPrediction],
) -> TrustedJudgement {
    let view = CaseDecisionView {
        case_id: c.id.clone(),
        predictions: predictions
            .iter()
            .filter(|p| p.case_id == c.id)
            .cloned()
            .collect(),
        decisions: decisions
            .iter()
            .filter(|d| d.case_id == c.id)
            .cloned()
            .collect(),
        outcomes: outcomes
            .iter()
            .filter(|o| o.case_id.as_deref() == Some(c.id.as_str()))
            .cloned()
            .collect(),
        false_negatives: Vec::new(),
    };
    judge(c, &view)
}

/// Apply the trust precedence to an already-assembled `CaseDecisionView` with the
/// case's shadow verdict as the fallback. The shared tail of both `resolve_case`
/// (which filters the record slices per case) and `OutcomeIndex::build` (which
/// pre-groups them once), so the two paths are guaranteed identical.
fn judge(c: &Case, view: &CaseDecisionView) -> TrustedJudgement {
    resolve_trusted(
        view,
        c.verdict.as_ref().map(|v| v.disposition),
        c.verdict.as_ref().map(|v| v.severity),
        c.trigger.rule_id.starts_with("garmr-risk-"),
    )
}

/// Exponential time decay: a case's weight halves every `halflife` hours. A
/// non-positive OR non-finite half-life disables decay (every in-window case at
/// full weight) — the `is_finite` guard means a `nan`/`inf` slipping through
/// config can never poison a score into NaN (which would defeat the caller's
/// threshold comparisons). The loop also validates the config at startup.
fn decay(age_hours: f64, halflife: f64) -> f64 {
    if !halflife.is_finite() || halflife <= 0.0 {
        return 1.0;
    }
    0.5_f64.powf(age_hours / halflife)
}

/// Score risk objects of one `kind` from the case set, grouping by whatever
/// `subject_of` returns (the host, or the acting db_user for staff). Returns the
/// objects sorted by score descending (take the top N, or filter ≥ threshold).
///
/// A case contributes iff: it isn't itself a risk case, yields a non-empty
/// subject key, falls within [`WINDOW_HOURS`] of `now`, and its disposition
/// multiplier is non-zero (benign is dropped). Age is measured from
/// `updated_at` (a bumped burst stays "hot") and clamped at 0 so minor clock
/// skew never inflates it.
fn score_by(
    cases: &[Case],
    now: DateTime<Utc>,
    params: &RiskParams,
    index: &OutcomeIndex,
    kind: &str,
    subject_of: impl Fn(&Case) -> Option<String>,
) -> Vec<RiskObject> {
    let mut by_subject: BTreeMap<String, Vec<Contributor>> = BTreeMap::new();

    for c in cases {
        // Feedback guard: a raised risk case (host OR staff) must not feed the
        // next score — both use a `garmr-risk-` rule-id prefix.
        if c.trigger.rule_id.starts_with("garmr-risk-") {
            continue;
        }
        let Some(subject) = subject_of(c)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let age_hours = ((now - c.updated_at).num_seconds() as f64 / 3600.0).max(0.0);
        if age_hours > WINDOW_HOURS {
            continue;
        }
        let judgement = index.resolve(c);
        let mult = resolved_mult(&judgement, params);
        if mult <= 0.0 {
            continue; // benign / zero-weight — no contribution
        }
        let contribution =
            level_weight(&c.trigger.level) * mult * decay(age_hours, params.halflife_hours);
        if contribution <= 0.0 {
            continue;
        }
        by_subject.entry(subject).or_default().push(Contributor {
            case_id: c.id.clone(),
            rule_id: c.trigger.rule_id.clone(),
            level: c.trigger.level.clone(),
            contribution,
            trust: judgement.source,
            attack: c.trigger.attack.clone(),
        });
    }

    let mut objects: Vec<RiskObject> = by_subject
        .into_iter()
        .map(|(host, mut contributors)| {
            contributors.sort_by(|a, b| {
                b.contribution
                    .partial_cmp(&a.contribution)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let score = contributors.iter().map(|c| c.contribution).sum();
            RiskObject {
                kind: kind.to_string(),
                host,
                score,
                contributors,
            }
        })
        .collect();
    // Highest risk first; ties broken by name for a stable order.
    objects.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.host.cmp(&b.host))
    });
    objects
}

/// Score every host from the current case set (RBA over the always-present
/// `host` entity). Uses only the shadow verdict — call [`score_hosts_with`] to
/// factor in analyst decisions and incident outcomes.
pub fn score_hosts(cases: &[Case], now: DateTime<Utc>, params: &RiskParams) -> Vec<RiskObject> {
    let index = OutcomeIndex::build(cases, &[], &[], &[]);
    score_hosts_with(cases, now, params, &index)
}

/// Score every host, resolving each case's disposition through a prebuilt
/// [`OutcomeIndex`] (trusted outcome > analyst decision > discounted prediction >
/// shadow verdict > unresolved).
pub fn score_hosts_with(
    cases: &[Case],
    now: DateTime<Utc>,
    params: &RiskParams,
    index: &OutcomeIndex,
) -> Vec<RiskObject> {
    score_by(cases, now, params, index, "host", |c| {
        Some(c.trigger.event.host.to_string())
    })
}

/// Score per-STAFF risk — group by the acting `db_user` (the register
/// caseworker) instead of the host. This is the person-level insider-misuse RBA
/// the host cut misses: a caseworker who spreads low-and-slow abuse (a couple
/// of off-hours lookups, an odd without-ticket, one watchlist brush) never trips
/// any single rule's page, but the decayed sum over their cases does. A case
/// with no `db_user` yields no subject, so this is empty on a deployment without
/// a Postgres access-audit feed.
pub fn score_staff(cases: &[Case], now: DateTime<Utc>, params: &RiskParams) -> Vec<RiskObject> {
    let index = OutcomeIndex::build(cases, &[], &[], &[]);
    score_staff_with(cases, now, params, &index)
}

/// Score per-staff risk, resolving each case through a prebuilt [`OutcomeIndex`].
pub fn score_staff_with(
    cases: &[Case],
    now: DateTime<Utc>,
    params: &RiskParams,
    index: &OutcomeIndex,
) -> Vec<RiskObject> {
    score_by(cases, now, params, index, "staff", |c| {
        c.trigger.event.field("db_user").map(str::to_string)
    })
}

/// Build the synthetic detection for a subject over threshold. `critical` at ≥
/// 2× threshold, else `high`. The message + fields name the top contributing
/// cases so the agent (and a human) can pivot straight to them.
///
/// A `staff`-kind object opens a distinct `garmr-risk-user-<db_user>` case (host
/// synthesised as `registerlookup` so a caseworker is never mistaken for a host
/// node) and carries the acting `db_user` in fields, so the alert reads "risk
/// caseworker X" and the investigate surface can pivot straight to them.
pub fn risk_detection(obj: &RiskObject, params: &RiskParams, now: DateTime<Utc>) -> Detection {
    let critical = obj.score >= 2.0 * params.threshold;
    let level = if critical { "critical" } else { "high" };
    let severity = if critical { "critical" } else { "high" };
    let staff = obj.kind == "staff";

    let top: Vec<String> = obj
        .contributors
        .iter()
        .take(5)
        .map(|c| {
            format!(
                "{} [{}] {:.1}",
                short_id(&c.case_id),
                c.rule_id,
                c.contribution
            )
        })
        .collect();

    let mut fields = BTreeMap::new();
    fields.insert("risk_score".to_string(), format!("{:.1}", obj.score));
    fields.insert(
        "risk_threshold".to_string(),
        format!("{:.0}", params.threshold),
    );
    fields.insert(
        "contributors".to_string(),
        obj.contributors.len().to_string(),
    );
    fields.insert("top_signals".to_string(), top.join("; "));
    // Staff risk carries the db_user so downstream (alert enrichment, the staff
    // pivot, the graph) can attribute the case to the caseworker.
    if staff {
        fields.insert("db_user".to_string(), obj.host.clone());
    }

    // Per-subject rule id → per-subject dedup (via the standard suppression
    // path). Both prefixes start `garmr-risk-`, so both are excluded from
    // re-scoring by the feedback guard in `score_by`.
    let rule_id = if staff {
        format!("garmr-risk-user-{user}", user = obj.host)
    } else {
        format!("garmr-risk-{host}", host = obj.host)
    };
    let rule_title = if staff {
        "Risk caseworker over threshold (RBA)"
    } else {
        "Risk object over threshold (RBA)"
    };
    // A staff object's `host` is a db_user, not a machine — synthesise a neutral
    // system host so it never becomes a host graph node.
    let event_host = if staff {
        "registerlookup".to_string()
    } else {
        obj.host.clone()
    };
    let message = if staff {
        format!(
            "Risk caseworker {user}: accumulated risk {score:.1} (threshold {th:.0}) from {n} signals — {top}",
            user = obj.host,
            score = obj.score,
            th = params.threshold,
            n = obj.contributors.len(),
            top = top.join("; "),
        )
    } else {
        format!(
            "Risk object {host}: accumulated risk {score:.1} (threshold {th:.0}) from {n} signals — {top}",
            host = obj.host,
            score = obj.score,
            th = params.threshold,
            n = obj.contributors.len(),
            top = top.join("; "),
        )
    };

    // The union of what actually fed this score, deduped and ordered. Never a
    // hardcoded technique: a risk incident is an aggregation, so claiming a
    // technique of its own would put a signal in the coverage matrix that no
    // detector produced. An empty union (contributors that were themselves
    // untagged) correctly yields an untagged incident.
    let attack = {
        let mut a: Vec<String> = obj
            .contributors
            .iter()
            .flat_map(|c| c.attack.iter().cloned())
            .collect();
        a.sort();
        a.dedup();
        a
    };

    Detection {
        rule_id,
        rule_title: rule_title.to_string(),
        level: level.to_string(),
        attack,
        event: Event {
            ts: now,
            host: event_host.into(),
            service: "risk".into(),
            source: "risk".into(),
            environment: "risk".into(),
            severity: severity.to_string().into(),
            log_type: "risk".into(),
            message,
            fields,
        },
        observed_at: now,
        realert_secs: Some(params.realert_secs),
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration;
    use garmr_core::{Case, CaseState, Detection, Disposition, Event, Verdict};

    use super::*;

    fn params() -> RiskParams {
        RiskParams {
            threshold: 20.0,
            halflife_hours: 12.0,
            realert_secs: 3600,
            prediction_discount: 0.5,
        }
    }

    /// A trusted analyst decision for a case (full-weight in the resolver).
    fn decide(case: &Case, disp: Disposition) -> garmr_core::AnalystDecision {
        let mut d: garmr_core::AnalystDecision = serde_json::from_str("{}").unwrap();
        d.decision_id = format!("dec-{}", case.id);
        d.case_id = case.id.clone();
        d.disposition = disp;
        d.severity = 6;
        d.created_at = Utc::now();
        d
    }

    /// The pre-grouped `OutcomeIndex::build` must produce EXACTLY the same
    /// judgement per case as the reference per-case full-scan `resolve_case`,
    /// including multiple decisions for one case (order-sensitive) and a stray
    /// record for a case not in the set (grouped but never consumed). Red the
    /// instant the group-by-`case_id` misroutes or reorders a record.
    #[test]
    fn build_matches_per_case_full_scan() {
        let a = case(
            "garmr-sigma-x",
            "high",
            "h1",
            Some(Disposition::Malicious),
            1,
        );
        let b = case("garmr-sigma-y", "medium", "h2", None, 2);
        let c = case("garmr-sigma-z", "low", "h3", Some(Disposition::Benign), 3);
        let cases = vec![a.clone(), b.clone(), c.clone()];

        // Two decisions for `a` (order matters), one for `b`, a stray for a
        // non-existent case, and none for `c`.
        let mut d_a1 = decide(&a, Disposition::Suspicious);
        d_a1.decision_id = "dec-a-1".into();
        let mut d_a2 = decide(&a, Disposition::Malicious);
        d_a2.decision_id = "dec-a-2".into();
        let d_b = decide(&b, Disposition::Benign);
        let mut stray = decide(&a, Disposition::Benign);
        stray.case_id = "ghost-case".into();
        stray.decision_id = "dec-ghost".into();
        let decisions = vec![d_a1, d_a2, d_b, stray];

        let idx = OutcomeIndex::build(&cases, &[], &decisions, &[]);
        for cse in &cases {
            assert_eq!(
                idx.by_case.get(&cse.id).copied(),
                Some(resolve_case(cse, &[], &decisions, &[])),
                "pre-grouped build must equal per-case full-scan resolve for {}",
                cse.id
            );
        }
    }

    /// Build an index that resolves the given cases with trusted decisions.
    fn decided_index(cases: &[Case], disp: Disposition) -> OutcomeIndex {
        let decisions: Vec<_> = cases.iter().map(|c| decide(c, disp)).collect();
        OutcomeIndex::build(cases, &[], &decisions, &[])
    }

    fn det(rule_id: &str, level: &str, host: &str) -> Detection {
        Detection {
            rule_id: rule_id.to_string(),
            rule_title: "t".to_string(),
            level: level.to_string(),
            attack: vec![],
            event: Event {
                ts: Utc::now(),
                host: host.into(),
                service: "sshd".into(),
                source: "journald".into(),
                environment: "test".into(),
                severity: "warning".into(),
                log_type: "system".into(),
                message: "m".to_string(),
                fields: BTreeMap::new(),
            },
            observed_at: Utc::now(),
            realert_secs: None,
        }
    }

    /// A case with a given level/host, verdict disposition, and age (hours ago).
    fn case(rule_id: &str, level: &str, host: &str, disp: Option<Disposition>, age_h: i64) -> Case {
        let mut c = Case::open(det(rule_id, level, host));
        c.updated_at = Utc::now() - Duration::hours(age_h);
        c.state = CaseState::Triaged;
        c.verdict = disp.map(|d| Verdict {
            disposition: d,
            severity: 5,
            confidence: 0.8,
            rationale: "r".to_string(),
            proposed_action: None,
        });
        c
    }

    /// A registerlookup case: same db host, a `db_user` field carrying the
    /// acting caseworker — the shape staff RBA groups on.
    fn staff_case(
        rule_id: &str,
        level: &str,
        db_user: &str,
        disp: Option<Disposition>,
        age_h: i64,
    ) -> Case {
        let mut d = det(rule_id, level, "pgserver");
        d.event
            .fields
            .insert("db_user".to_string(), db_user.to_string());
        let mut c = Case::open(d);
        c.updated_at = Utc::now() - Duration::hours(age_h);
        c.state = CaseState::Triaged;
        c.verdict = disp.map(|d| Verdict {
            disposition: d,
            severity: 5,
            confidence: 0.8,
            rationale: "r".to_string(),
            proposed_action: None,
        });
        c
    }

    #[test]
    fn benign_cases_never_accumulate_risk() {
        // Ten benign highs on one host → zero risk (RBA drops adjudicated noise).
        let cases: Vec<Case> = (0..10)
            .map(|i| {
                case(
                    &format!("r{i}"),
                    "high",
                    "pve",
                    Some(Disposition::Benign),
                    0,
                )
            })
            .collect();
        let objs = score_hosts(&cases, Utc::now(), &params());
        assert!(
            objs.is_empty(),
            "benign cases must not produce a risk object"
        );
    }

    #[test]
    fn many_weak_signals_cross_threshold() {
        // Six fresh medium cases, none benign: 6 × 4 × mult. Suspicious ×1 → 24
        // > 20 threshold. This is the core wedge: none of these individually
        // escalate, but together they raise the host.
        let cases: Vec<Case> = (0..6)
            .map(|i| {
                case(
                    &format!("r{i}"),
                    "medium",
                    "pve",
                    Some(Disposition::Suspicious),
                    0,
                )
            })
            .collect();
        // Agent-only (unreviewed) → discounted: 6 × 4 × (1.0 × 0.5) = 12, below
        // the 20 threshold. Unreviewed weak signals are now held back.
        let objs = score_hosts(&cases, Utc::now(), &params());
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].host, "pve");
        assert!((objs[0].score - 12.0).abs() < 0.01, "got {}", objs[0].score);
        assert_eq!(objs[0].contributors.len(), 6);
        assert!(objs[0]
            .contributors
            .iter()
            .all(|c| c.trust == TrustSource::DiscountedPrediction));

        // Once a human adjudicates the same signals Suspicious, they count at
        // full weight: 6 × 4 × 1.0 = 24 → crosses the threshold (trusted risk).
        let idx = decided_index(&cases, Disposition::Suspicious);
        let trusted = score_hosts_with(&cases, Utc::now(), &params(), &idx);
        assert!(
            trusted[0].score >= 20.0,
            "trusted score {} should cross threshold",
            trusted[0].score
        );
        assert!((trusted[0].score - 24.0).abs() < 0.01);
    }

    #[test]
    fn malicious_doubles_and_decay_reduces() {
        // Unreviewed malicious high, discounted: 8 × 2 × 0.5 × 1.0 = 8.
        let fresh = score_hosts(
            &[case("r", "high", "pve", Some(Disposition::Malicious), 0)],
            Utc::now(),
            &params(),
        );
        assert!(
            (fresh[0].score - 8.0).abs() < 0.01,
            "got {}",
            fresh[0].score
        );
        // The same case 12h old (one half-life) ≈ 4.
        let aged = score_hosts(
            &[case("r", "high", "pve", Some(Disposition::Malicious), 12)],
            Utc::now(),
            &params(),
        );
        assert!((aged[0].score - 4.0).abs() < 0.1, "got {}", aged[0].score);
        // 24h out (two half-lives) ≈ 2 — still well inside the 72h window.
        let old = score_hosts(
            &[case("r", "high", "pve", Some(Disposition::Malicious), 24)],
            Utc::now(),
            &params(),
        );
        assert!((old[0].score - 2.0).abs() < 0.2, "got {}", old[0].score);

        // A TRUSTED malicious decision on the fresh case counts at full weight:
        // 8 × 2 × 1.0 = 16 (the shadow discount does not apply to human truth).
        let c = [case("r", "high", "pve", Some(Disposition::Malicious), 0)];
        let idx = decided_index(&c, Disposition::Malicious);
        let trusted = score_hosts_with(&c, Utc::now(), &params(), &idx);
        assert!(
            (trusted[0].score - 16.0).abs() < 0.01,
            "trusted full weight, got {}",
            trusted[0].score
        );
        assert_eq!(
            trusted[0].contributors[0].trust,
            TrustSource::AnalystDecision
        );
    }

    #[test]
    fn risk_cases_are_excluded_from_scoring() {
        // A prior risk case must not feed the next score (no runaway feedback).
        let cases = vec![
            case(
                "garmr-risk-pve",
                "critical",
                "pve",
                Some(Disposition::Malicious),
                0,
            ),
            case("real-rule", "low", "pve", Some(Disposition::Suspicious), 0),
        ];
        let objs = score_hosts(&cases, Utc::now(), &params());
        assert_eq!(objs.len(), 1);
        // Only the real low case counts, discounted: 2 × 1 × 0.5 = 1, NOT the
        // excluded critical (the garmr-risk- guard drops it before resolution).
        assert!((objs[0].score - 1.0).abs() < 0.01, "got {}", objs[0].score);
    }

    #[test]
    fn untriaged_cases_get_partial_credit() {
        // An in-flight (no verdict) case counts at half — a fresh burst can raise
        // a host before the agent finishes, without over-counting the unknown.
        let objs = score_hosts(&[case("r", "high", "pve", None, 0)], Utc::now(), &params());
        assert!(
            (objs[0].score - 4.0).abs() < 0.01,
            "8 × 0.5 = 4, got {}",
            objs[0].score
        );
    }

    #[test]
    fn detection_escalates_severity_and_names_signals() {
        let cases: Vec<Case> = (0..8)
            .map(|i| {
                case(
                    &format!("r{i}"),
                    "high",
                    "pve",
                    Some(Disposition::Malicious),
                    0,
                )
            })
            .collect();
        let objs = score_hosts(&cases, Utc::now(), &params());
        // 8 × (8 × 2 × 0.5 discount) = 64 ≥ 2×20 → still critical.
        let d = risk_detection(&objs[0], &params(), Utc::now());
        assert_eq!(d.level, "critical");
        assert_eq!(d.event.log_type, "risk");
        assert_eq!(d.rule_id, "garmr-risk-pve");
        assert_eq!(d.realert_secs, Some(3600));
        assert!(d.event.fields.get("top_signals").unwrap().contains("r0"));
        assert_eq!(
            d.event.fields.get("contributors").map(String::as_str),
            Some("8")
        );
        // Its dedup key is per-host so bursts collapse to one risk case.
        assert!(d.dedup_key().starts_with("garmr-risk-pve|pve|"));
    }

    #[test]
    fn out_of_window_cases_are_ignored() {
        let objs = score_hosts(
            &[case(
                "r",
                "critical",
                "pve",
                Some(Disposition::Malicious),
                96,
            )],
            Utc::now(),
            &params(),
        );
        assert!(objs.is_empty(), "a 96h-old case is outside the 72h window");
    }

    #[test]
    fn nan_halflife_never_poisons_the_score() {
        // A nan/inf half-life (TOML permits the literal) must not make scores
        // NaN — decay falls back to 1.0, keeping every contribution finite.
        let bad = RiskParams {
            threshold: 20.0,
            halflife_hours: f64::NAN,
            realert_secs: 3600,
            prediction_discount: 0.5,
        };
        let objs = score_hosts(
            &[case("r", "high", "pve", Some(Disposition::Malicious), 3)],
            Utc::now(),
            &bad,
        );
        assert_eq!(objs.len(), 1);
        assert!(
            objs[0].score.is_finite(),
            "score must stay finite, got {}",
            objs[0].score
        );
        assert!(
            (objs[0].score - 8.0).abs() < 0.01,
            "no decay applied → 8×2×0.5 discount = 8"
        );
    }

    #[test]
    fn nan_prediction_discount_never_poisons_the_score() {
        // A misconfigured non-finite discount must not make scores NaN/inf: the
        // resolved_mult guard falls back to 0.5, so an unreviewed malicious high
        // resolves to 8 × 2 × 0.5 = 8 (finite), not NaN.
        let mut p = params();
        p.prediction_discount = f64::NAN;
        let objs = score_hosts(
            &[case("r", "high", "pve", Some(Disposition::Malicious), 0)],
            Utc::now(),
            &p,
        );
        assert_eq!(objs.len(), 1);
        assert!(objs[0].score.is_finite(), "got {}", objs[0].score);
        assert!((objs[0].score - 8.0).abs() < 0.01, "got {}", objs[0].score);
    }

    #[test]
    fn staff_risk_scores_per_handlaggare_not_per_host() {
        // Two caseworkers on the SAME db host. Host RBA lumps them onto the one
        // host; staff RBA separates them by db_user — the whole point.
        let cases = vec![
            staff_case(
                "reg_off_hours_lookup",
                "high",
                "anna.h",
                Some(Disposition::Suspicious),
                0,
            ),
            staff_case(
                "reg_bulk_lookups_by_user",
                "high",
                "anna.h",
                Some(Disposition::Suspicious),
                0,
            ),
            staff_case(
                "reg_lookup_without_ticket",
                "high",
                "anna.h",
                Some(Disposition::Suspicious),
                0,
            ),
            staff_case(
                "reg_off_hours_lookup",
                "high",
                "bob.k",
                Some(Disposition::Suspicious),
                0,
            ),
        ];
        // Staff RBA (agent-only, discounted): anna.h = 3×8×0.5 = 12, bob.k = 4.
        // The point under test is per-user grouping, not the threshold.
        let staff = score_staff(&cases, Utc::now(), &params());
        assert_eq!(staff.len(), 2);
        assert_eq!(staff[0].kind, "staff");
        assert_eq!(staff[0].host, "anna.h");
        assert!(
            (staff[0].score - 12.0).abs() < 0.01,
            "got {}",
            staff[0].score
        );
        // Once adjudicated Suspicious, anna.h's signals cross the threshold (24).
        let idx = decided_index(&cases, Disposition::Suspicious);
        let trusted = score_staff_with(&cases, Utc::now(), &params(), &idx);
        assert!(
            trusted[0].score >= params().threshold,
            "trusted staff score {} should cross threshold",
            trusted[0].score
        );
        // Host RBA on the same cases collapses everyone onto the single db host.
        let hosts = score_hosts(&cases, Utc::now(), &params());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "pgserver");

        // The staff detection is per-user, names the caseworker, carries the
        // db_user, and hides the person behind a neutral system host.
        let d = risk_detection(&staff[0], &params(), Utc::now());
        assert_eq!(d.rule_id, "garmr-risk-user-anna.h");
        assert_eq!(d.event.host, "registerlookup");
        assert_eq!(
            d.event.fields.get("db_user").map(String::as_str),
            Some("anna.h")
        );
        assert!(d.event.message.contains("Risk caseworker anna.h"));
        assert!(d
            .dedup_key()
            .starts_with("garmr-risk-user-anna.h|registerlookup|"));

        // Feedback guard: the raised staff-risk case must not re-feed scoring.
        let mut risk_case = Case::open(d);
        risk_case.state = CaseState::Triaged;
        risk_case.verdict = Some(Verdict {
            disposition: Disposition::Malicious,
            severity: 9,
            confidence: 0.9,
            rationale: "r".to_string(),
            proposed_action: None,
        });
        assert!(score_staff(&[risk_case], Utc::now(), &params()).is_empty());
    }

    #[test]
    fn risk_incident_reports_the_union_of_contributor_techniques() {
        // RBA is an aggregation, so its ATT&CK claim must be exactly what fed
        // it. A hardcoded technique here would put a signal in the coverage
        // matrix that no detector actually produced.
        let obj = RiskObject {
            kind: "host".into(),
            host: "pve".into(),
            score: 42.0,
            contributors: vec![
                Contributor {
                    case_id: "c1".into(),
                    rule_id: "r1".into(),
                    level: "high".into(),
                    contribution: 20.0,
                    trust: TrustSource::Unresolved,
                    attack: vec!["T1110".into(), "T1078".into()],
                },
                Contributor {
                    case_id: "c2".into(),
                    rule_id: "r2".into(),
                    level: "medium".into(),
                    // Overlaps c1 — the union must dedupe rather than double-count.
                    contribution: 12.0,
                    trust: TrustSource::Unresolved,
                    attack: vec!["T1078".into()],
                },
                Contributor {
                    case_id: "c3".into(),
                    rule_id: "r3".into(),
                    level: "low".into(),
                    // An untagged contributor (e.g. the frequency baseline) must
                    // not cause a technique to be invented.
                    contribution: 10.0,
                    trust: TrustSource::Unresolved,
                    attack: vec![],
                },
            ],
        };
        let d = risk_detection(&obj, &params(), Utc::now());
        assert_eq!(d.attack, vec!["T1078".to_string(), "T1110".to_string()]);
    }

    #[test]
    fn risk_incident_from_untagged_contributors_stays_untagged() {
        let obj = RiskObject {
            kind: "host".into(),
            host: "pve".into(),
            score: 30.0,
            contributors: vec![Contributor {
                case_id: "c1".into(),
                rule_id: "garmr-freq-pve-sshd".into(),
                level: "medium".into(),
                contribution: 30.0,
                trust: TrustSource::Unresolved,
                attack: vec![],
            }],
        };
        let d = risk_detection(&obj, &params(), Utc::now());
        assert!(
            d.attack.is_empty(),
            "an aggregation of untagged signals claims nothing: {:?}",
            d.attack
        );
    }
}
