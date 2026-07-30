// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The dataset builder: fold the case store into an immutable, content-addressed
//! [`DatasetSnapshot`] of TRUSTED-only, poison-excluded, temporally-split labels.
//!
//! Two safety properties are enforced here by construction:
//!
//! * **Trusted labels only (invariant #3).** A row is kept ONLY when
//!   [`resolve_trusted`] yields [`TrustSource::Outcome`] or
//!   [`TrustSource::AnalystDecision`]. A prediction / shadow / unresolved label
//!   is dropped (recorded as an `UntrustedLabel` exclusion), so a self-prediction
//!   can never become a training label.
//!
//! * **Poison exclusion never strips the positive class.** The Phase-5
//!   compromised-entity set folds in the entities of every human-adjudged adverse
//!   case — so a human-Malicious case is IN that set. Excluding it would empty the
//!   positive class and make the dangerous-FN guard vacuous. So the poison
//!   exclusion is applied ONLY to benign-labeled cases (the real poisoning vector:
//!   benign floods that teach "ignore this host"); adverse-labeled rows are ALWAYS
//!   kept. `bucket_counts` then exposes the surviving positive class so a vacuous
//!   Test holdout is caught downstream.

use std::collections::HashMap;

use chrono::Utc;
use garmr_core::{
    assign_split, is_dangerous, resolve_trusted, AgentPrediction, AnalystDecision, Case,
    CaseDecisionView, DatasetSnapshot, DatasetVersions, Disposition, Exclusion, ExclusionReason,
    IncidentOutcome, LabelRow, LabelSourcePin, PinnedCase, Result, SnapshotWindow, TemporalSplit,
    TrustSource,
};
use garmr_store::Store;

/// Everything the pure builder needs — plain data, so [`build_snapshot`] is
/// unit-testable with no I/O.
#[derive(Debug, Clone, Default)]
pub struct DatasetInputs {
    pub name: String,
    /// Build timestamp (unix micros) — metadata only, excluded from the digest.
    pub built_at_us: i64,
    pub cases: Vec<Case>,
    pub outcomes: Vec<IncidentOutcome>,
    pub decisions: Vec<AnalystDecision>,
    pub predictions: Vec<AgentPrediction>,
    /// Per-case exclusion candidates (from `poisoned_case_reasons`), applied
    /// ONLY to benign rows.
    pub poisoned: HashMap<String, ExclusionReason>,
    /// Per-case asset-criticality `[0,1]` from the Trusted environment model, so
    /// a criticality-sensitive knob is measurable on replay.
    pub criticality: HashMap<String, f32>,
    pub versions: DatasetVersions,
    pub window: SnapshotWindow,
    /// (train_frac, val_frac); the remainder is the Test holdout.
    pub split_fracs: (f64, f64),
}

/// Resolve one case's trusted judgement from an already-assembled view (the same
/// precedence `risk.rs` uses). Split out so `build_snapshot` can feed it a view
/// built from a pre-grouped index instead of re-filtering every slice per case.
fn judge_view(c: &Case, view: &CaseDecisionView) -> garmr_core::TrustedJudgement {
    resolve_trusted(
        view,
        c.verdict.as_ref().map(|v| v.disposition),
        c.verdict.as_ref().map(|v| v.severity),
        c.trigger.rule_id.starts_with("garmr-risk-"),
    )
}

/// Compute the temporal split boundaries from the kept rows' `opened_at` so the
/// newest slice is the Test holdout. Quantile-by-count on the ascending times.
fn temporal_split(mut ats: Vec<i64>, train_frac: f64, val_frac: f64) -> TemporalSplit {
    if ats.is_empty() {
        return TemporalSplit::default();
    }
    ats.sort_unstable();
    let n = ats.len();
    let tf = train_frac.clamp(0.0, 1.0);
    let vf = val_frac.clamp(0.0, 1.0 - tf.min(1.0));
    let train_count = ((tf * n as f64).floor() as usize).min(n);
    let val_count = ((vf * n as f64).floor() as usize).min(n - train_count);
    let train_end_us = if train_count == 0 {
        i64::MIN
    } else {
        ats[train_count - 1]
    };
    let val_idx = train_count + val_count;
    let val_end_us = if val_idx == 0 {
        train_end_us
    } else {
        ats[val_idx - 1]
    };
    TemporalSplit {
        train_end_us,
        val_end_us,
    }
}

/// Build an immutable dataset snapshot from plain inputs. Pure — no I/O, no clock.
pub fn build_snapshot(inputs: DatasetInputs) -> DatasetSnapshot {
    let DatasetInputs {
        name,
        built_at_us,
        cases,
        outcomes,
        decisions,
        predictions,
        poisoned,
        criticality,
        versions,
        window,
        split_fracs,
    } = inputs;

    let windowed = window.to_us != 0 || window.from_us != 0;
    let mut kept: Vec<(String, LabelRow)> = Vec::new(); // (case_id, row) pre-split
    let mut excluded: Vec<Exclusion> = Vec::new();
    let mut included: Vec<PinnedCase> = Vec::new();
    let mut sources: Vec<TrustSource> = Vec::new();

    // Pre-group the three label slices by case_id ONCE (O(records)) so each case's
    // judgement is O(1) map lookups, not three full linear scans per case — the
    // same de-quadratic (O(cases×records) → O(cases+records)) applied to the risk
    // board's `OutcomeIndex::build`. Each per-case Vec preserves slice order, so
    // every `CaseDecisionView` is byte-identical to the old per-case `filter`.
    use std::collections::HashMap;
    let mut preds_by: HashMap<&str, Vec<AgentPrediction>> = HashMap::new();
    for p in &predictions {
        preds_by
            .entry(p.case_id.as_str())
            .or_default()
            .push(p.clone());
    }
    let mut decs_by: HashMap<&str, Vec<AnalystDecision>> = HashMap::new();
    for d in &decisions {
        decs_by
            .entry(d.case_id.as_str())
            .or_default()
            .push(d.clone());
    }
    let mut outs_by: HashMap<&str, Vec<IncidentOutcome>> = HashMap::new();
    for o in &outcomes {
        if let Some(cid) = o.case_id.as_deref() {
            outs_by.entry(cid).or_default().push(o.clone());
        }
    }

    for c in &cases {
        let opened_at_us = c.opened_at.timestamp_micros();
        if windowed && (opened_at_us < window.from_us || opened_at_us > window.to_us) {
            excluded.push(Exclusion {
                case_id: c.id.clone(),
                reason: ExclusionReason::OutOfWindow,
            });
            continue;
        }
        let view = CaseDecisionView {
            case_id: c.id.clone(),
            predictions: preds_by.get(c.id.as_str()).cloned().unwrap_or_default(),
            decisions: decs_by.get(c.id.as_str()).cloned().unwrap_or_default(),
            outcomes: outs_by.get(c.id.as_str()).cloned().unwrap_or_default(),
            false_negatives: Vec::new(),
        };
        let j = judge_view(c, &view);
        // Invariant #3: trusted labels only.
        if !matches!(
            j.source,
            TrustSource::Outcome | TrustSource::AnalystDecision
        ) {
            excluded.push(Exclusion {
                case_id: c.id.clone(),
                reason: ExclusionReason::UntrustedLabel,
            });
            continue;
        }
        let disposition = j.disposition.unwrap_or(Disposition::NeedsHuman);
        let adverse = is_dangerous(disposition);
        // A NeedsHuman "decision" is not a usable label.
        if !adverse && disposition == Disposition::NeedsHuman {
            excluded.push(Exclusion {
                case_id: c.id.clone(),
                reason: ExclusionReason::UntrustedLabel,
            });
            continue;
        }
        // FIX#1: the poison exclusion applies ONLY to benign rows. An adverse
        // (Malicious/Suspicious) trusted row is the positive class the
        // dangerous-FN guard protects and is ALWAYS kept.
        if !adverse {
            if let Some(reason) = poisoned.get(&c.id) {
                excluded.push(Exclusion {
                    case_id: c.id.clone(),
                    reason: *reason,
                });
                continue;
            }
        }

        let event_ids: Vec<String> = c
            .trigger
            .event
            .field("event_id")
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();
        included.push(PinnedCase {
            case_id: c.id.clone(),
            event_ids,
            opened_at_us,
        });
        sources.push(j.source);
        // Use the finding's PRE-boost base level when present (an env-detection
        // case carries `finding_base_level`); `Detection.level` is already the
        // criticality-boosted, floored output, so scoring it through the ensemble
        // again would DOUBLE-COUNT criticality. A plain (non-ensemble) detection
        // has no such field, so its raw rule level is used directly.
        let rule_level = c
            .trigger
            .event
            .field("finding_base_level")
            .map(|s| s.to_string())
            .unwrap_or_else(|| c.trigger.level.clone());
        kept.push((
            c.id.clone(),
            LabelRow {
                case_id: c.id.clone(),
                rule_level,
                criticality: criticality.get(&c.id).copied().unwrap_or(0.0),
                trusted_disposition: disposition,
                trusted_severity: j.severity.unwrap_or(0),
                trusted_source: j.source,
                opened_at_us,
                split: garmr_core::SplitBucket::Train, // stamped below
            },
        ));
    }

    let split = temporal_split(
        kept.iter().map(|(_, r)| r.opened_at_us).collect(),
        split_fracs.0,
        split_fracs.1,
    );

    let rows: Vec<LabelRow> = kept
        .into_iter()
        .map(|(_, mut r)| {
            r.split = assign_split(r.opened_at_us, split);
            r
        })
        .collect();

    // Pin the distinct label sources (all trusted at weight 1.0).
    sources.sort_by_key(|s| *s as u8);
    sources.dedup();
    let label_sources: Vec<LabelSourcePin> = sources
        .into_iter()
        .map(|kind| LabelSourcePin { kind, trust: 1.0 })
        .collect();

    let mut snap = DatasetSnapshot {
        name,
        built_at_us,
        window,
        versions,
        label_sources,
        split,
        included,
        excluded,
        rows,
        digest: String::new(),
    };
    snap.stamp_digest();
    snap
}

/// Gather the builder inputs from the local store: the case records, the
/// per-case poison candidates, and the per-case asset-criticality from the
/// Trusted environment model. Not pure (reads the store, uses the clock).
pub fn collect_inputs(
    store: &Store,
    name: &str,
    window: SnapshotWindow,
    versions: DatasetVersions,
    split_fracs: (f64, f64),
) -> Result<DatasetInputs> {
    let now = Utc::now();
    let cases = store.state.list_cases()?;
    let outcomes = store.state.list_incident_outcomes()?;
    let decisions = store.state.list_decisions()?;
    let predictions = store.state.list_predictions()?;
    let poisoned = store.state.poisoned_case_reasons()?;

    // Real per-case criticality from the Trusted env model (matches what serve's
    // ensemble sees), so `crit_coef` is measurable on replay.
    let view = garmr_analytics::envdetect::TrustedView::load(store, None, now)?;
    let mut criticality = HashMap::new();
    for c in &cases {
        criticality.insert(c.id.clone(), view.criticality_of(&c.trigger.event.host));
    }

    Ok(DatasetInputs {
        name: name.to_string(),
        built_at_us: now.timestamp_micros(),
        cases,
        outcomes,
        decisions,
        predictions,
        poisoned,
        criticality,
        versions,
        window,
        split_fracs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone};
    use garmr_core::{Detection, Event, SplitBucket};
    use std::collections::BTreeMap;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn ev(host: &str) -> Event {
        Event {
            ts: at(0),
            host: host.into(),
            service: "s".into(),
            source: "src".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields: BTreeMap::new(),
        }
    }

    fn case(id: &str, host: &str, opened_secs: i64, verdict: Option<Disposition>) -> Case {
        let det = Detection {
            rule_id: "r1".into(),
            rule_title: "t".into(),
            level: "high".into(),
            attack: vec![],
            event: ev(host),
            observed_at: at(opened_secs),
            realert_secs: None,
        };
        let mut c = Case::open(det);
        c.id = id.into();
        c.opened_at = at(opened_secs);
        c.state = garmr_core::CaseState::Closed;
        c.verdict = verdict.map(|d| garmr_core::Verdict {
            disposition: d,
            severity: 5,
            confidence: 0.9,
            rationale: "r".into(),
            proposed_action: None,
        });
        c
    }

    fn decision(case_id: &str, d: Disposition) -> AnalystDecision {
        AnalystDecision {
            decision_id: format!("dec-{case_id}"),
            case_id: case_id.into(),
            principal: "analyst".into(),
            disposition: d,
            severity: 7,
            reason_codes: vec![],
            narrative: String::new(),
            accepted_evidence: vec![],
            rejected_evidence: vec![],
            prediction_correct: None,
            important_evidence_missed: None,
            proposed_action_justified: None,
            supersedes: None,
            created_at: at(0),
            audit_id: None,
        }
    }

    fn inputs(cases: Vec<Case>, decisions: Vec<AnalystDecision>) -> DatasetInputs {
        DatasetInputs {
            name: "d".into(),
            cases,
            decisions,
            split_fracs: (0.5, 0.25),
            ..Default::default()
        }
    }

    /// The pre-grouped (by case_id) judgement `build_snapshot` uses must equal the
    /// old per-case full-scan filter for every case — including multiple decisions
    /// for one case (order-sensitive) and a stray decision for a case not in the
    /// set. Red the instant the group-by misroutes or reorders a record.
    #[test]
    fn pregrouped_judge_matches_per_case_scan() {
        use std::collections::HashMap;
        let cases = vec![
            case("a", "h", 10, Some(Disposition::Malicious)),
            case("b", "h", 20, None),
            case("c", "h", 30, None),
        ];
        let mut d_a2 = decision("a", Disposition::Malicious);
        d_a2.decision_id = "dec-a-2".into();
        let mut stray = decision("a", Disposition::Benign);
        stray.case_id = "ghost".into();
        stray.decision_id = "dec-ghost".into();
        let decisions = vec![
            decision("a", Disposition::Suspicious),
            d_a2,
            decision("b", Disposition::Benign),
            stray,
        ];

        let mut decs_by: HashMap<&str, Vec<AnalystDecision>> = HashMap::new();
        for d in &decisions {
            decs_by
                .entry(d.case_id.as_str())
                .or_default()
                .push(d.clone());
        }
        for c in &cases {
            let scan = CaseDecisionView {
                case_id: c.id.clone(),
                predictions: vec![],
                decisions: decisions
                    .iter()
                    .filter(|d| d.case_id == c.id)
                    .cloned()
                    .collect(),
                outcomes: vec![],
                false_negatives: vec![],
            };
            let grouped = CaseDecisionView {
                case_id: c.id.clone(),
                predictions: vec![],
                decisions: decs_by.get(c.id.as_str()).cloned().unwrap_or_default(),
                outcomes: vec![],
                false_negatives: vec![],
            };
            assert_eq!(
                judge_view(c, &scan),
                judge_view(c, &grouped),
                "case {}",
                c.id
            );
        }
    }

    #[test]
    fn a_prediction_only_case_yields_no_row() {
        // Agent verdict Malicious but NO human decision/outcome ⇒ discounted
        // prediction ⇒ not a trusted label ⇒ excluded, no row.
        let cases = vec![case("c1", "h1", 10, Some(Disposition::Malicious))];
        let snap = build_snapshot(inputs(cases, vec![]));
        assert!(snap.rows.is_empty());
        assert_eq!(snap.excluded.len(), 1);
        assert_eq!(snap.excluded[0].reason, ExclusionReason::UntrustedLabel);
    }

    #[test]
    fn a_benign_case_on_a_poisoned_entity_is_excluded() {
        let cases = vec![case("c1", "h1", 10, None)];
        let decisions = vec![decision("c1", Disposition::Benign)];
        let mut i = inputs(cases, decisions);
        i.poisoned.insert("c1".into(), ExclusionReason::Compromised);
        let snap = build_snapshot(i);
        assert!(snap.rows.is_empty());
        assert_eq!(snap.excluded[0].reason, ExclusionReason::Compromised);
    }

    #[test]
    fn an_adverse_case_on_a_poisoned_entity_is_kept() {
        // FIX#1: a human-Malicious case is in the compromised set by construction;
        // it must survive as a positive, not be stripped.
        let cases = vec![case("c1", "h1", 10, None)];
        let decisions = vec![decision("c1", Disposition::Malicious)];
        let mut i = inputs(cases, decisions);
        i.poisoned.insert("c1".into(), ExclusionReason::Compromised);
        let snap = build_snapshot(i);
        assert_eq!(snap.rows.len(), 1, "the adverse positive is kept");
        assert_eq!(snap.rows[0].trusted_disposition, Disposition::Malicious);
        assert_eq!(snap.rows[0].trusted_source, TrustSource::AnalystDecision);
    }

    #[test]
    fn temporal_split_puts_the_newest_in_test() {
        // Four benign trusted cases at t=10,20,30,40 with fracs (0.5, 0.25):
        // 2 Train, 1 Val, 1 Test (the newest).
        let cases = vec![
            case("c1", "h1", 10, None),
            case("c2", "h2", 20, None),
            case("c3", "h3", 30, None),
            case("c4", "h4", 40, None),
        ];
        let decisions = vec![
            decision("c1", Disposition::Benign),
            decision("c2", Disposition::Benign),
            decision("c3", Disposition::Benign),
            decision("c4", Disposition::Malicious),
        ];
        let snap = build_snapshot(inputs(cases, decisions));
        assert_eq!(snap.rows.len(), 4);
        let counts = snap.bucket_counts();
        assert_eq!(counts.train.total, 2);
        assert_eq!(counts.val.total, 1);
        assert_eq!(counts.test.total, 1);
        // The newest (c4, t=40, Malicious) is the Test holdout positive.
        let newest = snap.rows.iter().find(|r| r.case_id == "c4").unwrap();
        assert_eq!(newest.split, SplitBucket::Test);
        assert_eq!(counts.test.dangerous, 1);
        assert!(snap.verify_digest());
    }

    #[test]
    fn env_case_records_the_pre_boost_base_level() {
        // An env-detection case's trigger.level is the criticality-BOOSTED,
        // floored output ("high"); finding_base_level preserves the raw base
        // ("medium"). The row must record the base, else replay double-counts
        // criticality.
        let mut c = case("c1", "h1", 10, None);
        c.trigger.level = "high".into(); // the boosted output
        c.trigger
            .event
            .fields
            .insert("finding_base_level".into(), "medium".into());
        let snap = build_snapshot(inputs(
            vec![c],
            vec![decision("c1", Disposition::Malicious)],
        ));
        assert_eq!(snap.rows.len(), 1);
        assert_eq!(
            snap.rows[0].rule_level, "medium",
            "the pre-boost base level is recorded, not the boosted output"
        );
    }

    #[test]
    fn digest_is_stable_across_input_case_order() {
        let mk = |order: &[&str]| {
            let by: HashMap<&str, (i64, Disposition)> = [
                ("c1", (10, Disposition::Benign)),
                ("c2", (20, Disposition::Malicious)),
            ]
            .into_iter()
            .collect();
            let cases: Vec<Case> = order
                .iter()
                .map(|id| {
                    let (t, _) = by[id];
                    case(id, "h", t, None)
                })
                .collect();
            let decisions: Vec<AnalystDecision> =
                order.iter().map(|id| decision(id, by[id].1)).collect();
            build_snapshot(inputs(cases, decisions)).digest
        };
        assert_eq!(mk(&["c1", "c2"]), mk(&["c2", "c1"]));
    }
}
