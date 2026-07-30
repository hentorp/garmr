// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 9 — the offline, deterministic, LLM-free reflection drafter.
//!
//! Clusters analyst-authored [`MistakeRecord`]s by [`MistakeCategory`] and, for
//! each category with enough corroboration, emits a [`Lesson`] whose body is the
//! FROZEN [`category_guidance`] string (never model/attacker bytes). Pure — no
//! LLM, no egress, no clock — so it ships in the default build.
//!
//! Invariant #3 anchor: a CASE-SCOPED mistake counts only when that case's
//! current analyst decision is a genuine correction (the agent was wrong, or
//! missed evidence). A mistake tied only to an unreviewed case does not count, so
//! the system can never "learn" from its own unadjudicated output.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use garmr_core::{
    category_guidance, current_decision, validate_lesson_set, AnalystDecision, FalseNegativeRecord,
    Lesson, LessonFinding, LessonSet, MistakeCategory, MistakeRecord, LESSON_CAPS,
};

/// Tunable reflection parameters. The SAFETY caps are NOT here — they live in
/// `garmr_core::LESSON_CAPS`, single-sourced with the promote-time gate.
#[derive(Debug, Clone, Copy)]
pub struct ReflectPolicy {
    /// Minimum corroborating mistakes for a category to yield a lesson.
    pub min_support: usize,
    /// The lookback window (hours) — used by the caller to pre-filter mistakes.
    pub lookback_hours: i64,
}

impl Default for ReflectPolicy {
    fn default() -> Self {
        Self {
            min_support: 2,
            lookback_hours: 720,
        }
    }
}

/// Every category, so we ship a lesson for exactly those with frozen guidance.
const ALL_CATEGORIES: &[MistakeCategory] = &[
    MistakeCategory::Unspecified,
    MistakeCategory::MissedEvidence,
    MistakeCategory::MisinterpretedEvidence,
    MistakeCategory::UnnecessaryTools,
    MistakeCategory::MissingTools,
    MistakeCategory::WrongAssumption,
    MistakeCategory::Unknown,
];

/// Does this case's CURRENT analyst decision represent a genuine correction?
fn case_is_corrected(case_id: &str, decisions: &[AnalystDecision]) -> bool {
    let for_case: Vec<AnalystDecision> = decisions
        .iter()
        .filter(|d| d.case_id == case_id)
        .cloned()
        .collect();
    match current_decision(&for_case) {
        Some(d) => d.prediction_correct == Some(false) || d.important_evidence_missed == Some(true),
        None => false,
    }
}

/// A mistake counts toward its category iff it is corroborated: a case-scoped
/// mistake needs a genuine analyst correction on that case; a caseless mistake is
/// a standalone analyst-authored correction and counts on its own.
fn counts(m: &MistakeRecord, decisions: &[AnalystDecision]) -> bool {
    match &m.case_id {
        Some(cid) => case_is_corrected(cid, decisions),
        None => true,
    }
}

/// Distinct cases whose CURRENT analyst decision flags `important_evidence_missed`
/// — an unambiguous, structured MissedEvidence corroboration straight from the
/// analyst's normal adjudication (no separately-filed mistake required). `cutoff`
/// bounds the RESOLVED current decision by `created_at` (so an out-of-window
/// decision can't draft a lesson); the full list is still passed to
/// `current_decision` so supersede resolution isn't broken by pre-filtering.
fn missed_evidence_cases(
    decisions: &[AnalystDecision],
    cutoff: Option<DateTime<Utc>>,
) -> BTreeSet<String> {
    let cases: BTreeSet<&str> = decisions.iter().map(|d| d.case_id.as_str()).collect();
    let mut out = BTreeSet::new();
    for cid in cases {
        let for_case: Vec<AnalystDecision> = decisions
            .iter()
            .filter(|d| d.case_id == cid)
            .cloned()
            .collect();
        if let Some(d) = current_decision(&for_case) {
            let in_window = cutoff.is_none_or(|c| d.created_at >= c);
            if d.important_evidence_missed == Some(true) && in_window {
                out.insert(cid.to_string());
            }
        }
    }
    out
}

/// Draft a LessonSet from the analyst's corrections. Pure.
///
/// Corroboration is counted per DISTINCT SOURCE (case, else the record id), never
/// per raw record — so two mistakes filed on one case are one incident, not two.
/// For each category with FROZEN guidance a lesson is drafted once the distinct
/// corroborator count reaches `min_support`, from:
///   - an explicit [`MistakeRecord`] of that category that is corroborated (its
///     case has a genuine correction, or it is a standalone caseless mistake); and
///   - for the unambiguous **MissedEvidence** category ONLY, the analyst's normal
///     adjudication itself: a decision that flags `important_evidence_missed`, and
///     any [`FalseNegativeRecord`] (a missed detection IS missed evidence).
///
/// This closes the loop so an overturn/miss teaches WITHOUT a separately-filed
/// mistake, while the lesson body stays the frozen guidance (never analyst /
/// attacker text) — corroboration decides only WHICH frozen lesson ships.
///
/// `cutoff` (the lookback window's lower bound; `None` = no bound) applies to the
/// decision-sourced MissedEvidence corroboration, so an out-of-window decision
/// can't draft a lesson. Mistakes + false negatives are expected to be
/// pre-filtered to the window by the caller. Pure (the clock is the caller's).
pub fn reflect(
    mistakes: &[MistakeRecord],
    decisions: &[AnalystDecision],
    false_negatives: &[FalseNegativeRecord],
    cutoff: Option<DateTime<Utc>>,
    policy: &ReflectPolicy,
) -> LessonSet {
    let mut lessons: Vec<Lesson> = Vec::new();
    for &cat in ALL_CATEGORIES {
        let Some(guidance) = category_guidance(cat) else {
            continue; // no frozen guidance for this category → no lesson
        };
        // Distinct corroborating sources (deduped by case, else record id).
        let mut sources: BTreeSet<String> = BTreeSet::new();
        for m in mistakes
            .iter()
            .filter(|m| m.category == cat && counts(m, decisions))
        {
            let key = m
                .case_id
                .clone()
                .unwrap_or_else(|| format!("mistake:{}", m.mistake_id));
            sources.insert(key);
        }
        // MissedEvidence is the one category the analyst's structured adjudication
        // corroborates unambiguously — a `prediction_correct=false` decision alone
        // can't tell misinterpreted from wrong-assumption, so those still need an
        // explicitly-categorized mistake.
        if cat == MistakeCategory::MissedEvidence {
            sources.extend(missed_evidence_cases(decisions, cutoff));
            for fnr in false_negatives {
                let key = fnr
                    .case_id
                    .clone()
                    .unwrap_or_else(|| format!("fn:{}", fnr.fn_id));
                sources.insert(key);
            }
        }
        if sources.len() >= policy.min_support {
            lessons.push(Lesson {
                category: cat,
                guidance: guidance.to_string(),
                support: sources.len() as u32,
                source_mistake_ids: sources.into_iter().collect(),
            });
        }
    }
    // Deterministic order; cap to the shared limit.
    lessons.sort_by(|a, b| {
        b.support.cmp(&a.support).then_with(|| {
            garmr_core::category_tag(a.category).cmp(garmr_core::category_tag(b.category))
        })
    });
    lessons.truncate(LESSON_CAPS.max_lessons);
    LessonSet { lessons }
}

/// The fail-closed gate the CLI runs on a drafted set (single-sourced caps).
pub fn validate_reflection(set: &LessonSet) -> Vec<LessonFinding> {
    validate_lesson_set(&set.lessons, LESSON_CAPS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::Disposition;

    fn mistake(id: &str, case_id: Option<&str>, cat: MistakeCategory) -> MistakeRecord {
        MistakeRecord {
            mistake_id: id.into(),
            case_id: case_id.map(|s| s.into()),
            principal: "analyst".into(),
            category: cat,
            narrative: String::new(),
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            audit_id: None,
        }
    }

    fn decision(
        case_id: &str,
        prediction_correct: Option<bool>,
        missed: Option<bool>,
    ) -> AnalystDecision {
        AnalystDecision {
            decision_id: format!("d-{case_id}"),
            case_id: case_id.into(),
            principal: "analyst".into(),
            disposition: Disposition::Malicious,
            severity: 7,
            reason_codes: vec![],
            narrative: String::new(),
            accepted_evidence: vec![],
            rejected_evidence: vec![],
            prediction_correct,
            important_evidence_missed: missed,
            proposed_action_justified: None,
            supersedes: None,
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            audit_id: None,
        }
    }

    /// A genuine correction that also flags missed evidence (the common overturn).
    fn correction(case_id: &str) -> AnalystDecision {
        decision(case_id, Some(false), Some(true))
    }

    fn false_negative(id: &str, case_id: Option<&str>) -> FalseNegativeRecord {
        FalseNegativeRecord {
            fn_id: id.into(),
            case_id: case_id.map(|s| s.into()),
            principal: "analyst".into(),
            discovered_via: "threat hunt".into(),
            disposition: Disposition::Malicious,
            severity: 7,
            narrative: String::new(),
            evidence: vec![],
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            audit_id: None,
        }
    }

    #[test]
    fn corroborated_category_yields_a_lesson() {
        let mistakes = vec![
            mistake("m1", Some("c1"), MistakeCategory::MissedEvidence),
            mistake("m2", Some("c2"), MistakeCategory::MissedEvidence),
        ];
        let decisions = vec![correction("c1"), correction("c2")];
        let set = reflect(&mistakes, &decisions, &[], None, &ReflectPolicy::default());
        assert_eq!(set.lessons.len(), 1);
        assert_eq!(set.lessons[0].category, MistakeCategory::MissedEvidence);
        assert_eq!(set.lessons[0].support, 2);
        assert!(validate_reflection(&set).is_empty());
    }

    #[test]
    fn an_uncorrected_case_mistake_does_not_count() {
        // Two mistakes, but neither case has a genuine analyst correction → below
        // min_support → no lesson (invariant #3: no learning from unadjudicated
        // output).
        let mistakes = vec![
            mistake("m1", Some("c1"), MistakeCategory::MissedEvidence),
            mistake("m2", Some("c2"), MistakeCategory::MissedEvidence),
        ];
        let set = reflect(&mistakes, &[], &[], None, &ReflectPolicy::default());
        assert!(set.lessons.is_empty());
    }

    #[test]
    fn tool_economy_mistakes_never_yield_a_lesson() {
        let mistakes = vec![
            mistake("m1", None, MistakeCategory::UnnecessaryTools),
            mistake("m2", None, MistakeCategory::UnnecessaryTools),
            mistake("m3", None, MistakeCategory::MissingTools),
            mistake("m4", None, MistakeCategory::MissingTools),
        ];
        let set = reflect(&mistakes, &[], &[], None, &ReflectPolicy::default());
        assert!(
            set.lessons.is_empty(),
            "no gate can prove tool-economy lessons preserve recall — none is drafted"
        );
    }

    #[test]
    fn below_min_support_yields_nothing() {
        let mistakes = vec![mistake("m1", None, MistakeCategory::WrongAssumption)];
        let set = reflect(&mistakes, &[], &[], None, &ReflectPolicy::default());
        assert!(set.lessons.is_empty());
    }

    // ---- Phase 13: closing the adjudication → lesson loop ---------------

    #[test]
    fn missed_evidence_decisions_alone_yield_a_lesson() {
        // No separately-filed mistakes — just the analyst's normal adjudication on
        // two distinct cases flagging missed evidence. The loop now closes.
        let decisions = vec![correction("c1"), correction("c2")];
        let set = reflect(&[], &decisions, &[], None, &ReflectPolicy::default());
        assert_eq!(set.lessons.len(), 1);
        assert_eq!(set.lessons[0].category, MistakeCategory::MissedEvidence);
        assert_eq!(set.lessons[0].support, 2);
    }

    #[test]
    fn false_negatives_corroborate_missed_evidence() {
        // One missed-evidence decision + one false negative = two distinct sources.
        let set = reflect(
            &[],
            &[correction("c1")],
            &[false_negative("fn1", Some("c2"))],
            None,
            &ReflectPolicy::default(),
        );
        assert_eq!(set.lessons.len(), 1);
        assert_eq!(set.lessons[0].category, MistakeCategory::MissedEvidence);
        assert_eq!(set.lessons[0].support, 2);
    }

    #[test]
    fn two_signals_on_one_case_count_once() {
        // A mistake AND a missed-evidence decision AND a false negative, all on the
        // SAME case c1 → one distinct incident → below min_support → no lesson.
        let set = reflect(
            &[mistake("m1", Some("c1"), MistakeCategory::MissedEvidence)],
            &[correction("c1")],
            &[false_negative("fn1", Some("c1"))],
            None,
            &ReflectPolicy::default(),
        );
        assert!(
            set.lessons.is_empty(),
            "one case is one incident, not three corroborations"
        );
    }

    #[test]
    fn out_of_window_decisions_do_not_draft_a_lesson() {
        // Two missed-evidence decisions dated at the epoch; a cutoff a day later
        // excludes them, so the decision-sourced corroboration is out of window.
        let decisions = vec![correction("c1"), correction("c2")];
        let cutoff = chrono::DateTime::from_timestamp(86_400, 0).unwrap(); // epoch + 1d
        let windowed = reflect(
            &[],
            &decisions,
            &[],
            Some(cutoff),
            &ReflectPolicy::default(),
        );
        assert!(
            windowed.lessons.is_empty(),
            "out-of-window decisions are excluded"
        );
        // Same decisions with no cutoff DO draft (proves the window is the cause).
        let unbounded = reflect(&[], &decisions, &[], None, &ReflectPolicy::default());
        assert_eq!(unbounded.lessons.len(), 1);
    }

    #[test]
    fn a_wrong_disposition_alone_does_not_synthesize_a_category() {
        // prediction_correct=false but no missed-evidence flag + no filed mistake:
        // misinterpreted-vs-wrong-assumption is ambiguous, so nothing is drafted
        // (only MissedEvidence is auto-corroborated from structured adjudication).
        let decisions = vec![
            decision("c1", Some(false), None),
            decision("c2", Some(false), None),
        ];
        let set = reflect(&[], &decisions, &[], None, &ReflectPolicy::default());
        assert!(set.lessons.is_empty());
    }
}
