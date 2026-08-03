// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-source state for the monitoring board, and the rules that decide what the
//! board is allowed to claim.
//!
//! A SOC console that renders a green tile from data it never received is worse
//! than one that renders nothing: the operator reads "0 subjects over budget"
//! and moves on, when the truth is "the risk API failed". The old board could do
//! exactly that — an absent audit response defaulted to `verified`, a failed
//! request produced an empty row set, and an empty row set rendered "All clear".
//!
//! So every source carries an explicit [`SourceState`], and the aggregate claims
//! ("All clear", a green metric) are gated on it. Like [`crate::auth`], this
//! module is pure — no `web_sys`, no signals — so the rules are unit-tested on
//! the host target rather than eyeballed in a browser.

/// The state of one data source backing the board.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceState {
    /// No answer yet (first load).
    Loading,
    /// Answered, and the answer is inside the freshness budget.
    Fresh,
    /// Answered, but the data is older than the freshness budget.
    Stale,
    /// 401/403 — the console may not read this source.
    Unauthorized,
    /// 404 or a disabled capability — the source is not present in this deployment.
    Unavailable,
    /// Transport failure or 5xx — the source is present but broken.
    Failed,
}

impl SourceState {
    /// Only a fresh source may contribute to a positive ("all clear", green)
    /// conclusion. Everything else is, at best, unknown.
    pub fn supports_positive_claim(self) -> bool {
        matches!(self, SourceState::Fresh)
    }
    /// True when the operator should be told something is wrong with this source.
    pub fn is_degraded(self) -> bool {
        matches!(
            self,
            SourceState::Stale
                | SourceState::Unauthorized
                | SourceState::Unavailable
                | SourceState::Failed
        )
    }
    /// A short label for the tile / banner. Paired with text, never colour-alone.
    pub fn label(self) -> &'static str {
        match self {
            SourceState::Loading => "loading",
            SourceState::Fresh => "fresh",
            SourceState::Stale => "stale",
            SourceState::Unauthorized => "not authorized",
            SourceState::Unavailable => "unavailable",
            SourceState::Failed => "failed",
        }
    }
    /// The concise recovery action for this state.
    pub fn recovery(self) -> &'static str {
        match self {
            SourceState::Loading => "",
            SourceState::Fresh => "",
            SourceState::Stale => "check the source is still shipping events",
            SourceState::Unauthorized => "authorize as an operator in System › Access",
            SourceState::Unavailable => "enable the capability in System › Setup",
            SourceState::Failed => "retry, then check the garmr service logs",
        }
    }
}

/// Derive a source's state from what the request layer actually observed.
///
/// `err` is the HTTP status of the last failure (0 = transport). `age_secs` is
/// how old the held data is. Note that a refresh over existing data does NOT
/// return to [`SourceState::Loading`] — a monitoring board keeps showing the
/// last good numbers while it refetches, with a separate refreshing indicator.
pub fn derive(
    loading: bool,
    has_data: bool,
    err: Option<u16>,
    age_secs: Option<u64>,
    budget_secs: u64,
) -> SourceState {
    if let Some(status) = err {
        return match status {
            401 | 403 => SourceState::Unauthorized,
            404 => SourceState::Unavailable,
            _ => SourceState::Failed,
        };
    }
    if !has_data {
        // No data and no error: either the first fetch is in flight, or nothing
        // has been requested yet. Both are "we do not know", never "all clear".
        let _ = loading;
        return SourceState::Loading;
    }
    match age_secs {
        Some(age) if age > budget_secs => SourceState::Stale,
        _ => SourceState::Fresh,
    }
}

/// A metric's displayed value. A count is only shown when the source that
/// produced it is fresh — otherwise the tile says "Unknown" rather than a `0`
/// the operator would read as good news.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricValue {
    Known(i64),
    Unknown,
}

impl MetricValue {
    pub fn text(&self) -> String {
        match self {
            MetricValue::Known(n) => n.to_string(),
            MetricValue::Unknown => "Unknown".to_string(),
        }
    }
}

/// The value to render for a count metric backed by `state`.
pub fn metric_value(state: SourceState, count: i64) -> MetricValue {
    if state.supports_positive_claim() {
        MetricValue::Known(count)
    } else {
        MetricValue::Unknown
    }
}

/// The status class for a count metric. A source that is not fresh is never
/// green: an unknown number cannot be reassuring.
///
/// `bad_when_positive` picks the tone for a non-zero count — `"bad"` for things
/// that demand action (needs-human, over budget), `"warn"` for softer signals.
pub fn metric_tone(
    state: SourceState,
    count: i64,
    bad_when_positive: &'static str,
) -> &'static str {
    if !state.supports_positive_claim() {
        return "dim";
    }
    if count > 0 {
        bad_when_positive
    } else {
        "pass"
    }
}

/// Audit-ledger integrity as an honest three-valued answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditIntegrity {
    /// The ledger verified. Only ever returned from a fresh response that said so.
    Verified,
    /// The ledger did not verify — a real integrity failure.
    Failed,
    /// We do not know: the response is missing, failed, unauthorized, or the
    /// field is absent. Never rendered as "verified".
    Unknown,
    /// Audit is switched off in this deployment; there is nothing to verify.
    Disabled,
}

impl AuditIntegrity {
    pub fn text(self) -> &'static str {
        match self {
            AuditIntegrity::Verified => "verified",
            AuditIntegrity::Failed => "FAILED",
            AuditIntegrity::Unknown => "Unknown",
            AuditIntegrity::Disabled => "disabled",
        }
    }
    pub fn tone(self) -> &'static str {
        match self {
            AuditIntegrity::Verified => "pass",
            AuditIntegrity::Failed => "bad",
            AuditIntegrity::Unknown => "dim",
            AuditIntegrity::Disabled => "dim",
        }
    }
}

/// Decide audit integrity from the source state and the response fields.
///
/// This is the fix for the board's worst defect: the old code did
/// `…get("ok").unwrap_or(true)`, so a missing or failed audit response rendered
/// as a green "verified".
pub fn audit_integrity(
    state: SourceState,
    enabled: Option<bool>,
    ok: Option<bool>,
) -> AuditIntegrity {
    if !state.supports_positive_claim() {
        return AuditIntegrity::Unknown;
    }
    match enabled {
        Some(false) => AuditIntegrity::Disabled,
        _ => match ok {
            Some(true) => AuditIntegrity::Verified,
            Some(false) => AuditIntegrity::Failed,
            // Present response, absent field: still unknown. Never assume.
            None => AuditIntegrity::Unknown,
        },
    }
}

/// May the board claim "All clear"?
///
/// Only when every required source completed successfully and is fresh. An empty
/// attention feed is necessary but nowhere near sufficient — that was the bug.
pub fn all_clear_permitted(states: &[SourceState], feed_is_empty: bool) -> bool {
    feed_is_empty && !states.is_empty() && states.iter().all(|s| s.supports_positive_claim())
}

/// The sources that need to be called out in the degraded-data banner, as
/// (name, state) pairs, in the order given.
pub fn degraded<'a>(named: &[(&'a str, SourceState)]) -> Vec<(&'a str, SourceState)> {
    named
        .iter()
        .filter(|(_, s)| s.is_degraded())
        .copied()
        .collect()
}

/// Are any sources still loading (so the board is incomplete rather than wrong)?
pub fn any_loading(states: &[SourceState]) -> bool {
    states.iter().any(|s| matches!(s, SourceState::Loading))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: u64 = 120;

    // ---- derivation ---------------------------------------------------------

    #[test]
    fn errors_map_to_distinct_states() {
        assert_eq!(
            derive(false, false, Some(401), None, BUDGET),
            SourceState::Unauthorized
        );
        assert_eq!(
            derive(false, false, Some(403), None, BUDGET),
            SourceState::Unauthorized
        );
        assert_eq!(
            derive(false, false, Some(404), None, BUDGET),
            SourceState::Unavailable
        );
        assert_eq!(
            derive(false, false, Some(500), None, BUDGET),
            SourceState::Failed
        );
        // 0 = transport failure (offline, DNS, TLS).
        assert_eq!(
            derive(false, false, Some(0), None, BUDGET),
            SourceState::Failed
        );
    }

    #[test]
    fn an_error_wins_over_stale_held_data() {
        // We still hold rows, but the latest refresh failed: the board must say
        // so rather than presenting the old numbers as current.
        assert_eq!(
            derive(false, true, Some(500), Some(5), BUDGET),
            SourceState::Failed
        );
    }

    #[test]
    fn no_data_is_loading_never_fresh() {
        assert_eq!(
            derive(true, false, None, None, BUDGET),
            SourceState::Loading
        );
        assert_eq!(
            derive(false, false, None, None, BUDGET),
            SourceState::Loading
        );
    }

    #[test]
    fn freshness_budget_is_applied() {
        assert_eq!(
            derive(false, true, None, Some(10), BUDGET),
            SourceState::Fresh
        );
        assert_eq!(
            derive(false, true, None, Some(BUDGET), BUDGET),
            SourceState::Fresh
        );
        assert_eq!(
            derive(false, true, None, Some(BUDGET + 1), BUDGET),
            SourceState::Stale
        );
    }

    #[test]
    fn refreshing_over_existing_data_keeps_showing_it() {
        // loading=true with data held stays Fresh — the board does not blank out
        // every poll interval.
        assert_eq!(
            derive(true, true, None, Some(1), BUDGET),
            SourceState::Fresh
        );
    }

    // ---- the central rule: no green from absent data ------------------------

    #[test]
    fn all_clear_requires_every_source_fresh() {
        use SourceState::*;
        assert!(all_clear_permitted(&[Fresh, Fresh, Fresh], true));

        for bad in [Loading, Stale, Unauthorized, Unavailable, Failed] {
            assert!(
                !all_clear_permitted(&[Fresh, bad, Fresh], true),
                "{bad:?} must block an All-clear claim"
            );
        }
    }

    #[test]
    fn all_clear_requires_an_empty_feed_too() {
        assert!(!all_clear_permitted(
            &[SourceState::Fresh, SourceState::Fresh],
            false
        ));
    }

    #[test]
    fn all_clear_is_never_claimed_with_no_sources() {
        assert!(!all_clear_permitted(&[], true));
    }

    #[test]
    fn a_failed_source_never_renders_zero_or_green() {
        for bad in [
            SourceState::Loading,
            SourceState::Stale,
            SourceState::Unauthorized,
            SourceState::Unavailable,
            SourceState::Failed,
        ] {
            assert_eq!(metric_value(bad, 0), MetricValue::Unknown);
            assert_eq!(metric_value(bad, 7), MetricValue::Unknown);
            assert_eq!(
                metric_tone(bad, 0, "bad"),
                "dim",
                "{bad:?} must not render green"
            );
            assert_eq!(metric_value(bad, 0).text(), "Unknown");
        }
    }

    #[test]
    fn a_fresh_source_renders_its_real_count() {
        assert_eq!(metric_value(SourceState::Fresh, 0), MetricValue::Known(0));
        assert_eq!(metric_tone(SourceState::Fresh, 0, "bad"), "pass");
        assert_eq!(metric_tone(SourceState::Fresh, 3, "bad"), "bad");
        assert_eq!(metric_tone(SourceState::Fresh, 3, "warn"), "warn");
    }

    // ---- audit integrity: the fail-open defect ------------------------------

    #[test]
    fn audit_integrity_never_defaults_to_verified() {
        // The exact regression: response absent → the old code said "verified".
        for state in [
            SourceState::Loading,
            SourceState::Failed,
            SourceState::Unauthorized,
            SourceState::Unavailable,
            SourceState::Stale,
        ] {
            assert_eq!(
                audit_integrity(state, Some(true), Some(true)),
                AuditIntegrity::Unknown,
                "{state:?} must not yield Verified"
            );
        }
        // Fresh response but the field is missing: still unknown.
        assert_eq!(
            audit_integrity(SourceState::Fresh, Some(true), None),
            AuditIntegrity::Unknown
        );
    }

    #[test]
    fn audit_integrity_reports_real_answers() {
        assert_eq!(
            audit_integrity(SourceState::Fresh, Some(true), Some(true)),
            AuditIntegrity::Verified
        );
        assert_eq!(
            audit_integrity(SourceState::Fresh, Some(true), Some(false)),
            AuditIntegrity::Failed
        );
        assert_eq!(
            audit_integrity(SourceState::Fresh, Some(false), Some(true)),
            AuditIntegrity::Disabled
        );
    }

    #[test]
    fn unknown_audit_is_not_green() {
        assert_eq!(AuditIntegrity::Unknown.tone(), "dim");
        assert_eq!(AuditIntegrity::Unknown.text(), "Unknown");
        assert_eq!(AuditIntegrity::Failed.tone(), "bad");
        assert_eq!(AuditIntegrity::Verified.tone(), "pass");
    }

    // ---- degraded banner ----------------------------------------------------

    #[test]
    fn degraded_lists_only_broken_sources_with_recovery() {
        let named = [
            ("cases", SourceState::Fresh),
            ("risk", SourceState::Failed),
            ("ingest", SourceState::Unauthorized),
            ("audit", SourceState::Loading),
        ];
        let d = degraded(&named);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].0, "risk");
        assert_eq!(d[1].0, "ingest");
        assert!(!d[0].1.recovery().is_empty());
        assert_eq!(
            d[1].1.recovery(),
            "authorize as an operator in System › Access"
        );
    }

    #[test]
    fn loading_is_incomplete_not_degraded() {
        assert!(!SourceState::Loading.is_degraded());
        assert!(any_loading(&[SourceState::Fresh, SourceState::Loading]));
        assert!(!any_loading(&[SourceState::Fresh, SourceState::Failed]));
    }
}
