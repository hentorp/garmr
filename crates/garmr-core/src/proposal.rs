// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Detection-rule proposals — the authoring half of propose≠act (M3).
//!
//! The agent DRAFTS a rule (Sigma YAML or correlation TOML) grounded in real
//! log data; the proposal is validated, backtested, and persisted as
//! `pending`. A HUMAN approves it into the ruleset (an authenticated action,
//! same trust model as silences) or rejects it. The agent never edits the
//! rule directories.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What kind of rule a proposal carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// A Sigma YAML rule (per-event, `detect.rules_dir`).
    Sigma,
    /// A correlation TOML rule (windowed SQL, `detect.correlations_dir`).
    Correlation,
}

/// Lifecycle of a proposal. Terminal states are immutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
}

/// A qualitative read on a backtest, used to gate a rule "before enable" — the
/// difference between measuring what a rule *would* have done and deciding
/// whether it is safe to turn on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BacktestHealth {
    /// Fired at a sensible rate over enough data — safe to enable.
    Healthy,
    /// Zero hits over the scanned window. NOT necessarily wrong — a detection
    /// for a threat that simply hasn't happened yet is *supposed* to be quiet —
    /// but the reviewer should know it is unproven against real data.
    Silent,
    /// Fired on a large fraction of everything (sigma) or produced a flood of
    /// rows (correlation): a false-positive cannon that would bury the analyst.
    /// This is the state that blocks drafting and refuses enabling.
    Noisy,
    /// Too little data scanned to judge the firing rate either way.
    Inconclusive,
}

impl BacktestHealth {
    /// Would enabling a rule with this health bury the analyst? The one state
    /// that blocks a draft and refuses an approval.
    pub fn is_noisy(self) -> bool {
        matches!(self, BacktestHealth::Noisy)
    }
}

/// Fraction of scanned events a sigma rule may match before it's "noisy".
pub const NOISY_HIT_RATE: f64 = 0.10;
/// Below this many scanned events, a sigma hit-rate is not trustworthy.
pub const MIN_SCAN_FOR_RATE: u64 = 50;
/// A correlation rule producing at least this many rows in one window is a
/// flood (correlation backtests have no scanned denominator to take a rate of).
pub const NOISY_CORRELATION_ROWS: u64 = 500;

/// What the proposed rule would have done against recent history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Backtest {
    /// Events (sigma) or window rows (correlation) the backtest scanned.
    pub scanned: u64,
    /// Detections/rows the proposed rule produced.
    pub hits: u64,
    /// Up to a handful of matched examples, for the human reviewer.
    #[serde(default)]
    pub samples: Vec<String>,
    /// The backtest window, for context. For correlation rules this is the
    /// rule's OWN window (how it will actually fire), not a fixed span.
    pub window_hours: u32,
    /// The scan hit its event cap — hit counts cover the newest slice only,
    /// not the whole window.
    #[serde(default)]
    pub scan_capped: bool,
}

impl Backtest {
    /// The sigma hit rate (hits / scanned), or `None` for a correlation
    /// backtest (which has no scanned denominator).
    pub fn hit_rate(&self) -> Option<f64> {
        (self.scanned > 0).then(|| self.hits as f64 / self.scanned as f64)
    }

    /// Classify the backtest for enable-gating. See [`BacktestHealth`].
    pub fn health(&self) -> BacktestHealth {
        // Correlation backtests report `scanned == 0` (rows-returned has no
        // "examined" denominator) — judge them on absolute firing volume.
        if self.scanned == 0 {
            return if self.hits == 0 {
                BacktestHealth::Silent
            } else if self.hits >= NOISY_CORRELATION_ROWS {
                BacktestHealth::Noisy
            } else {
                BacktestHealth::Healthy
            };
        }
        if self.hits == 0 {
            return BacktestHealth::Silent;
        }
        if self.scanned < MIN_SCAN_FOR_RATE {
            return BacktestHealth::Inconclusive;
        }
        match self.hit_rate() {
            Some(rate) if rate >= NOISY_HIT_RATE => BacktestHealth::Noisy,
            _ => BacktestHealth::Healthy,
        }
    }

    /// One-line human/model summary including the health verdict.
    pub fn describe(&self) -> String {
        let capped = if self.scan_capped {
            " (scan capped)"
        } else {
            ""
        };
        match self.health() {
            BacktestHealth::Healthy => match self.hit_rate() {
                Some(r) => format!(
                    "healthy: {} hits of {} scanned ({:.1}%) over {}h{capped}",
                    self.hits, self.scanned, r * 100.0, self.window_hours
                ),
                None => format!(
                    "healthy: {} hits over the {}h window{capped}",
                    self.hits, self.window_hours
                ),
            },
            BacktestHealth::Silent => format!(
                "silent: 0 hits over {} scanned events ({}h){capped} — unproven against real data (ok for a rare threat rule)",
                self.scanned, self.window_hours
            ),
            BacktestHealth::Noisy => match self.hit_rate() {
                Some(r) => format!(
                    "NOISY: {} hits of {} scanned ({:.1}%) — would bury the analyst",
                    self.hits, self.scanned, r * 100.0
                ),
                None => format!(
                    "NOISY: {} firings in a {}h window — would bury the analyst",
                    self.hits, self.window_hours
                ),
            },
            BacktestHealth::Inconclusive => format!(
                "insufficient data: only {} events scanned — cannot judge the hit rate",
                self.scanned
            ),
        }
    }
}

/// A persisted rule proposal with its audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProposal {
    pub id: String,
    pub kind: ProposalKind,
    /// Human-readable title (also used in the rule file name).
    pub title: String,
    /// The agent's grounded motivation: what pattern, what evidence.
    pub rationale: String,
    /// The full rule text (YAML or TOML) exactly as it would land on disk.
    pub rule_body: String,
    /// What the operator asked for (the authoring instruction).
    pub request: String,
    pub backtest: Backtest,
    pub status: ProposalStatus,
    pub created_at: DateTime<Utc>,
    /// Set when approved/rejected.
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    /// Reviewer's reason (rejections) or target path (approvals).
    #[serde(default)]
    pub decision_note: Option<String>,
    /// USD charged to the daily ledger for drafting this proposal.
    pub cost_usd: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bt(scanned: u64, hits: u64) -> Backtest {
        Backtest {
            scanned,
            hits,
            ..Default::default()
        }
    }

    #[test]
    fn health_classifies_sigma_backtests() {
        // Enough data, low rate → healthy.
        assert_eq!(bt(1000, 5).health(), BacktestHealth::Healthy);
        // Enough data, high rate → noisy (would flood).
        assert_eq!(bt(1000, 300).health(), BacktestHealth::Noisy);
        assert!(bt(1000, 300).health().is_noisy());
        // Zero hits → silent (unproven, but allowed — rare threats are quiet).
        assert_eq!(bt(1000, 0).health(), BacktestHealth::Silent);
        assert!(!bt(1000, 0).health().is_noisy());
        // Too few events to judge a rate → inconclusive, even at 100%.
        assert_eq!(bt(3, 3).health(), BacktestHealth::Inconclusive);
        assert!(!bt(3, 3).health().is_noisy());
    }

    #[test]
    fn health_classifies_correlation_backtests() {
        // Correlation backtests report scanned == 0.
        assert_eq!(bt(0, 0).health(), BacktestHealth::Silent);
        assert_eq!(bt(0, 10).health(), BacktestHealth::Healthy);
        assert_eq!(
            bt(0, NOISY_CORRELATION_ROWS).health(),
            BacktestHealth::Noisy
        );
    }

    #[test]
    fn hit_rate_is_none_for_correlation() {
        assert_eq!(bt(0, 10).hit_rate(), None);
        assert_eq!(bt(100, 10).hit_rate(), Some(0.1));
    }

    #[test]
    fn noisy_boundary_is_inclusive() {
        // Exactly at the threshold counts as noisy.
        let at = bt(100, (100.0 * NOISY_HIT_RATE) as u64);
        assert_eq!(at.health(), BacktestHealth::Noisy);
    }
}