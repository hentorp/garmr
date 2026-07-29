// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Threat-hunt types: a hypothesis-driven investigation and its audited
//! outcome. A hunt is the proactive mirror of a triage: instead of a detection
//! opening a case, the analyst (or a schedule) states a hypothesis and the
//! agent tries to find evidence for it. Findings feed the SAME case machinery
//! as Sigma/correlation detections — the hunt itself never acts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::case::TranscriptEntry;

/// How a hunt ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntOutcome {
    /// The hypothesis found no support — the environment looks clean.
    Clean,
    /// One or more findings; see [`HuntReport::findings`].
    Findings,
    /// The agent could not finish (budget, refusal, iteration cap …).
    NeedsHuman,
}

/// One piece of evidence a hunt surfaced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntFinding {
    /// Short title, e.g. "outbound ssh to unknown network from pve".
    pub title: String,
    /// Analyst severity 0–10.
    pub severity: u8,
    /// Grounded evidence in prose (queries + row references).
    pub evidence: String,
    /// Host the finding concerns, when one is identifiable.
    #[serde(default)]
    pub host: Option<String>,
    /// Source IP the finding concerns, when one is identifiable.
    #[serde(default)]
    pub src_ip: Option<String>,
}

/// The persisted, audited record of one hunt run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub id: String,
    /// Scheduled-hunt id, or `"ad-hoc"` for operator-initiated runs.
    pub hunt_id: String,
    pub hypothesis: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub outcome: HuntOutcome,
    pub findings: Vec<HuntFinding>,
    /// Why the agent stopped, when `outcome` is `NeedsHuman`.
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Full tool-call audit trail, same shape as a case transcript.
    pub transcript: Vec<TranscriptEntry>,
    /// USD charged to the daily ledger for this run.
    pub cost_usd: f64,
    /// Model iterations consumed.
    pub iterations: u32,
}