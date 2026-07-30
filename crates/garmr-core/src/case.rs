// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Case + verdict: the unit of triage and its outcome.
//!
//! A [`Case`] opens when a (deduped) detection needs investigation. The agent
//! drives it through the [`CaseState`] machine and records a [`Verdict`]. The
//! full tool transcript is kept append-only for audit — the same guarantee the
//! Hermes APPROVAL_FLOW design requires before any action boundary is crossed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Detection;

/// Lifecycle of a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseState {
    /// Just opened, not yet picked up by the agent.
    New,
    /// Agent is running its tool loop.
    Investigating,
    /// Agent produced a verdict.
    Triaged,
    /// Posted to the alerts room (severity over threshold or malicious).
    Escalated,
    /// Closed (benign / resolved).
    Closed,
    /// Budget exhausted or agent unavailable — awaiting a human.
    NeedsHuman,
}

/// A disposition — the security judgement of a case. Used by the agent's
/// prediction, a human analyst's decision, and an incident outcome alike (Phase
/// 3 keeps them as distinct records; the shared vocabulary is this enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Benign,
    Suspicious,
    Malicious,
    /// The safe default: unresolved, needs a human.
    #[default]
    NeedsHuman,
}

/// One step in the agent's investigation — recorded verbatim for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub at: DateTime<Utc>,
    /// Tool name, or `assistant` / `system` for model turns.
    pub actor: String,
    /// Tool input or model text, serialised.
    pub detail: String,
}

/// The agent's conclusion for a case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub disposition: Disposition,
    /// Analyst severity 0–10 (independent of the rule's declared level).
    pub severity: u8,
    /// Confidence 0.0–1.0.
    pub confidence: f32,
    /// Grounded rationale in prose.
    pub rationale: String,
    /// A proposed remediation the agent may *suggest* but never execute
    /// (capability separation — see APPROVAL_FLOW). `None` if no action advised.
    pub proposed_action: Option<String>,
}

/// A triage case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    /// The stable dedup key (rule|host|ip) this case collapses.
    pub dedup_key: String,
    pub state: CaseState,
    /// The detections folded into this case (first triggers investigation;
    /// repeats bump `event_count`).
    pub trigger: Detection,
    pub event_count: u64,
    pub opened_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub transcript: Vec<TranscriptEntry>,
    pub verdict: Option<Verdict>,
}

impl Case {
    /// Open a fresh case from the first detection of a burst.
    pub fn open(detection: Detection) -> Self {
        let now = detection.observed_at;
        Self {
            id: Uuid::new_v4().to_string(),
            dedup_key: detection.dedup_key(),
            state: CaseState::New,
            trigger: detection,
            event_count: 1,
            opened_at: now,
            updated_at: now,
            transcript: Vec::new(),
            verdict: None,
        }
    }

    /// Fold a repeat detection (same dedup key) into this case.
    pub fn bump(&mut self, at: DateTime<Utc>) {
        self.event_count += 1;
        self.updated_at = at;
    }

    /// Append an audit-trail entry.
    pub fn record(
        &mut self,
        actor: impl Into<String>,
        detail: impl Into<String>,
        at: DateTime<Utc>,
    ) {
        self.transcript.push(TranscriptEntry {
            at,
            actor: actor.into(),
            detail: detail.into(),
        });
        self.updated_at = at;
    }
}
