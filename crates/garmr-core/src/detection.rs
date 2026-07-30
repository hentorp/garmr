// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Detection: what a rule produces when it matches an event.
//!
//! A [`Detection`] is the bridge between `garmr-detect` and `garmr-agent`: a
//! rule fired against one event, tagged with enough identity to dedup a burst
//! into a single [`crate::Case`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Event;

/// One rule firing against one event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// The Sigma rule id (stable across restarts — the dedup key component).
    pub rule_id: String,
    /// Human-readable rule title.
    pub rule_title: String,
    /// Rule-declared severity (informational | low | medium | high | critical).
    pub level: String,
    /// MITRE ATT&CK technique tags, if the rule carries them.
    pub attack: Vec<String>,
    /// The event that triggered the match.
    pub event: Event,
    /// When the match was observed.
    pub observed_at: DateTime<Utc>,
    /// Per-detection suppression window override, in seconds. `None` means use
    /// the pipeline's global `realert_secs`. Correlation rules set this from
    /// their own `realert_secs` so a noisy rule can be dampened independently.
    #[serde(default)]
    pub realert_secs: Option<u64>,
}

impl Detection {
    /// The dedup key: a burst of the same rule for the same host + principal is
    /// one incident, not N. The principal is the source IP if present, else the
    /// acting `db_user` (a Postgres access-audit lookup has no src_ip — the
    /// register caseworker IS the principal, so per-staff misuse opens one case
    /// per staffer, not one lumped host case), else the OS `user` (so a
    /// local-only rule firing for two different users opens two cases, not one),
    /// else a fixed `-` sentinel. It is never the host — using the host would
    /// collide with a real `src_ip == host` and conflate unrelated local
    /// incidents.
    pub fn dedup_key(&self) -> String {
        let principal = self
            .event
            .src_ip()
            .or_else(|| self.event.field("db_user"))
            .or_else(|| self.event.field("user"))
            .unwrap_or("-");
        format!("{}|{}|{}", self.rule_id, self.event.host, principal)
    }
}
