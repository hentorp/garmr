// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! A human-approved notification silence (see `garmr-route`).
//!
//! Keyed by Sigma/correlation rule id, optionally scoped to one host. Persisted
//! in the state store so it survives restarts and is auditable; expired entries
//! are pruned on read. Suppresses outbound notifications only — never case
//! creation, triage, or persistence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Silence {
    /// Rule id this silence applies to (exact match).
    pub rule: String,
    /// Optional host scope; `None` silences the rule on every host.
    pub host: Option<String>,
    /// Expiry (UTC). At most 7 days out — enforced at the write path.
    pub until: DateTime<Utc>,
    /// Operator-supplied reason, for the audit trail.
    pub reason: String,
    /// When the silence was created.
    pub created: DateTime<Utc>,
    /// Notifications suppressed by this silence so far.
    pub hits: u64,
}

impl Silence {
    /// Does this silence apply to a notification for `(rule, host)`?
    /// (Expiry is checked by the store's read path, not here.)
    pub fn matches(&self, rule: &str, host: &str) -> bool {
        self.rule == rule && self.host.as_deref().is_none_or(|h| h == host)
    }
}