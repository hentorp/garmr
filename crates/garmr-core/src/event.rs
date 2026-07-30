// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The normalised event — garmr's single internal representation of a log line.
//!
//! Every ingest path (native `/ingest/v1/events`, syslog, replay, and — under
//! `loki-compat` — Loki push) converges on [`Event`]. The
//! shape mirrors the SOC's enforced 6-label model (host, service, source,
//! environment, severity, log_type) plus the raw line and a small map of
//! ingest-extracted fields (src_ip, user, port, …) that both Sigma field
//! mapping and the agent's tools key off. Nothing here does I/O.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Label;

/// A single normalised log event.
///
/// The six label fields (`host`, `service`, `source`, `environment`, `severity`,
/// `log_type`) are [`Label`]s — interned, `Arc<str>`-backed strings. These are
/// low-cardinality across a firehose (a handful of distinct hosts/severities in
/// millions of events), so interning collapses their per-event heap allocation
/// to an atomic refcount bump, lifting the `malloc`-serialisation ceiling under
/// the gatling fan-out. `Label` derefs to `str` and compares to `&str`, so read
/// sites are unchanged and `"pve".into()` still constructs a field (now dedup'd).
/// `message` and `fields` stay owned — they are high-cardinality (the borrowed
/// `Event<'a>` follow-up covers those).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event time from the source (not receive time) where available.
    pub ts: DateTime<Utc>,
    /// Originating host (the `host` label).
    pub host: Label,
    /// Service / unit (the `service` label), e.g. `sshd`, `kernel`.
    pub service: Label,
    /// Producer class (the `source` label): journald | pve-firewall | docker |
    /// wazuh | syslog | talos | replay.
    pub source: Label,
    /// Deployment environment (the `environment` label): prod | lab | …
    pub environment: Label,
    /// Severity keyword (the `severity` label), lower-cased where possible.
    pub severity: Label,
    /// Coarse classification (the `log_type` label): system | firewall | app |
    /// security_alert | cluster.
    pub log_type: Label,
    /// The verbatim log line — the grep/search surface.
    pub message: String,
    /// Ingest-extracted high-value fields (src_ip, user, port, …). Kept as an
    /// ordered map so serialisation is stable for tests and prompt caching.
    pub fields: BTreeMap<String, String>,
}

impl Event {
    /// Convenience accessor: a field value, if the ingest extractor set it.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// The extracted source IP, if any — the single most-used field across
    /// detection and triage.
    pub fn src_ip(&self) -> Option<&str> {
        self.field("src_ip")
    }
}
