// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Parsing the Loki label string and mapping the enforced 6-label model onto a
//! garmr [`Event`].
//!
//! Loki carries labels as a Prometheus-style string, e.g.
//! `{host="pve", source="journald", log_type="system", severity="info"}`.
//! garmr honours the same allowlist the SOC's Alloy config enforces
//! (host, service, source, environment, severity, log_type) and ignores the
//! rest.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use garmr_core::Event;

use crate::fields;

/// Parse a Loki label string `{k="v", k2="v2"}` into a map.
pub fn parse_label_string(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let inner = s.trim().trim_start_matches('{').trim_end_matches('}');
    for pair in split_top_level(inner) {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim().trim_matches('"');
        if !k.is_empty() {
            out.insert(k.to_string(), unescape(v));
        }
    }
    out
}

/// Split on commas that are not inside a quoted value.
fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in s.chars() {
        match ch {
            '\\' if in_quotes && !escaped => {
                escaped = true;
                cur.push(ch);
            }
            '"' if !escaped => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => {
                escaped = false;
                cur.push(ch);
            }
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

fn unescape(v: &str) -> String {
    v.replace("\\\"", "\"")
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
}

/// Build a normalised [`Event`] from labels + a raw line + a timestamp.
///
/// Missing labels get sensible defaults so a sparse or non-conforming stream
/// still lands as a usable event rather than being dropped.
pub fn to_event(
    labels: &BTreeMap<String, String>,
    line: &str,
    ts: DateTime<Utc>,
    default_environment: &str,
) -> Event {
    let get = |k: &str| labels.get(k).cloned();
    Event {
        ts,
        host: get("host").unwrap_or_else(|| "unknown".to_string()).into(),
        service: get("service").unwrap_or_default().into(),
        source: get("source").unwrap_or_else(|| "loki".to_string()).into(),
        environment: get("environment")
            .unwrap_or_else(|| default_environment.to_string())
            .into(),
        severity: get("severity").unwrap_or_else(|| "info".to_string()).into(),
        log_type: get("log_type").unwrap_or_else(|| "app".to_string()).into(),
        message: line.to_string(),
        fields: fields::extract(line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_label_string() {
        let m = parse_label_string(r#"{host="pve", source="journald", service="sshd"}"#);
        assert_eq!(m.get("host").map(String::as_str), Some("pve"));
        assert_eq!(m.get("source").map(String::as_str), Some("journald"));
        assert_eq!(m.get("service").map(String::as_str), Some("sshd"));
    }

    #[test]
    fn defaults_fill_missing_labels() {
        let m = parse_label_string(r#"{host="h1"}"#);
        let e = to_event(&m, "hello", Utc::now(), "prod");
        assert_eq!(e.host, "h1");
        assert_eq!(e.environment, "prod");
        assert_eq!(e.source, "loki");
    }
}
