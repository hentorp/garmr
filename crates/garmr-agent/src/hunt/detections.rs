// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Converting hunt findings into synthetic [`Detection`]s so they flow through
//! the SAME case/dedup/realert/triage path as Sigma and correlation hits — a
//! hunt never acts on its own; it only proposes cases.

use garmr_core::{Detection, Event, HuntReport};

/// Convert a report's findings into synthetic detections for the case
/// machinery: same dedup/realert/triage/Matrix path as Sigma and correlation.
pub fn findings_to_detections(report: &HuntReport) -> Vec<Detection> {
    report
        .findings
        .iter()
        .map(|f| {
            let mut fields = std::collections::BTreeMap::new();
            if let Some(ip) = &f.src_ip {
                fields.insert("src_ip".to_string(), ip.clone());
            }
            fields.insert("hunt_report".to_string(), report.id.clone());
            Detection {
                // Finding-specific dedup identity: without the title hash, two
                // distinct findings on the same host would share a dedup key
                // and the second would be silently swallowed by the realert
                // window. Same title recurring across runs still dedups.
                rule_id: format!("garmr-hunt-{}-{:08x}", report.hunt_id, fnv1a(&f.title)),
                rule_title: format!("Hunt: {}", f.title),
                level: severity_level(f.severity).into(),
                attack: vec![],
                event: Event {
                    ts: report.finished_at,
                    host: f.host.clone().unwrap_or_else(|| "-".to_string()).into(),
                    service: "garmr-hunt".into(),
                    source: "hunt".into(),
                    environment: "hunt".into(),
                    severity: severity_level(f.severity).into(),
                    log_type: "hunt".into(),
                    message: f.evidence.clone(),
                    fields,
                },
                observed_at: report.finished_at,
                realert_secs: None,
            }
        })
        .collect()
}

/// Deterministic 32-bit FNV-1a — a stable fingerprint for dedup keys (the std
/// hasher is not guaranteed stable across Rust versions, and dedup keys are
/// persisted in the suppression table).
fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn severity_level(s: u8) -> &'static str {
    match s {
        0..=2 => "low",
        3..=6 => "medium",
        7..=8 => "high",
        _ => "critical",
    }
}
