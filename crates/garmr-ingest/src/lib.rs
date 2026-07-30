// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-ingest` — normalise log sources into garmr [`Event`]s.
//!
//! Primary path: the native canonical HTTP endpoint (`/ingest/v1/events`) — a
//! vendor-neutral JSON / NDJSON contract any collector that can POST JSON
//! speaks, with no Loki, protobuf, or snappy in the path. Secondary: syslog
//! UDP/TCP for appliances that speak nothing else. A `replay` helper feeds a
//! captured file through the same normalisation for testing.
//!
//! Loki push (`/loki/api/v1/push`) is available only under the `loki-compat`
//! feature, for environments still fanning in through Grafana Alloy's
//! `loki.write`. It is not part of the default build.

pub mod adapter;
pub mod fields;
#[cfg(feature = "flight")]
pub mod flight;
pub mod ioc;
pub mod labels;
#[cfg(feature = "loki-compat")]
pub mod loki;
pub mod native;
pub mod pg;
pub mod server;
pub mod syslog;

pub use adapter::{Adapter, AdapterRegistry};
pub use ioc::{tag_ioc_batch, tag_ioc_batch_opt, IOC_FEED_FIELD};
#[cfg(feature = "loki-compat")]
pub use server::run_loki;
pub use server::{
    run_ingest, run_syslog_tcp, run_syslog_udp, EventSink, IngestAudit, IngestAuditor, IngestBatch,
    IngestSeqObserver,
};

use garmr_core::{Event, Result};

/// Decode a captured file for `garmr replay` / `garmr import`.
///
/// `as_json` selects garmr's canonical event JSON — a top-level array, or
/// newline-delimited event objects (auto-detected from the first byte).
/// Otherwise the body is treated as one syslog line per row.
pub fn replay_bytes(body: &[u8], as_json: bool, default_environment: &str) -> Result<Vec<Event>> {
    if as_json {
        // A leading `[` is a JSON array; anything else is treated as one event
        // object per line (NDJSON), which also covers a single object.
        let is_array = body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[');
        native::decode_events(body, !is_array, default_environment)
    } else {
        // Bulk syslog import: `parse_line` is real per-line CPU (RFC3164/5424
        // parse + an owned `Event`) and independent per line, so a large capture
        // fans the lines across cores (ROOT LAW #0 — znippy gatling, no rayon).
        // `gatling_for_each` returns in index order, so the imported event order
        // matches the file exactly. Below the threshold a serial pass avoids the
        // scoped-thread spawn (mirrors the native NDJSON decode's own fan-out).
        let text = String::from_utf8_lossy(body);
        let lines: Vec<&str> = text.lines().collect();
        let events = if lines.len() >= PARALLEL_LINE_THRESHOLD {
            znippy_zoomies::gatling_forkjoin::gatling_for_each(lines.len(), 0, |i| {
                syslog::parse_line(lines[i], default_environment)
            })
        } else {
            lines
                .iter()
                .map(|l| syslog::parse_line(l, default_environment))
                .collect()
        };
        Ok(events)
    }
}

/// At/above this many lines, a bulk syslog replay fans line-parsing across cores;
/// below it a serial pass is cheaper than the scoped-thread spawn.
const PARALLEL_LINE_THRESHOLD: usize = 4_096;

/// Decode a captured file in a named FORMAT for `garmr replay --format <name>`.
///
/// `json`/`ndjson` and `syslog` use the built-in paths; any other name is
/// resolved against the built-in [`AdapterRegistry`] (e.g. `postgres-csvlog`,
/// `postgres-jsonlog`, `ocsf`, `otel`). This is the offline-import path for
/// PostgreSQL / pgAudit audit files.
pub fn replay_format(body: &[u8], format: &str, default_environment: &str) -> Result<Vec<Event>> {
    match format {
        "json" | "ndjson" | "events" => replay_bytes(body, true, default_environment),
        "syslog" => replay_bytes(body, false, default_environment),
        other => AdapterRegistry::with_builtin().parse(other, body, default_environment),
    }
}

/// The format names `replay_format` accepts, for CLI help / validation.
pub fn replay_formats() -> Vec<String> {
    let mut v = vec!["json".to_string(), "syslog".to_string()];
    v.extend(AdapterRegistry::with_builtin().names());
    v
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    /// A bulk syslog replay past `PARALLEL_LINE_THRESHOLD` must parse to EXACTLY
    /// the serial `parse_line`-per-line result, in file order. Compares the
    /// deterministic parsed fields (not `ts`, whose fallback can be `now()` and so
    /// differ by wall-clock between the two runs) — red the instant the gatling
    /// fan-out reorders or drops a line.
    #[test]
    fn replay_syslog_parallel_matches_serial_in_order() {
        let n = PARALLEL_LINE_THRESHOLD + 500;
        let mut body = String::new();
        for i in 0..n {
            body.push_str(&format!(
                "<34>Oct 11 22:14:{:02} host{} app{}[{}]: message number {} details\n",
                i % 60,
                i % 32,
                i % 7,
                i,
                i
            ));
        }
        let parallel = replay_bytes(body.as_bytes(), false, "prod").unwrap();
        let serial: Vec<Event> = body
            .lines()
            .map(|l| syslog::parse_line(l, "prod"))
            .collect();

        assert!(
            parallel.len() >= PARALLEL_LINE_THRESHOLD,
            "must exercise the fan-out"
        );
        assert_eq!(parallel.len(), serial.len());
        // The deterministic (non-`ts`) parse projection, compared in order.
        let proj = |e: &Event| {
            (
                e.host.clone(),
                e.service.clone(),
                e.source.clone(),
                e.severity.clone(),
                e.log_type.clone(),
                e.message.clone(),
                e.fields.clone(),
            )
        };
        let p: Vec<_> = parallel.iter().map(proj).collect();
        let s: Vec<_> = serial.iter().map(proj).collect();
        assert_eq!(p, s, "parallel replay must equal serial parse, in order");
    }
}
