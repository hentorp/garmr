// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Syslog ingest (RFC5424 / RFC3164) via `syslog_loose` — the tolerant parser
//! that copes with the format chaos real devices emit. The direct path for the
//! router and any appliance that can't run Alloy.

use chrono::{DateTime, Utc};
use garmr_core::Event;
use syslog_loose::{parse_message, ProcId, Protocol, SyslogSeverity, Variant};

use crate::fields;

/// The lower-cased Debug name of a syslog severity, as a `&'static str`.
///
/// This reproduces exactly what `format!("{s:?}").to_lowercase()` used to
/// produce (the `SyslogSeverity` variants are `SEV_EMERG`, `SEV_WARNING`, …, so
/// the stored value has always been `sev_emerg`/`sev_warning`/…) — byte-identical
/// to the old path, but without the per-line `format!` + `to_lowercase` heap
/// allocations. `None` keeps the historical `"info"` default.
fn severity_str(sev: Option<SyslogSeverity>) -> &'static str {
    match sev {
        Some(SyslogSeverity::SEV_EMERG) => "sev_emerg",
        Some(SyslogSeverity::SEV_ALERT) => "sev_alert",
        Some(SyslogSeverity::SEV_CRIT) => "sev_crit",
        Some(SyslogSeverity::SEV_ERR) => "sev_err",
        Some(SyslogSeverity::SEV_WARNING) => "sev_warning",
        Some(SyslogSeverity::SEV_NOTICE) => "sev_notice",
        Some(SyslogSeverity::SEV_INFO) => "sev_info",
        Some(SyslogSeverity::SEV_DEBUG) => "sev_debug",
        None => "info",
    }
}

/// Parse one syslog line into a normalised event. Never fails: an unparseable
/// line still lands as an event with the raw text as the message.
pub fn parse_line(line: &str, default_environment: &str) -> Event {
    // `Either`: try RFC5424 first, fall back to RFC3164 — the tolerant default.
    let msg = parse_message(line, Variant::Either);

    // Intern the low-cardinality labels straight from the parser's borrowed
    // slices — no intermediate `String` per line. `host`/`service`/`severity`
    // repeat heavily across a syslog firehose, so `Label::from(&str)` collapses to
    // an atomic refcount bump after first sight (the allocator-ceiling win the
    // bulk-replay path was measured against).
    let host: garmr_core::Label = msg.hostname.unwrap_or("unknown").into();
    let service: garmr_core::Label = msg.appname.unwrap_or("").into();
    let severity: garmr_core::Label = severity_str(msg.severity).into();
    let log_type = match msg.protocol {
        Protocol::RFC5424(_) => "app",
        Protocol::RFC3164 => "system",
    };
    let ts: DateTime<Utc> = msg
        .timestamp
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let text = msg.msg.to_string();
    let mut fields = fields::extract(&text);
    if let Some(ProcId::PID(pid)) = msg.procid {
        fields.insert("pid".to_string(), pid.to_string());
    }

    Event {
        ts,
        host,
        service,
        source: "syslog".into(),
        environment: default_environment.into(),
        severity,
        log_type: log_type.into(),
        message: text,
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3164() {
        let line =
            "<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root from 10.0.0.9 port 22";
        let e = parse_line(line, "prod");
        assert_eq!(e.host, "myhost");
        assert_eq!(e.service, "sshd");
        assert_eq!(e.src_ip(), Some("10.0.0.9"));
        assert_eq!(e.source, "syslog");
    }
}
