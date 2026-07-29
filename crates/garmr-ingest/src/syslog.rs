// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Syslog ingest (RFC5424 / RFC3164) via `syslog_loose` — the tolerant parser
//! that copes with the format chaos real devices emit. The direct path for the
//! router and any appliance that can't run Alloy.

use chrono::{DateTime, Utc};
use garmr_core::Event;
use syslog_loose::{parse_message, ProcId, Protocol, Variant};

use crate::fields;

/// Parse one syslog line into a normalised event. Never fails: an unparseable
/// line still lands as an event with the raw text as the message.
pub fn parse_line(line: &str, default_environment: &str) -> Event {
    // `Either`: try RFC5424 first, fall back to RFC3164 — the tolerant default.
    let msg = parse_message(line, Variant::Either);

    let host = msg
        .hostname
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let service = msg.appname.map(str::to_string).unwrap_or_default();
    let severity = msg
        .severity
        .map(|s| format!("{s:?}").to_lowercase())
        .unwrap_or_else(|| "info".to_string());
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
        host: host.into(),
        service: service.into(),
        source: "syslog".into(),
        environment: default_environment.into(),
        severity: severity.into(),
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