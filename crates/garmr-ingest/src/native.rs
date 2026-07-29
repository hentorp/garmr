// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Native, vendor-neutral canonical event ingestion.
//!
//! garmr's own ingest contract, independent of any log vendor: a source POSTs
//! canonical events to `/ingest/v1/events` as a JSON array (or a single object),
//! or as newline-delimited JSON (`application/x-ndjson`). Every field maps 1:1
//! onto [`Event`]. Labels are optional and take the same defaults the label
//! normaliser applies; `fields` are the ingest-extracted high-value keys —
//! supplied by the sender, or derived from the message via [`fields::extract`]
//! when omitted, so detection keeps working for senders that ship only a raw
//! line.
//!
//! This replaces the Loki push protocol as garmr's primary ingest. Any collector
//! that can POST JSON (Vector, Fluent Bit, a cron job, `curl`) speaks it with no
//! Loki, protobuf, or snappy in the path.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use garmr_core::{Error, Event, Result};
use serde::Deserialize;

use crate::fields;

/// Maximum raw request body accepted on the native ingest path (8 MiB). The
/// axum route SHOULD also cap the body (see the ingest router), but this is the
/// authoritative, transport-independent guard: `decode_events` refuses a body
/// larger than this before parsing, so an oversized payload can never be walked.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of events accepted in a single request. A batch larger than
/// this is rejected wholesale rather than partially ingested.
pub const MAX_EVENTS_PER_REQUEST: usize = 50_000;
/// Maximum byte length of any single `fields` value.
pub const MAX_FIELD_VALUE_BYTES: usize = 65_536;
/// Maximum byte length of a single event `message`.
pub const MAX_MESSAGE_BYTES: usize = 262_144;

/// One canonical event on the wire. Strictly typed — `deny_unknown_fields` makes
/// a malformed or misdirected payload fail loudly rather than silently drop the
/// unrecognised parts. All labels are optional and fall back to the normaliser's
/// defaults; only `message` is required.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    /// Source event time. Defaults to receive time when omitted.
    #[serde(default)]
    ts: Option<DateTime<Utc>>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    log_type: Option<String>,
    /// The log line. Required.
    message: String,
    /// Pre-extracted high-value fields. When omitted, they are derived from
    /// `message` so a sender can ship just a raw line.
    #[serde(default)]
    fields: Option<BTreeMap<String, String>>,
}

impl WireEvent {
    fn into_event(self, default_environment: &str) -> Event {
        // Sender-supplied fields win; otherwise extract from the message so a
        // raw line still yields src_ip/user/port for detection and triage. This
        // mirrors `labels::to_event` so an event looks identical regardless of
        // whether it arrived native or (in compat mode) via Loki.
        let fields = self
            .fields
            .unwrap_or_else(|| fields::extract(&self.message));
        Event {
            ts: self.ts.unwrap_or_else(Utc::now),
            host: self.host.unwrap_or_else(|| "unknown".to_string()).into(),
            service: self.service.unwrap_or_default().into(),
            source: self.source.unwrap_or_else(|| "native".to_string()).into(),
            environment: self
                .environment
                .unwrap_or_else(|| default_environment.to_string())
                .into(),
            severity: self.severity.unwrap_or_else(|| "info".to_string()).into(),
            log_type: self.log_type.unwrap_or_else(|| "app".to_string()).into(),
            message: self.message,
            fields,
        }
    }
}

/// First non-whitespace byte of `body`, if any.
fn first_nonspace(body: &[u8]) -> Option<u8> {
    body.iter().copied().find(|b| !b.is_ascii_whitespace())
}

/// Decode a native ingest body into events.
///
/// `ndjson` selects newline-delimited JSON — one event object per line, blank
/// lines skipped. Otherwise the body is a JSON array of events; a single JSON
/// object is also accepted for convenience.
pub fn decode_events(body: &[u8], ndjson: bool, default_environment: &str) -> Result<Vec<Event>> {
    // Fail-closed body cap: refuse an oversized payload before parsing so a giant
    // request is never walked. Transport-independent; the axum route caps too.
    if body.len() > MAX_BODY_BYTES {
        return Err(Error::Ingest(format!(
            "ingest body too large: {} bytes exceeds the {} byte limit",
            body.len(),
            MAX_BODY_BYTES
        )));
    }
    let events = decode_events_inner(body, ndjson, default_environment)?;
    enforce_event_limits(&events)?;
    Ok(events)
}

/// Per-batch guards, checked after decode: bound the event count and the size of
/// each `message` / `fields` value. Rejects the whole batch (fail-closed) so an
/// abusive request never lands partially.
fn enforce_event_limits(events: &[Event]) -> Result<()> {
    if events.len() > MAX_EVENTS_PER_REQUEST {
        return Err(Error::Ingest(format!(
            "too many events in one request: {} exceeds the {} event limit",
            events.len(),
            MAX_EVENTS_PER_REQUEST
        )));
    }
    for ev in events {
        if ev.message.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Ingest(format!(
                "event message too large: {} bytes exceeds the {} byte limit",
                ev.message.len(),
                MAX_MESSAGE_BYTES
            )));
        }
        for (k, v) in &ev.fields {
            if v.len() > MAX_FIELD_VALUE_BYTES {
                return Err(Error::Ingest(format!(
                    "field '{k}' value too large: {} bytes exceeds the {} byte limit",
                    v.len(),
                    MAX_FIELD_VALUE_BYTES
                )));
            }
        }
    }
    Ok(())
}

fn decode_events_inner(body: &[u8], ndjson: bool, default_environment: &str) -> Result<Vec<Event>> {
    if ndjson {
        let text =
            std::str::from_utf8(body).map_err(|e| Error::Ingest(format!("ndjson utf8: {e}")))?;
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let wire: WireEvent = serde_json::from_str(line)
                .map_err(|e| Error::Ingest(format!("ndjson line {}: {e}", i + 1)))?;
            out.push(wire.into_event(default_environment));
        }
        Ok(out)
    } else {
        // A JSON array of events, or a single event object.
        let wires: Vec<WireEvent> = if first_nonspace(body) == Some(b'[') {
            serde_json::from_slice(body).map_err(|e| Error::Ingest(format!("json decode: {e}")))?
        } else {
            vec![serde_json::from_slice(body)
                .map_err(|e| Error::Ingest(format!("json decode: {e}")))?]
        };
        Ok(wires
            .into_iter()
            .map(|w| w.into_event(default_environment))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_json_array_and_extracts_fields() {
        let body = br#"[
            {"host":"pve","service":"sshd","source":"journald",
             "message":"Failed password for root from 10.0.0.9 port 22 ssh2"}
        ]"#;
        let events = decode_events(body, false, "prod").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, "pve");
        assert_eq!(events[0].service, "sshd");
        // fields not supplied → derived from the message.
        assert_eq!(events[0].src_ip(), Some("10.0.0.9"));
        // environment not supplied → default.
        assert_eq!(events[0].environment, "prod");
    }

    #[test]
    fn accepts_single_object() {
        let body = br#"{"message":"hello"}"#;
        let events = decode_events(body, false, "lab").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "hello");
        assert_eq!(events[0].source, "native");
        assert_eq!(events[0].log_type, "app");
        assert_eq!(events[0].environment, "lab");
    }

    #[test]
    fn decodes_ndjson_skipping_blanks() {
        let body = b"{\"message\":\"a\",\"host\":\"h1\"}\n\n{\"message\":\"b\",\"host\":\"h2\"}\n";
        let events = decode_events(body, true, "prod").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].host, "h1");
        assert_eq!(events[1].host, "h2");
    }

    #[test]
    fn sender_supplied_fields_win() {
        let body = br#"{"message":"anything","fields":{"src_ip":"1.2.3.4","user":"root"}}"#;
        let events = decode_events(body, false, "prod").unwrap();
        assert_eq!(events[0].src_ip(), Some("1.2.3.4"));
        assert_eq!(events[0].field("user"), Some("root"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let body = br#"{"message":"x","bogus":1}"#;
        assert!(decode_events(body, false, "prod").is_err());
    }

    #[test]
    fn missing_message_is_rejected() {
        let body = br#"{"host":"h1"}"#;
        assert!(decode_events(body, false, "prod").is_err());
    }

    #[test]
    fn accepts_normal_batch_within_limits() {
        // A modest, in-limit batch decodes unchanged.
        let mut body = String::from("[");
        for i in 0..10 {
            if i > 0 {
                body.push(',');
            }
            body.push_str(&format!(r#"{{"message":"line {i}","host":"h{i}"}}"#));
        }
        body.push(']');
        let events = decode_events(body.as_bytes(), false, "prod").unwrap();
        assert_eq!(events.len(), 10);
        assert_eq!(events[0].message, "line 0");
    }

    #[test]
    fn rejects_too_many_events() {
        // Build one more than MAX_EVENTS_PER_REQUEST tiny ndjson lines — cheap to
        // construct and stays well under MAX_BODY_BYTES.
        let mut body = String::with_capacity(MAX_EVENTS_PER_REQUEST * 16);
        for _ in 0..(MAX_EVENTS_PER_REQUEST + 1) {
            body.push_str("{\"message\":\"x\"}\n");
        }
        assert!(
            body.len() <= MAX_BODY_BYTES,
            "test body must fit the body cap"
        );
        let err = decode_events(body.as_bytes(), true, "prod").unwrap_err();
        assert!(
            err.to_string().contains("too many events"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_over_long_message() {
        let big = "m".repeat(MAX_MESSAGE_BYTES + 1);
        let body = format!(r#"{{"message":"{big}"}}"#);
        let err = decode_events(body.as_bytes(), false, "prod").unwrap_err();
        assert!(
            err.to_string().contains("message too large"),
            "unexpected error: {err}"
        );
        // A message exactly at the limit is still accepted.
        let ok = "m".repeat(MAX_MESSAGE_BYTES);
        let body = format!(r#"{{"message":"{ok}"}}"#);
        assert!(decode_events(body.as_bytes(), false, "prod").is_ok());
    }

    #[test]
    fn rejects_over_long_field_value() {
        let big = "v".repeat(MAX_FIELD_VALUE_BYTES + 1);
        let body = format!(r#"{{"message":"x","fields":{{"blob":"{big}"}}}}"#);
        let err = decode_events(body.as_bytes(), false, "prod").unwrap_err();
        assert!(
            err.to_string().contains("value too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_over_large_body() {
        // A body over MAX_BODY_BYTES is refused before parsing.
        let body = vec![b' '; MAX_BODY_BYTES + 1];
        let err = decode_events(&body, false, "prod").unwrap_err();
        assert!(
            err.to_string().contains("body too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn honours_explicit_timestamp() {
        let body = br#"{"message":"x","ts":"2026-07-23T19:59:58.123Z"}"#;
        let events = decode_events(body, false, "prod").unwrap();
        assert_eq!(
            events[0]
                .ts
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2026-07-23T19:59:58.123Z"
        );
    }
}