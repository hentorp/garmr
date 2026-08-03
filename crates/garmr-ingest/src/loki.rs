// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Loki push protocol decoding (opt-in `loki-compat` feature).
//!
//! The compatibility path for environments still fanning in through Grafana
//! Alloy's `loki.write`, which POSTs snappy-block-compressed protobuf to
//! `/loki/api/v1/push`. We decode that wire format (the one Alloy actually
//! emits) and also accept the JSON body used by `curl`, tests, and
//! `garmr replay`. Both paths converge on [`Event`]s. The native
//! `/ingest/v1/events` endpoint is garmr's primary ingest; this module is not
//! part of the default build.
//!
//! A stream whose `source` label names a PostgreSQL adapter
//! (`postgres-csvlog` / `postgres-jsonlog`) is newline-joined and parsed
//! through that adapter — reconstructing multiline csvlog records Alloy ships
//! as separate values — while every other source takes the generic per-entry
//! label classifier.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use garmr_core::{Error, Event, Result};
use prost::Message;

use crate::labels;

/// Process-wide registry of the built-in source adapters, so a Loki stream can
/// be parsed live by the same adapter the offline `replay --format` path uses.
static ADAPTERS: std::sync::LazyLock<crate::adapter::AdapterRegistry> =
    std::sync::LazyLock::new(crate::adapter::AdapterRegistry::with_builtin);

/// Turn one Loki stream (labels + timestamped entry lines) into events.
///
/// When the stream's `source` label names a **PostgreSQL** adapter
/// (`postgres-csvlog` / `postgres-jsonlog`), the whole push's lines are joined
/// with `\n` and parsed through that adapter — reconstructing multiline csvlog
/// records that Alloy delivers as separate values, and giving the live firehose
/// the same rich parsing (canonical actor/object/statement fields, SQL
/// fingerprint) as the offline path. A `host` stream label overrides the
/// adapter's default host (csvlog carries none). On a parse error we log and
/// fall through to the generic classifier.
///
/// Routing is deliberately restricted to the line-oriented pg formats: the JSON
/// adapters (ocsf/otel) are whole-document-per-line and would be corrupted by a
/// newline-join, so they are NOT auto-routed here. Every other source — the
/// firehose's journald / kunai / pve-firewall / syslog — takes the generic
/// per-entry classifier path, byte-identical to before adapters existed.
fn stream_to_events(
    labels: &BTreeMap<String, String>,
    entries: &[(DateTime<Utc>, String)],
    default_environment: &str,
) -> Vec<Event> {
    let source = labels.get("source").map(String::as_str).unwrap_or("");
    if matches!(source, "postgres-csvlog" | "postgres-jsonlog") && ADAPTERS.get(source).is_some() {
        let blob = entries
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        match ADAPTERS.parse(source, blob.as_bytes(), default_environment) {
            Ok(mut events) => {
                if let Some(host) = labels.get("host") {
                    for ev in &mut events {
                        ev.host = host.clone().into();
                    }
                }
                return events;
            }
            Err(e) => tracing::warn!(
                source = %source,
                error = %e,
                "pg adapter parse failed; falling back to raw-line classifier"
            ),
        }
    }
    entries
        .iter()
        .map(|(ts, line)| labels::to_event(labels, line, *ts, default_environment))
        .collect()
}

// ---- Hand-defined Loki push protobuf (logproto.proto subset) ----------------
// We only need labels + timestamp + line; structured metadata and the stream
// hash are ignored. Defining the messages here avoids a protoc/build.rs step.

#[derive(Clone, PartialEq, Message)]
struct PushRequest {
    #[prost(message, repeated, tag = "1")]
    streams: Vec<StreamAdapter>,
}

#[derive(Clone, PartialEq, Message)]
struct StreamAdapter {
    #[prost(string, tag = "1")]
    labels: String,
    #[prost(message, repeated, tag = "2")]
    entries: Vec<EntryAdapter>,
}

#[derive(Clone, PartialEq, Message)]
struct EntryAdapter {
    #[prost(message, optional, tag = "1")]
    timestamp: Option<Timestamp>,
    #[prost(string, tag = "2")]
    line: String,
}

/// `google.protobuf.Timestamp`.
#[derive(Clone, PartialEq, Message)]
struct Timestamp {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

fn ts_to_utc(ts: &Option<Timestamp>) -> DateTime<Utc> {
    match ts {
        Some(t) => Utc
            .timestamp_opt(t.seconds, t.nanos as u32)
            .single()
            .unwrap_or_else(Utc::now),
        None => Utc::now(),
    }
}

/// Decode a snappy-block-compressed protobuf push body into events.
pub fn decode_protobuf(body: &[u8], default_environment: &str) -> Result<Vec<Event>> {
    let raw = snap::raw::Decoder::new()
        .decompress_vec(body)
        .map_err(|e| Error::Ingest(format!("snappy decompress: {e}")))?;
    let req = PushRequest::decode(raw.as_slice())
        .map_err(|e| Error::Ingest(format!("protobuf decode: {e}")))?;
    Ok(streams_to_events(&req, default_environment))
}

fn streams_to_events(req: &PushRequest, default_environment: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for s in &req.streams {
        let labels = labels::parse_label_string(&s.labels);
        let entries: Vec<(DateTime<Utc>, String)> = s
            .entries
            .iter()
            .map(|e| (ts_to_utc(&e.timestamp), e.line.clone()))
            .collect();
        out.extend(stream_to_events(&labels, &entries, default_environment));
    }
    out
}

// ---- JSON push body ---------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct JsonPush {
    pub streams: Vec<JsonStream>,
}

#[derive(serde::Deserialize)]
pub struct JsonStream {
    pub stream: std::collections::BTreeMap<String, String>,
    /// Each value is `[ "<unix_nanos>", "<line>" ]` (metadata object ignored).
    pub values: Vec<Vec<String>>,
}

/// Decode a JSON push body into events.
pub fn decode_json(body: &[u8], default_environment: &str) -> Result<Vec<Event>> {
    let push: JsonPush =
        serde_json::from_slice(body).map_err(|e| Error::Ingest(format!("json decode: {e}")))?;
    let mut out = Vec::new();
    for s in push.streams {
        let mut entries: Vec<(DateTime<Utc>, String)> = Vec::new();
        for v in s.values {
            let (ts, line) = match v.as_slice() {
                [ns, line, ..] => (parse_nanos(ns), line.clone()),
                [line] => (Utc::now(), line.clone()),
                _ => continue,
            };
            entries.push((ts, line));
        }
        out.extend(stream_to_events(&s.stream, &entries, default_environment));
    }
    Ok(out)
}

fn parse_nanos(s: &str) -> DateTime<Utc> {
    s.parse::<i64>()
        .ok()
        .and_then(|ns| {
            Utc.timestamp_opt(ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
                .single()
        })
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_json_push() {
        let body = br#"{"streams":[{"stream":{"host":"pve","source":"journald","service":"sshd"},
            "values":[["1720000000000000000","Failed password for root from 10.0.0.9 port 22 ssh2"]]}]}"#;
        let events = decode_json(body, "prod").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, "pve");
        assert_eq!(events[0].service, "sshd");
        assert_eq!(events[0].src_ip(), Some("10.0.0.9"));
    }

    #[test]
    fn protobuf_roundtrip() {
        let req = PushRequest {
            streams: vec![StreamAdapter {
                labels: r#"{host="h", source="journald"}"#.to_string(),
                entries: vec![EntryAdapter {
                    timestamp: Some(Timestamp {
                        seconds: 1_720_000_000,
                        nanos: 0,
                    }),
                    line: "hello from 1.2.3.4".to_string(),
                }],
            }],
        };
        let proto = req.encode_to_vec();
        let compressed = snap::raw::Encoder::new().compress_vec(&proto).unwrap();
        let events = decode_protobuf(&compressed, "prod").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, "h");
        assert_eq!(events[0].src_ip(), Some("1.2.3.4"));
    }

    // ---- source-adapter routing (live pg ingest) ---------------------------

    /// A 26-column PostgreSQL csvlog line (mirrors the pg::tests helper); the
    /// message + application columns are quoted since they can contain commas.
    #[allow(clippy::too_many_arguments)]
    fn csvline(
        user: &str,
        db: &str,
        conn: &str,
        tag: &str,
        sev: &str,
        state: &str,
        message: &str,
        app: &str,
    ) -> String {
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        [
            "2024-06-01 12:00:00.123 UTC".to_string(),
            q(user),
            q(db),
            "4711".to_string(),
            q(conn),
            q("6650abcd.1"),
            "1".to_string(),
            q(tag),
            "2024-06-01 12:00:00 UTC".to_string(),
            q("3/15"),
            "0".to_string(),
            q(sev),
            q(state),
            q(message),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            q("auth.c:1"),
            q(app),
            q("client backend"),
            String::new(),
            String::new(),
        ]
        .join(",")
    }

    fn push_body(stream: serde_json::Value, values: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"streams":[{"stream":stream,"values":values}]}))
            .unwrap()
    }

    #[test]
    fn json_push_routes_pg_csvlog_source_through_adapter() {
        let msg = "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.persons,\
                   SELECT pnr FROM public.persons WHERE id = 42,<none>";
        let line = csvline(
            "caseworker7",
            "registry",
            "10.0.0.5:52001",
            "SELECT",
            "LOG",
            "00000",
            msg,
            "psql",
        );
        let body = push_body(
            serde_json::json!({"source":"postgres-csvlog","host":"db01","log_type":"audit"}),
            serde_json::json!([["1720000000000000000", line]]),
        );
        let events = decode_json(&body, "prod").unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.log_type, "audit");
        assert_eq!(ev.host, "db01"); // stream label overrides the adapter default
        assert_eq!(ev.field("db_user"), Some("caseworker7"));
        assert_eq!(ev.field("query_type"), Some("select"));
        assert!(ev
            .field("statement_fingerprint")
            .unwrap()
            .starts_with("sql1:"));
        assert_eq!(ev.field("sql_read_tables"), Some("public.persons"));
    }

    #[test]
    fn multiline_csvlog_record_split_across_two_values_is_stitched() {
        let stmt = "CREATE TABLE public.t (\n  id int\n)";
        let msg = format!("AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.t,{stmt},<none>");
        let line = csvline(
            "dba",
            "app",
            "[local]",
            "CREATE TABLE",
            "LOG",
            "00000",
            &msg,
            "psql",
        );
        // Ship each physical line of the record as a separate Loki value.
        let values: Vec<Vec<String>> = line
            .split('\n')
            .enumerate()
            .map(|(i, p)| {
                vec![
                    format!("{}", 1_720_000_000_000_000_000u64 + i as u64),
                    p.to_string(),
                ]
            })
            .collect();
        let body = push_body(
            serde_json::json!({"source":"postgres-csvlog","host":"db01"}),
            serde_json::to_value(values).unwrap(),
        );
        let events = decode_json(&body, "prod").unwrap();
        assert_eq!(
            events.len(),
            1,
            "the multiline record must stitch into ONE event"
        );
        assert_eq!(events[0].field("query_type"), Some("create"));
    }

    #[test]
    fn journald_source_still_uses_the_line_classifier() {
        // A non-adapter source must behave exactly as before (no regression).
        let body = push_body(
            serde_json::json!({"host":"pve","source":"journald","service":"sshd"}),
            serde_json::json!([[
                "1720000000000000000",
                "Failed password for root from 10.0.0.9 port 22 ssh2"
            ]]),
        );
        let events = decode_json(&body, "prod").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "journald");
        assert_eq!(events[0].src_ip(), Some("10.0.0.9"));
    }
}
