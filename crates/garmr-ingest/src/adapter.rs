// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned source adapters: pluggable, named+versioned parsers that map a
//! foreign log format into garmr's canonical [`Event`].
//!
//! The native (`/ingest/v1/events`) and syslog paths remain the primary ingest;
//! adapters extend garmr to well-known external schemas without teaching every
//! collector garmr's wire format. Each adapter carries a stable `name` and
//! `version` (recorded as the event's producer class, and — via the store —
//! surfaced in the `parser_name` provenance column), so a downstream schema
//! change is a version bump, not a silent behavior change.
//!
//! Adapters parse defensively over `serde_json::Value`: these schemas are wide
//! and mostly-optional, so a missing field yields a sane default rather than a
//! hard failure. Two real adapters ship here — OCSF and OpenTelemetry Logs — in
//! addition to the existing native + syslog ingest.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use garmr_core::{Error, Event, Result};
use serde_json::Value;

use crate::fields;

/// A named, versioned parser from a foreign format to canonical events.
pub trait Adapter: Send + Sync {
    /// Stable format identifier (also the event's `source`/producer class).
    fn name(&self) -> &str;
    /// Adapter version — bump on any mapping change.
    fn version(&self) -> &str;
    /// Parse a raw record (a JSON value — object or array) into zero or more
    /// events. `default_environment` fills the environment label when absent.
    fn parse(&self, raw: &[u8], default_environment: &str) -> Result<Vec<Event>>;
}

/// Registry of adapters by format name.
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    by_name: HashMap<String, Arc<dyn Adapter>>,
}

impl AdapterRegistry {
    /// A registry with every built-in adapter registered.
    pub fn with_builtin() -> Self {
        let mut r = AdapterRegistry::default();
        r.register(Arc::new(OcsfAdapter));
        r.register(Arc::new(OtelLogsAdapter));
        r.register(Arc::new(crate::pg::PgCsvlogAdapter));
        r.register(Arc::new(crate::pg::PgJsonlogAdapter));
        r
    }

    pub fn register(&mut self, adapter: Arc<dyn Adapter>) {
        self.by_name.insert(adapter.name().to_string(), adapter);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Adapter>> {
        self.by_name.get(name).cloned()
    }

    /// Registered format names, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut n: Vec<String> = self.by_name.keys().cloned().collect();
        n.sort();
        n
    }

    /// Parse `body` with the adapter named `format`.
    pub fn parse(
        &self,
        format: &str,
        body: &[u8],
        default_environment: &str,
    ) -> Result<Vec<Event>> {
        let adapter = self
            .get(format)
            .ok_or_else(|| Error::Ingest(format!("unknown adapter format '{format}'")))?;
        adapter.parse(body, default_environment)
    }
}

/// Parse a body that is either a single JSON object or an array of objects,
/// mapping each object through `one`.
fn parse_json_records<F>(body: &[u8], one: F) -> Result<Vec<Event>>
where
    F: Fn(&Value) -> Event,
{
    let v: Value =
        serde_json::from_slice(body).map_err(|e| Error::Ingest(format!("json decode: {e}")))?;
    match v {
        Value::Array(items) => Ok(items.iter().map(&one).collect()),
        obj @ Value::Object(_) => Ok(vec![one(&obj)]),
        _ => Err(Error::Ingest("expected a JSON object or array".into())),
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str()
}

fn insert_if(map: &mut BTreeMap<String, String>, key: &str, val: Option<&str>) {
    if let Some(s) = val {
        if !s.is_empty() {
            map.insert(key.to_string(), s.to_string());
        }
    }
}

// ---- OCSF ------------------------------------------------------------------

/// OCSF (Open Cybersecurity Schema Framework) JSON events. Maps the common
/// top-level classification + endpoints + actor into the six-label model; the
/// class/category/activity ids and network/identity fields go into `fields`.
pub struct OcsfAdapter;

impl OcsfAdapter {
    fn severity(v: &Value) -> String {
        if let Some(s) = v.get("severity").and_then(Value::as_str) {
            return s.to_ascii_lowercase();
        }
        // OCSF severity_id: 1 Informational … 6 Fatal.
        match v.get("severity_id").and_then(Value::as_i64) {
            Some(1) => "info",
            Some(2) => "low",
            Some(3) => "medium",
            Some(4) => "high",
            Some(5) => "critical",
            Some(6) => "fatal",
            _ => "info",
        }
        .to_string()
    }

    fn to_event(v: &Value, default_environment: &str) -> Event {
        let ts = v
            .get("time")
            .and_then(Value::as_i64)
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .unwrap_or_else(Utc::now);
        let host = str_at(v, &["device", "hostname"])
            .or_else(|| str_at(v, &["device", "name"]))
            .or_else(|| str_at(v, &["src_endpoint", "hostname"]))
            .unwrap_or("unknown")
            .to_string();
        let service = str_at(v, &["metadata", "product", "name"])
            .or_else(|| v.get("class_name").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string();
        let message = v
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| v.get("class_name").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();

        let mut fields = BTreeMap::new();
        insert_if(&mut fields, "src_ip", str_at(v, &["src_endpoint", "ip"]));
        insert_if(&mut fields, "dst_ip", str_at(v, &["dst_endpoint", "ip"]));
        insert_if(&mut fields, "user", str_at(v, &["actor", "user", "name"]));
        insert_if(
            &mut fields,
            "ocsf_class",
            v.get("class_name").and_then(Value::as_str),
        );
        insert_if(
            &mut fields,
            "ocsf_category",
            v.get("category_name").and_then(Value::as_str),
        );
        insert_if(
            &mut fields,
            "ocsf_activity",
            v.get("activity_name").and_then(Value::as_str),
        );
        // Backfill extractable fields from the message when the structured form
        // did not carry them (keeps detection/triage working).
        if !fields.contains_key("src_ip") {
            for (k, val) in fields::extract(&message) {
                fields.entry(k).or_insert(val);
            }
        }

        Event {
            ts,
            host: host.into(),
            service: service.into(),
            source: "ocsf".into(),
            environment: default_environment.into(),
            severity: Self::severity(v).into(),
            log_type: "security_alert".into(),
            message,
            fields,
        }
    }
}

impl Adapter for OcsfAdapter {
    fn name(&self) -> &str {
        "ocsf"
    }
    fn version(&self) -> &str {
        "1.0"
    }
    fn parse(&self, raw: &[u8], default_environment: &str) -> Result<Vec<Event>> {
        parse_json_records(raw, |v| Self::to_event(v, default_environment))
    }
}

// ---- OpenTelemetry Logs ----------------------------------------------------

/// OpenTelemetry log records (OTLP/JSON, per-record shape). Reads
/// `timeUnixNano`, `severityText`, `body.stringValue`, and the `attributes`
/// key/value list (host.name, service.name, and the rest flattened into
/// `fields`).
pub struct OtelLogsAdapter;

impl OtelLogsAdapter {
    /// Flatten an OTLP attribute list (`[{key, value:{stringValue|intValue|…}}]`)
    /// into a string map.
    fn attributes(v: &Value) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if let Some(arr) = v.get("attributes").and_then(Value::as_array) {
            for a in arr {
                let Some(key) = a.get("key").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(val) = a.get("value").and_then(Self::any_value) {
                    out.insert(key.to_string(), val);
                }
            }
        }
        out
    }

    /// Render an OTLP `AnyValue` as a string (string/int/double/bool).
    fn any_value(v: &Value) -> Option<String> {
        if let Some(s) = v.get("stringValue").and_then(Value::as_str) {
            return Some(s.to_string());
        }
        if let Some(n) = v.get("intValue") {
            return Some(
                n.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| n.to_string()),
            );
        }
        if let Some(n) = v.get("doubleValue") {
            return Some(n.to_string());
        }
        if let Some(b) = v.get("boolValue").and_then(Value::as_bool) {
            return Some(b.to_string());
        }
        None
    }

    fn to_event(v: &Value, default_environment: &str) -> Event {
        // timeUnixNano may be a JSON string or number (protobuf-JSON uses strings
        // for 64-bit ints).
        let nanos = v
            .get("timeUnixNano")
            .or_else(|| v.get("observedTimeUnixNano"))
            .and_then(|t| {
                t.as_i64()
                    .or_else(|| t.as_str().and_then(|s| s.parse().ok()))
            });
        let ts = nanos
            .map(DateTime::<Utc>::from_timestamp_nanos)
            .unwrap_or_else(Utc::now);

        let message = str_at(v, &["body", "stringValue"])
            .or_else(|| v.get("body").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();

        let mut attrs = Self::attributes(v);
        let host = attrs
            .remove("host.name")
            .or_else(|| attrs.remove("host.id"))
            .unwrap_or_else(|| "unknown".to_string());
        let service = attrs.remove("service.name").unwrap_or_default();

        // Remaining attributes become fields; backfill from the message too.
        let mut fields = attrs;
        for (k, val) in fields::extract(&message) {
            fields.entry(k).or_insert(val);
        }
        if let Some(t) = v.get("traceId").and_then(Value::as_str) {
            if !t.is_empty() {
                fields.insert("trace_id".to_string(), t.to_string());
            }
        }

        Event {
            ts,
            host: host.into(),
            service: service.into(),
            source: "otel".into(),
            environment: default_environment.into(),
            severity: v
                .get("severityText")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_ascii_lowercase()
                .into(),
            log_type: "app".into(),
            message,
            fields,
        }
    }
}

impl Adapter for OtelLogsAdapter {
    fn name(&self) -> &str {
        "otel"
    }
    fn version(&self) -> &str {
        "1.0"
    }
    fn parse(&self, raw: &[u8], default_environment: &str) -> Result<Vec<Event>> {
        parse_json_records(raw, |v| Self::to_event(v, default_environment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lists_builtins() {
        let r = AdapterRegistry::with_builtin();
        assert_eq!(
            r.names(),
            vec![
                "ocsf".to_string(),
                "otel".to_string(),
                "postgres-csvlog".to_string(),
                "postgres-jsonlog".to_string(),
            ]
        );
        assert_eq!(r.get("ocsf").unwrap().version(), "1.0");
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn ocsf_maps_endpoints_actor_and_severity() {
        let body = br#"{
            "class_name":"Authentication","category_name":"IAM",
            "activity_name":"Logon","severity_id":4,"time":1700000000000,
            "message":"Failed logon",
            "device":{"hostname":"win-dc-01"},
            "src_endpoint":{"ip":"10.0.0.9"},
            "dst_endpoint":{"ip":"10.0.0.1"},
            "actor":{"user":{"name":"administrator"}},
            "metadata":{"product":{"name":"WinLogon"}}
        }"#;
        let ev = &AdapterRegistry::with_builtin()
            .parse("ocsf", body, "prod")
            .unwrap()[0];
        assert_eq!(ev.host, "win-dc-01");
        assert_eq!(ev.service, "WinLogon");
        assert_eq!(ev.source, "ocsf");
        assert_eq!(ev.severity, "high");
        assert_eq!(ev.log_type, "security_alert");
        assert_eq!(ev.src_ip(), Some("10.0.0.9"));
        assert_eq!(ev.field("dst_ip"), Some("10.0.0.1"));
        assert_eq!(ev.field("user"), Some("administrator"));
        assert_eq!(ev.field("ocsf_class"), Some("Authentication"));
        assert_eq!(ev.ts.timestamp_millis(), 1_700_000_000_000);
    }

    #[test]
    fn ocsf_array_and_message_fallback() {
        let body = br#"[{"class_name":"NetworkActivity","message":"conn from 8.8.8.8"}]"#;
        let evs = OcsfAdapter.parse(body, "lab").unwrap();
        assert_eq!(evs.len(), 1);
        // src_ip backfilled from the message when not structured.
        assert_eq!(evs[0].src_ip(), Some("8.8.8.8"));
        assert_eq!(evs[0].environment, "lab");
    }

    #[test]
    fn otel_reads_body_attrs_and_string_nanos() {
        let body = br#"{
            "timeUnixNano":"1700000000000000000",
            "severityText":"ERROR",
            "body":{"stringValue":"disk failure on 10.1.2.3"},
            "attributes":[
                {"key":"host.name","value":{"stringValue":"node7"}},
                {"key":"service.name","value":{"stringValue":"kubelet"}},
                {"key":"k8s.pod","value":{"stringValue":"api-abc"}}
            ],
            "traceId":"abc123"
        }"#;
        let ev = &OtelLogsAdapter.parse(body, "prod").unwrap()[0];
        assert_eq!(ev.host, "node7");
        assert_eq!(ev.service, "kubelet");
        assert_eq!(ev.source, "otel");
        assert_eq!(ev.severity, "error");
        assert_eq!(ev.message, "disk failure on 10.1.2.3");
        assert_eq!(ev.field("k8s.pod"), Some("api-abc"));
        assert_eq!(ev.field("trace_id"), Some("abc123"));
        assert_eq!(ev.src_ip(), Some("10.1.2.3")); // backfilled from body
        assert_eq!(ev.ts.timestamp(), 1_700_000_000);
    }

    #[test]
    fn unknown_format_errors() {
        assert!(AdapterRegistry::with_builtin()
            .parse("bogus", b"{}", "prod")
            .is_err());
    }

    /// The OCSF-first source strategy, tested against the shapes real pipelines
    /// emit rather than against hand-written ideal input.
    ///
    /// The claim these guard is "anything Cribl/Vector can shape to OCSF gets
    /// in" — which is worth nothing unless the resulting event carries the
    /// fields detection and triage actually key on. A fixture that parses but
    /// yields an event with no user and no source IP would satisfy a naive test
    /// and be useless in production.
    mod ocsf_source_pipelines {
        use super::*;

        fn parse_fixture(name: &str) -> Event {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/ocsf/").to_string();
            let raw = std::fs::read(format!("{path}{name}"))
                .unwrap_or_else(|e| panic!("fixture {name}: {e}"));
            let mut evs = OcsfAdapter
                .parse(&raw, "prod")
                .unwrap_or_else(|e| panic!("fixture {name} failed to parse: {e}"));
            assert_eq!(evs.len(), 1, "one record should yield one event");
            evs.pop().unwrap()
        }

        #[test]
        fn cloudtrail_console_login_carries_the_fields_detection_needs() {
            let e = parse_fixture("cloudtrail-console-login-failure.json");
            // The three that matter: who, from where, and on what. A rule keyed
            // on any of these is a large share of the community corpus.
            assert_eq!(e.fields.get("user").map(String::as_str), Some("deploy-bot"));
            assert_eq!(
                e.fields.get("src_ip").map(String::as_str),
                Some("203.0.113.42")
            );
            assert_eq!(e.host.as_str(), "signin.amazonaws.com");
            // Product name becomes the service, so per-source rules and the
            // ingest-health view can distinguish CloudTrail from Okta.
            assert_eq!(e.service.as_str(), "AWS CloudTrail");
            assert_eq!(e.severity.as_str(), "medium");
            assert_eq!(
                e.fields.get("ocsf_class").map(String::as_str),
                Some("Authentication")
            );
        }

        #[test]
        fn okta_mfa_denial_carries_the_identity_and_address() {
            let e = parse_fixture("okta-mfa-denied.json");
            assert_eq!(
                e.fields.get("user").map(String::as_str),
                Some("henrik@vetra.se")
            );
            assert_eq!(
                e.fields.get("src_ip").map(String::as_str),
                Some("198.51.100.7")
            );
            assert_eq!(e.service.as_str(), "Okta");
            assert_eq!(e.severity.as_str(), "high");
        }

        #[test]
        fn m365_inbox_rule_carries_actor_ip_and_high_severity() {
            // New-InboxRule is the classic BEC persistence move (forward+delete)
            // — the fixture is the pipeline's output for exactly that, and it
            // must arrive triage-ready: who, from where, on which workload, HIGH.
            let e = parse_fixture("m365-mailbox-rule.json");
            assert_eq!(
                e.fields.get("user").map(String::as_str),
                Some("eve@vetra.se")
            );
            assert_eq!(
                e.fields.get("src_ip").map(String::as_str),
                Some("198.51.100.23")
            );
            assert_eq!(e.host.as_str(), "Exchange");
            assert_eq!(e.service.as_str(), "Microsoft 365");
            assert_eq!(e.severity.as_str(), "high");
        }

        #[test]
        fn both_fixtures_land_in_the_same_normalised_shape() {
            // The point of the OCSF-first strategy: two structurally different
            // producers (an AWS API audit and an identity provider) become the
            // same event shape, so one rule can span both without a per-source
            // mapping pipeline.
            for f in [
                "cloudtrail-console-login-failure.json",
                "okta-mfa-denied.json",
                "m365-mailbox-rule.json",
            ] {
                let e = parse_fixture(f);
                assert_eq!(e.source.as_str(), "ocsf", "{f}");
                assert_eq!(e.log_type.as_str(), "security_alert", "{f}");
                assert_eq!(e.environment.as_str(), "prod", "{f}");
                assert!(!e.message.is_empty(), "{f} lost its message");
                assert!(e.fields.contains_key("user"), "{f} has no actor");
            }
        }
    }
}
