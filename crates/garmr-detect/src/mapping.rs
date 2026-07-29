// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Map a garmr [`Event`] into the JSON object Sigma rules match against.
//!
//! Two overlaid views so both garmr's own rules AND upstream/community content
//! match the same event:
//! - **Flat garmr-native**: the 6 labels, raw `message`, and the ingest-extracted
//!   fields (`src_ip`, `user`, `port`, …) at top level. garmr's shipped rules key
//!   on `service` + `message`.
//! - **Canonical ECS aliases** (nested): the extracted fields ALSO exposed under
//!   Elastic Common Schema names (`destination.ip`, `user.name`,
//!   `process.command_line`, `dns.question.name`, `event.action`,
//!   `network.community_id`) so ECS-keyed community Sigma rules match without a
//!   per-rule field-mapping pipeline. rsigma resolves dotted field names by
//!   nested traversal, so the aliases are emitted as nested objects.
//!
//! Only consumed by [`crate::Detector::evaluate`] (rsigma). The stored event +
//! `fields` (read by correlate/graph/entity/SQL) are untouched — this is purely
//! the detection projection.
//!
//! Known gap: `source.ip` / `host.name` are NOT aliased — garmr's `source`
//! (ingest origin) and `host` labels occupy those ECS roots as strings. `src_ip`
//! and `host` stay flat-native; a fuller schema pass is a follow-up.

use garmr_core::Event;
use serde_json::{Map, Value};

/// Build the JSON event a Sigma rule is evaluated against.
pub fn event_to_json(event: &Event) -> Value {
    let mut m = Map::new();
    m.insert("host".into(), event.host.as_str().into());
    m.insert("service".into(), event.service.as_str().into());
    m.insert("source".into(), event.source.as_str().into());
    m.insert("environment".into(), event.environment.as_str().into());
    m.insert("severity".into(), event.severity.as_str().into());
    m.insert("log_type".into(), event.log_type.as_str().into());
    m.insert("message".into(), event.message.clone().into());
    // Flat garmr-native fields first (src_ip, dst_ip, exe, …).
    for (k, v) in &event.fields {
        m.entry(k.clone()).or_insert_with(|| v.clone().into());
    }
    // Then the canonical ECS aliases (nested). These overwrite the flat
    // `user`/`process`/`dns` with their ECS object form (no garmr rule matches
    // those flat, and correlate/graph read the stored event, not this JSON).
    add_ecs_aliases(&mut m, event);
    Value::Object(m)
}

/// Overlay canonical ECS field aliases (nested) built from the extracted fields.
fn add_ecs_aliases(m: &mut Map<String, Value>, event: &Event) {
    let f = |k: &str| event.fields.get(k).cloned();

    // destination.{ip,port} — network egress (free ECS root).
    let mut dst = Map::new();
    if let Some(v) = f("dst_ip") {
        dst.insert("ip".into(), v.into());
    }
    if let Some(v) = f("port") {
        dst.insert("port".into(), v.into());
    }
    if !dst.is_empty() {
        m.insert("destination".into(), Value::Object(dst));
    }

    // user.name
    if let Some(v) = f("user") {
        m.insert("user".into(), serde_json::json!({ "name": v }));
    }

    // process.{name,executable,command_line,pid}
    let mut proc = Map::new();
    if let Some(v) = f("process") {
        proc.insert("name".into(), v.into());
    }
    if let Some(v) = f("exe") {
        proc.insert("executable".into(), v.into());
    }
    if let Some(v) = f("cmdline") {
        proc.insert("command_line".into(), v.into());
    }
    if let Some(v) = f("pid") {
        proc.insert("pid".into(), v.into());
    }
    if !proc.is_empty() {
        m.insert("process".into(), Value::Object(proc));
    }

    // dns.question.name
    if let Some(v) = f("dns") {
        m.insert(
            "dns".into(),
            serde_json::json!({ "question": { "name": v } }),
        );
    }
    // event.action
    if let Some(v) = f("event_type") {
        m.insert("event".into(), serde_json::json!({ "action": v }));
    }
    // network.community_id
    if let Some(v) = f("community_id") {
        m.insert("network".into(), serde_json::json!({ "community_id": v }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;

    #[test]
    fn promotes_extracted_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("src_ip".to_string(), "1.2.3.4".to_string());
        let e = Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: "Failed password".into(),
            fields,
        };
        let j = event_to_json(&e);
        assert_eq!(j["src_ip"], "1.2.3.4");
        assert_eq!(j["service"], "sshd");
    }

    #[test]
    fn emits_ecs_aliases_nested() {
        let mut fields = BTreeMap::new();
        for (k, v) in [
            ("src_ip", "10.0.0.5"),
            ("dst_ip", "203.0.113.9"),
            ("port", "443"),
            ("user", "root"),
            ("process", "curl"),
            ("exe", "/usr/bin/curl"),
            ("cmdline", "curl http://x"),
            ("dns", "evil.example"),
            ("event_type", "connect"),
            ("community_id", "1:abc="),
        ] {
            fields.insert(k.to_string(), v.to_string());
        }
        let e = Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "kunai".into(),
            source: "kunai".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "endpoint".into(),
            message: "m".into(),
            fields,
        };
        let j = event_to_json(&e);
        // ECS nested aliases
        assert_eq!(j["destination"]["ip"], "203.0.113.9");
        assert_eq!(j["destination"]["port"], "443");
        assert_eq!(j["user"]["name"], "root");
        assert_eq!(j["process"]["name"], "curl");
        assert_eq!(j["process"]["executable"], "/usr/bin/curl");
        assert_eq!(j["process"]["command_line"], "curl http://x");
        assert_eq!(j["dns"]["question"]["name"], "evil.example");
        assert_eq!(j["event"]["action"], "connect");
        assert_eq!(j["network"]["community_id"], "1:abc=");
        // Flat garmr-native survivors (non-colliding names) stay for garmr's rules.
        assert_eq!(j["src_ip"], "10.0.0.5");
        assert_eq!(j["dst_ip"], "203.0.113.9");
        assert_eq!(j["cmdline"], "curl http://x");
        // source/host remain the string labels (documented ECS gap).
        assert_eq!(j["source"], "kunai");
        assert_eq!(j["host"], "pve");
    }
}