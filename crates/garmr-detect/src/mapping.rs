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
//! `source.ip`, `source.address`, `host.name` and `host.hostname` are aliased as
//! LITERAL DOTTED KEYS rather than nested objects: garmr's own `source` (ingest
//! origin) and `host` labels occupy those ECS roots as strings, and rsigma
//! resolves a flat exact-match before dot-traversal, so both views coexist —
//! `source` still returns the origin, `source.ip` returns the address. See
//! [`add_ecs_aliases`]. `source.port` is deliberately not aliased (its true side
//! is producer-dependent; the reasoning is at the call site).

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

    // source.* and host.* — emitted as LITERAL DOTTED KEYS, not nested objects.
    //
    // These two ECS roots are already occupied by garmr's own labels as strings
    // (`source` = ingest origin, `host` = hostname), so a nested object would
    // have to destroy a label every garmr-native rule keys on. rsigma's
    // `JsonEvent::get_field` resolves a flat exact-match BEFORE dot-traversal
    // (rsigma-eval event/json.rs), so a literal "source.ip" key answers a rule
    // asking for `source.ip` while `source` keeps returning the origin string.
    // Without these, community rules keyed on the two commonest ECS fields in
    // the corpus traverse into a string, find nothing, and SILENTLY never match.
    if let Some(v) = f("src_ip") {
        // `address` is the as-observed value, `ip` the parsed one; garmr extracts
        // a single value, so both aliases carry it (the ECS-recommended pattern).
        m.insert("source.ip".into(), v.clone().into());
        m.insert("source.address".into(), v.into());
    }
    m.insert("host.name".into(), event.host.as_str().into());
    m.insert("host.hostname".into(), event.host.as_str().into());
    // Deliberately NOT aliased: `source.port`. The extracted `port` field is
    // already mapped to `destination.port` above, and its true side is
    // producer-dependent (in an sshd "… from 1.2.3.4 port 54321" line it is the
    // CLIENT's port, i.e. ECS `source.port`). Emitting it under both roots would
    // make one of the two silently wrong for every rule that reads it; a wrong
    // alias is worse than a missing one, because it matches. Resolving this
    // needs per-producer port semantics at extraction time.
}

/// How (and whether) a field name can match against garmr's event projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    /// Always present on every event (the six labels + message).
    Core,
    /// Present when ingest extraction produced it, or as an ECS alias of one.
    Extracted,
    /// Not in garmr's vocabulary. Such a field matches ONLY if a collector
    /// ships it verbatim inside `fields` — possible, but nothing garmr promises.
    Unknown,
}

/// Classify a field name a Sigma rule references.
///
/// This table lives BESIDE [`event_to_json`] on purpose: it is the same
/// vocabulary, written twice — once as construction, once as classification —
/// and the drift-guard test walks the constructed JSON and asserts every key
/// classifies as known. Add a field to the projection without adding it here
/// and that test fails, which is the moment to update both rather than let the
/// import lint drift into rejecting rules the engine would happily match.
pub fn field_class(name: &str) -> FieldClass {
    match name {
        // The six labels + the raw line: on every event, always.
        "host" | "service" | "source" | "environment" | "severity" | "log_type" | "message" => {
            FieldClass::Core
        }
        // Flat extracted fields (ingest parsers populate them when present).
        "src_ip" | "dst_ip" | "port" | "user" | "process" | "exe" | "cmdline" | "pid" | "dns"
        | "event_type" | "community_id" => FieldClass::Extracted,
        // Nested ECS aliases emitted by add_ecs_aliases.
        "destination.ip"
        | "destination.port"
        | "user.name"
        | "process.name"
        | "process.executable"
        | "process.command_line"
        | "process.pid"
        | "dns.question.name"
        | "event.action"
        | "network.community_id" => FieldClass::Extracted,
        // Literal dotted aliases for the occupied ECS roots.
        "source.ip" | "source.address" | "host.name" | "host.hostname" => FieldClass::Extracted,
        _ => FieldClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;

    #[test]
    fn every_projected_field_classifies_as_known() {
        // THE DRIFT GUARD. Build an event carrying every extracted field, walk
        // the full projection (flat keys + nested ECS objects, dotted paths),
        // and assert each classifies as Core or Extracted. If event_to_json
        // grows a field this fails, forcing field_class() to grow with it — so
        // the import lint can never reject a rule the engine would match.
        let mut fields = BTreeMap::new();
        for (k, v) in [
            ("src_ip", "10.0.0.5"),
            ("dst_ip", "203.0.113.9"),
            ("port", "443"),
            ("user", "root"),
            ("process", "curl"),
            ("exe", "/usr/bin/curl"),
            ("cmdline", "curl http://x"),
            ("pid", "4242"),
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
            message: "connect".into(),
            fields,
        };
        let j = event_to_json(&e);
        fn walk(prefix: &str, v: &Value, out: &mut Vec<String>) {
            match v {
                Value::Object(m) => {
                    for (k, inner) in m {
                        let path = if prefix.is_empty() {
                            k.clone()
                        } else {
                            format!("{prefix}.{k}")
                        };
                        walk(&path, inner, out);
                    }
                }
                _ => out.push(prefix.to_string()),
            }
        }
        let mut paths = Vec::new();
        walk("", &j, &mut paths);
        for path in paths {
            assert_ne!(
                field_class(&path),
                FieldClass::Unknown,
                "event_to_json emits {path:?} but field_class does not know it — update both"
            );
        }
    }

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
