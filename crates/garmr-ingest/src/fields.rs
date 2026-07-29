// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Cheap field extraction at ingest time.
//!
//! Two paths, chosen by shape:
//! - **JSON events** (the line is a JSON object — how endpoint tools like Kunai,
//!   Pulsar, Falco, osquery and Wazuh emit): walk the object and pull known
//!   high-value keys (src_ip/dst_ip/user/exe/cmdline/process/pid/port/dns, plus
//!   the endpoint action `event_type` and the `community_id` flow hash) out of
//!   it, using PARENT-key context so `{"dst":{"ip":…}}` → `dst_ip` and
//!   `{"exe":{"path":…}}` → `exe`. This is what makes endpoint telemetry
//!   queryable / Sigma-mappable / graphable (M6). Lineage (`parent_task`) is
//!   deliberately ignored so the ACTING task owns the normalized fields. The
//!   same JSON path also carries the general **access-audit** vocabulary
//!   (actor→`db_user`, subject→`target_person`, `object_table`, `statement`,
//!   `action`, `ticket_ref`, plus the `watched`/`is_self` flags), with many
//!   input aliases folding onto each normalized key so an arbitrary audit feed
//!   — a person register, an account/document/record audit, an API access log —
//!   powers the "who accessed whom/what" investigation surface with no code
//!   edits. The registerkontroll person-register is the flagship case.
//! - **Text lines** (everything else): a few compiled regexes pull `src_ip` /
//!   `user` / `port` out of the raw line — enough for the common auth/firewall
//!   shapes.
//!
//! Both are deliberately shallow — not full parsers, just enough to key the
//! fields Sigma field-mapping, the graph and the agent's tools care about.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

struct Patterns {
    /// The source-IP context ("from <ip>") — preferred over any dotted-quad so
    /// an attacker can't put a chosen quad earlier in the line (e.g. as a
    /// username) and mislabel `src_ip`.
    ip_from: Regex,
    /// Fallback: any dotted-quad (firewall lines without "from").
    ip_any: Regex,
    /// "for [invalid user ]<user>" / "Invalid user <user>" (sshd), case-insensitive.
    user_ctx: Regex,
    /// "user=<user>" (pam).
    user_pam: Regex,
    /// "port <n>" or "dport=<n>".
    port: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        ip_from: Regex::new(r"(?i)from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap(),
        ip_any: Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap(),
        user_ctx: Regex::new(r"(?i)(?:invalid user |for (?:invalid user )?)([A-Za-z0-9._-]{1,32})")
            .unwrap(),
        user_pam: Regex::new(r"(?i)\buser=([A-Za-z0-9._-]{1,32})").unwrap(),
        port: Regex::new(r"(?i)(?:port |dport=)(\d{1,5})").unwrap(),
    })
}

fn valid_ipv4(s: &str) -> bool {
    let mut n = 0;
    for octet in s.split('.') {
        n += 1;
        match octet.parse::<u16>() {
            Ok(v) if v <= 255 => {}
            _ => return false,
        }
    }
    n == 4
}

/// Extract high-value fields from a log line. A JSON object is walked
/// structurally; anything else goes through the text regexes.
pub fn extract(line: &str) -> BTreeMap<String, String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(trimmed) {
            // Structured event: the JSON is authoritative — don't also run the
            // text regexes over it (they'd mislabel a dst_ip as src_ip etc.).
            let mut fields = BTreeMap::new();
            walk_json(&v, "", &mut fields);
            return fields;
        }
    }
    extract_text(line)
}

/// The text-line extractor (the original regex path).
fn extract_text(line: &str) -> BTreeMap<String, String> {
    let p = patterns();
    let mut fields = BTreeMap::new();

    // Prefer the "from <ip>" address; fall back to the first dotted-quad. Drop
    // anything whose octets are out of range (a spoofed/garbage quad).
    let ip = p
        .ip_from
        .captures(line)
        .or_else(|| p.ip_any.captures(line))
        .map(|c| c[1].to_string())
        .filter(|s| valid_ipv4(s));
    if let Some(ip) = ip {
        fields.insert("src_ip".to_string(), ip);
    }

    if let Some(c) = p
        .user_ctx
        .captures(line)
        .or_else(|| p.user_pam.captures(line))
    {
        fields.insert("user".to_string(), c[1].to_string());
    }

    if let Some(c) = p.port.captures(line) {
        if c[1].parse::<u32>().map(|v| v <= 65535).unwrap_or(false) {
            fields.insert("port".to_string(), c[1].to_string());
        }
    }
    fields
}

/// Recursively walk a JSON event, mapping known keys (in `parent` context) to
/// normalized fields. First occurrence wins (outer/earlier keys are usually the
/// primary ones). Arrays are walked keeping the parent key.
fn walk_json(v: &Value, parent: &str, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                let key = k.to_ascii_lowercase();
                match val {
                    Value::Object(_) | Value::Array(_) => walk_json(val, &key, out),
                    Value::String(s) => note_json(parent, &key, s, out),
                    Value::Number(n) => note_json(parent, &key, &n.to_string(), out),
                    // Booleans matter for the audit sensitivity flags (`watched`,
                    // `is_self`); a classifier that keeps them (e.g. as "true")
                    // is a no-op for unclassified bools (classify → None).
                    Value::Bool(b) => {
                        note_json(parent, &key, if *b { "true" } else { "false" }, out)
                    }
                    _ => {}
                }
            }
        }
        Value::Array(a) => {
            for val in a {
                walk_json(val, parent, out);
            }
        }
        _ => {}
    }
}

fn note_json(parent: &str, key: &str, val: &str, out: &mut BTreeMap<String, String>) {
    let Some(target) = classify(parent, key) else {
        return;
    };
    let val = val.trim();
    // Skip empties and the "?" unknown-sentinel endpoint tools (Kunai) emit for
    // an unresolved user/host — never a meaningful normalized value, and it
    // would otherwise become a bogus "user:?" graph node.
    if val.is_empty() || val == "?" {
        return;
    }
    // IP fields must actually look like an IP, so a "src_ip":"unknown" (or a
    // hostname) can't create a bogus graph node / mislead detection.
    if (target == "src_ip" || target == "dst_ip") && !valid_ipv4(val) && !val.contains(':') {
        return;
    }
    // Keep long command lines but bound them.
    let val = if val.len() > 512 {
        &val[..char_floor(val, 512)]
    } else {
        val
    };
    out.entry(target.to_string())
        .or_insert_with(|| val.to_string());
}

/// A `(parent_key, key)` → normalized-field classifier. Covers the flat form
/// (`src_ip`) and the nested form (`src`/`source` object with an `ip` leaf), so
/// it handles the common endpoint-tool schemas without hardcoding one vendor.
/// The endpoint shapes (nested `exe`, the event `name`, `community_id`) are
/// validated against real Kunai 0.6.2 output, not guessed.
fn classify(parent: &str, key: &str) -> Option<&'static str> {
    match (parent, key) {
        // Lineage context (Kunai's `parent_task`, i.e. who spawned the actor) is
        // NOT the acting entity — never let it populate the normalized actor
        // fields. The `ancestors` string already carries the chain, and the
        // acting `task` must win even though it sorts after `parent_task`.
        ("parent_task", _) => None,
        // Socket internals (Kunai's `data.socket.{domain,type,proto}`) are the
        // address family/type, NOT actor fields — in particular `socket.domain`
        // is "AF_INET", which must never be taken as a DNS `domain`.
        ("socket", _) => None,
        (_, "src_ip" | "source_ip" | "saddr" | "client_ip" | "remote_ip" | "sip") => Some("src_ip"),
        ("src" | "source" | "client" | "remote", "ip" | "addr" | "address") => Some("src_ip"),
        (_, "dst_ip" | "dest_ip" | "destination_ip" | "daddr" | "server_ip" | "dip") => {
            Some("dst_ip")
        }
        ("dst" | "dest" | "destination" | "server", "ip" | "addr" | "address") => Some("dst_ip"),
        (_, "user" | "username" | "user_name") => Some("user"),
        ("user" | "cred", "name") => Some("user"),
        (_, "command_line" | "cmdline" | "cmd") => Some("cmdline"),
        (_, "exe" | "executable" | "exe_path" | "binary") => Some("exe"),
        // Nested executable object (Kunai `data.exe.path`, ECS-ish).
        ("exe" | "interpreter", "path") => Some("exe"),
        (_, "comm" | "proc_name" | "task_name" | "image" | "process_name") => Some("process"),
        ("task" | "process", "name") => Some("process"),
        (_, "pid") => Some("pid"),
        (_, "port" | "dport" | "dst_port" | "sport" | "src_port" | "dstport" | "srcport") => {
            Some("port")
        }
        (_, "query" | "dns_query" | "domain" | "qname") => Some("dns"),
        // Endpoint/EDR telemetry: the action (execve/connect/dns_query/…) and
        // the cross-tool network-flow correlation hash (Community ID spec).
        ("event", "name") => Some("event_type"),
        (_, "community_id") => Some("community_id"),
        // Access-audit ("who accessed whom/what") — the general audit-log
        // vocabulary. An app (or a DB audit plugin) emits one structured JSON
        // event per access with an explicit subject (authoritative — the subject
        // can't be reliably reverse-engineered from a SQL WHERE clause). The
        // registerkontroll person-register is the flagship case (db_user reads a
        // target_person), but the SAME normalized keys serve any access audit:
        // account/document/record/case access, an API access log, an EHR module,
        // etc. Many input names fold onto each normalized key so an arbitrary
        // audit feed maps with zero code edits — the normalized keys
        // (db_user/target_person/object_table/statement/action/ticket_ref +
        // the watched/is_self flags) are what the rules, pivots and RBA key on.
        //
        // The ACTOR (who acted). Normalized: `db_user`.
        (
            _,
            "db_user" | "session_user" | "dbuser" | "actor" | "principal" | "acting_user"
            | "performed_by" | "accessed_by" | "operator" | "account" | "user_id",
        ) => Some("db_user"),
        // The SUBJECT/OBJECT accessed (a person, account, record, document…).
        // Normalized: `target_person` (an opaque id — no personnummer parsing).
        (
            _,
            "target_person" | "target_pnr" | "subject_person" | "registered_person" | "target"
            | "subject" | "target_id" | "subject_id" | "object_id" | "record_id" | "resource_id"
            | "entity_id",
        ) => Some("target_person"),
        // The client origin. NOT IP-guarded (a DB audit's `%h` may be a hostname
        // or "[local]"); emit `client_ip` for the guarded `src_ip` + IP pivots.
        (
            _,
            "client_addr" | "remote_host" | "client_host" | "remote_addr" | "source_host"
            | "origin_host" | "origin" | "client_address" | "source_address",
        ) => Some("client_addr"),
        // The kind of thing accessed (table / resource type / collection…).
        (
            _,
            "object_table" | "object_name" | "relation" | "table_name" | "object_type"
            | "resource_type" | "entity_type" | "resource" | "collection" | "dataset" | "endpoint",
        ) => Some("object_table"),
        // The full statement / SQL text. Do NOT name it `query` (maps to `dns`).
        (_, "statement" | "query_text" | "sql_text" | "sql") => Some("statement"),
        // The operation verb (read/view/export/GET/DELETE…) — distinct from the
        // SQL `statement`, so non-SQL audits capture "what was done".
        (_, "action" | "operation" | "op" | "verb" | "method") => Some("action"),
        // The justification: a ticket/case/diarie reference OR a free-text reason.
        (
            _,
            "ticket_ref" | "case_ref" | "arende" | "arende_ref" | "errand_ref" | "diarienr"
            | "reason" | "purpose" | "justification" | "access_reason" | "justification_text",
        ) => Some("ticket_ref"),
        // App-supplied sensitivity flags, so garmr never has to HOLD the
        // watchlist or the staff→own-record map: the app sets `watched: true`
        // when the accessed subject is on its watchlist, and `is_self: true`
        // when the actor accessed their own record. Accepts JSON bool or string.
        (_, "watched" | "is_watched" | "watchlisted") => Some("watched"),
        (_, "is_self" | "self_lookup" | "self_access") => Some("is_self"),
        _ => None,
    }
}

/// Largest char-boundary offset ≤ `max`.
fn char_floor(s: &str, max: usize) -> usize {
    let mut i = max.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sshd_failed_password() {
        let line = "Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2";
        let f = extract(line);
        assert_eq!(f.get("src_ip").map(String::as_str), Some("203.0.113.7"));
        assert_eq!(f.get("user").map(String::as_str), Some("admin"));
        assert_eq!(f.get("port").map(String::as_str), Some("51234"));
    }

    #[test]
    fn no_fields_when_absent() {
        assert!(extract("systemd: Started Daily apt upgrade.").is_empty());
    }

    #[test]
    fn extracts_for_user_on_real_account() {
        // The "for <user>" shape (successful + real-account failed logins) —
        // previously dropped, degrading baseline/user-keyed detection.
        let f = extract("Accepted publickey for alice from 192.168.1.50 port 40222 ssh2");
        assert_eq!(f.get("user").map(String::as_str), Some("alice"));
        assert_eq!(f.get("src_ip").map(String::as_str), Some("192.168.1.50"));
    }

    #[test]
    fn prefers_from_ip_over_earlier_quad() {
        // A crafted quad in the username must not win over the real "from" IP.
        let f = extract("Failed password for invalid user 1.2.3.4 from 203.0.113.9 port 22 ssh2");
        assert_eq!(f.get("src_ip").map(String::as_str), Some("203.0.113.9"));
    }

    #[test]
    fn rejects_out_of_range_octets_and_ports() {
        // 999.1.1.1 is not a valid address and there's no "from" context → no src_ip.
        let f = extract("weird 999.1.1.1 port 99999");
        assert_eq!(f.get("src_ip"), None);
        assert_eq!(f.get("port"), None);
    }

    #[test]
    fn extracts_kunai_style_connect_event() {
        // Kunai shape: info.task.{name,pid,exe,command_line}, data.{src,dst}.ip.
        let line = r#"{"info":{"host":{"name":"pve"},"event":{"name":"connect"},
          "task":{"name":"curl","pid":4242,"exe":"/usr/bin/curl","command_line":"curl http://x"}},
          "data":{"dst":{"ip":"203.0.113.9","port":443},"src":{"ip":"10.0.0.5"}}}"#;
        let f = extract(line);
        assert_eq!(f.get("dst_ip").map(String::as_str), Some("203.0.113.9"));
        assert_eq!(f.get("src_ip").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(f.get("process").map(String::as_str), Some("curl"));
        assert_eq!(f.get("exe").map(String::as_str), Some("/usr/bin/curl"));
        assert_eq!(f.get("cmdline").map(String::as_str), Some("curl http://x"));
        assert_eq!(f.get("pid").map(String::as_str), Some("4242"));
        assert_eq!(f.get("port").map(String::as_str), Some("443"));
    }

    #[test]
    fn extracts_ecs_style_nested_user_and_ip() {
        let line = r#"{"source":{"ip":"192.168.1.9"},"user":{"name":"root"},"destination":{"ip":"8.8.8.8"}}"#;
        let f = extract(line);
        assert_eq!(f.get("src_ip").map(String::as_str), Some("192.168.1.9"));
        assert_eq!(f.get("dst_ip").map(String::as_str), Some("8.8.8.8"));
        assert_eq!(f.get("user").map(String::as_str), Some("root"));
    }

    #[test]
    fn json_ip_fields_reject_non_ip_values() {
        // A "src_ip":"unknown" must not become a bogus field / graph node.
        let f = extract(r#"{"src_ip":"unknown","user":"bob","dst_ip":"malformed"}"#);
        assert_eq!(f.get("src_ip"), None);
        assert_eq!(f.get("dst_ip"), None);
        assert_eq!(f.get("user").map(String::as_str), Some("bob"));
    }

    #[test]
    fn extracts_real_kunai_connect_event() {
        // Captured VERBATIM from kunai 0.6.2 on Linux (a `connect` event) — the
        // real nesting: data.exe.path, data.{src,dst}.ip, info.event.name,
        // info.task.user, data.community_id, and a parent_task that must NOT win.
        let line = r#"{"data":{"ancestors":"/usr/lib/systemd/systemd","command_line":"/usr/bin/python3 /opt/talos-log-receiver/receiver.py","exe":{"path":"/usr/bin/python3.13","md5":"","sha256":""},"socket":{"domain":"AF_INET","type":"SOCK_STREAM","proto":"TCP"},"src":{"ip":"10.10.10.2","port":0},"dst":{"hostname":"?","ip":"10.10.10.12","port":3100,"public":false,"is_v6":false},"community_id":"1:/9h2X8wc6f2MS8gJSZN37tU9hCI=","connected":true},"info":{"host":{"name":"pve","container":null},"event":{"source":"kunai","id":8,"name":"connect","uuid":"2f74"},"task":{"name":"python3","pid":4242,"uid":0,"user":"root","gid":0,"group":"root"},"parent_task":{"name":"systemd","pid":1,"uid":0,"user":"root"},"utc_time":"2026-07-16T23:09:39Z"}}"#;
        let f = extract(line);
        assert_eq!(f.get("src_ip").map(String::as_str), Some("10.10.10.2"));
        assert_eq!(f.get("dst_ip").map(String::as_str), Some("10.10.10.12"));
        assert_eq!(f.get("port").map(String::as_str), Some("3100")); // dst wins over src:0
        assert_eq!(
            f.get("exe").map(String::as_str),
            Some("/usr/bin/python3.13")
        ); // nested exe.path
        assert_eq!(f.get("process").map(String::as_str), Some("python3"));
        assert_eq!(f.get("user").map(String::as_str), Some("root"));
        assert_eq!(f.get("event_type").map(String::as_str), Some("connect"));
        assert_eq!(
            f.get("community_id").map(String::as_str),
            Some("1:/9h2X8wc6f2MS8gJSZN37tU9hCI=")
        );
        assert_eq!(
            f.get("cmdline").map(String::as_str),
            Some("/usr/bin/python3 /opt/talos-log-receiver/receiver.py")
        );
        // socket.domain ("AF_INET") must NOT be taken as a DNS domain.
        assert_eq!(f.get("dns"), None);
    }

    #[test]
    fn kunai_unknown_sentinel_and_socket_family_are_skipped() {
        // Live finding: a namespaced task with an unresolved user comes through
        // as "?", and the socket family "AF_INET" must not become dns.
        let line = r#"{"data":{"socket":{"domain":"AF_INET","type":"SOCK_STREAM","proto":"TCP"},"dst":{"hostname":"?","ip":"10.0.0.9","port":443}},"info":{"event":{"name":"connect"},"task":{"name":"curl","user":"?"}}}"#;
        let f = extract(line);
        assert_eq!(f.get("user"), None, "\"?\" unknown-sentinel skipped");
        assert_eq!(f.get("dns"), None, "socket family is not a DNS domain");
        assert_eq!(f.get("dst_ip").map(String::as_str), Some("10.0.0.9"));
        assert_eq!(f.get("event_type").map(String::as_str), Some("connect"));
        assert_eq!(f.get("process").map(String::as_str), Some("curl"));
    }

    #[test]
    fn kunai_acting_task_wins_over_parent_lineage() {
        // Privilege boundary: the parent (sudo) ran as alice, the execve'd task
        // is root. The normalized `user`/`process` must be the ACTING task, even
        // though `parent_task` sorts first alphabetically.
        let line = r#"{"info":{"event":{"name":"execve"},"parent_task":{"name":"sudo","user":"alice","pid":10},"task":{"name":"id","user":"root","pid":11}},"data":{"command_line":"id","exe":{"path":"/usr/bin/id"}}}"#;
        let f = extract(line);
        assert_eq!(
            f.get("user").map(String::as_str),
            Some("root"),
            "acting task, not parent"
        );
        assert_eq!(f.get("process").map(String::as_str), Some("id"));
        assert_eq!(f.get("event_type").map(String::as_str), Some("execve"));
        assert_eq!(f.get("exe").map(String::as_str), Some("/usr/bin/id"));
    }

    #[test]
    fn kunai_send_data_keeps_v4_mapped_v6() {
        // send_data carries IPv4-mapped IPv6 (::ffff:…) — must survive the IP
        // validity guard (it contains ':').
        let line = r#"{"data":{"command_line":"minio server /data","exe":{"path":"/usr/bin/minio"},"src":{"ip":"::ffff:172.17.0.2","port":9000},"dst":{"ip":"::ffff:192.168.68.56","port":36660},"community_id":"1:fKnTvsFPszlibjZSLxr/ZUfRcMc="},"info":{"event":{"name":"send_data"},"task":{"name":"minio","user":"root"}}}"#;
        let f = extract(line);
        assert_eq!(
            f.get("src_ip").map(String::as_str),
            Some("::ffff:172.17.0.2")
        );
        assert_eq!(
            f.get("dst_ip").map(String::as_str),
            Some("::ffff:192.168.68.56")
        );
        assert_eq!(f.get("event_type").map(String::as_str), Some("send_data"));
    }

    #[test]
    fn non_json_still_uses_text_regexes() {
        let f = extract("Failed password for root from 203.0.113.7 port 22 ssh2");
        assert_eq!(f.get("src_ip").map(String::as_str), Some("203.0.113.7"));
        assert_eq!(f.get("user").map(String::as_str), Some("root"));
    }

    #[test]
    fn extracts_registerlookup_audit_event() {
        // The app-level "who looked up whom" event: an explicit target_person
        // (the subject), the acting db_user, the client, the touched table, the
        // arende reference and the SQL. All six must land in normalized fields.
        let line = r#"{"db_user":"anna.h","client_addr":"10.0.0.12","target_person":"19850101-1234","object_table":"person","statement":"SELECT * FROM person WHERE pnr = $1","ticket_ref":"AR-2026-4711"}"#;
        let f = extract(line);
        assert_eq!(f.get("db_user").map(String::as_str), Some("anna.h"));
        assert_eq!(f.get("client_addr").map(String::as_str), Some("10.0.0.12"));
        assert_eq!(
            f.get("target_person").map(String::as_str),
            Some("19850101-1234")
        );
        assert_eq!(f.get("object_table").map(String::as_str), Some("person"));
        assert_eq!(
            f.get("statement").map(String::as_str),
            Some("SELECT * FROM person WHERE pnr = $1")
        );
        assert_eq!(
            f.get("ticket_ref").map(String::as_str),
            Some("AR-2026-4711")
        );
    }

    #[test]
    fn client_addr_keeps_hostname_and_local() {
        // Unlike src_ip, client_addr is NOT IP-guarded — pgaudit's %h is often a
        // hostname or the "[local]" sentinel, and dropping those would blind the
        // audit to unix-socket / hostname-resolved lookups.
        let f = extract(r#"{"db_user":"bob","client_addr":"reg-app-01.internal"}"#);
        assert_eq!(
            f.get("client_addr").map(String::as_str),
            Some("reg-app-01.internal")
        );
        let f2 = extract(r#"{"db_user":"bob","client_addr":"[local]"}"#);
        assert_eq!(f2.get("client_addr").map(String::as_str), Some("[local]"));
    }

    #[test]
    fn pgaudit_style_aliases_normalize() {
        // pgaudit / object-audit column names (session_user, object_name,
        // relation, remote_host) fold onto the same normalized fields.
        let line = r#"{"session_user":"carol","remote_host":"10.0.0.9","object_name":"folkbokforing","sql_text":"SELECT 1","diarienr":"DNR-2026-9"}"#;
        let f = extract(line);
        assert_eq!(f.get("db_user").map(String::as_str), Some("carol"));
        assert_eq!(f.get("client_addr").map(String::as_str), Some("10.0.0.9"));
        assert_eq!(
            f.get("object_table").map(String::as_str),
            Some("folkbokforing")
        );
        assert_eq!(f.get("statement").map(String::as_str), Some("SELECT 1"));
        assert_eq!(f.get("ticket_ref").map(String::as_str), Some("DNR-2026-9"));
    }

    #[test]
    fn generic_access_audit_vocabulary_normalizes() {
        // A NON-person, NON-SQL access audit (an API/document access log) using
        // fully generic key names must map onto the same normalized fields — the
        // audit surface is not person-register-locked.
        let line = r#"{"actor":"svc-billing","target":"acct-90210","resource_type":"invoice","action":"export","reason":"month-end run","origin":"10.0.0.44"}"#;
        let f = extract(line);
        assert_eq!(f.get("db_user").map(String::as_str), Some("svc-billing"));
        assert_eq!(
            f.get("target_person").map(String::as_str),
            Some("acct-90210")
        );
        assert_eq!(f.get("object_table").map(String::as_str), Some("invoice"));
        assert_eq!(f.get("action").map(String::as_str), Some("export"));
        assert_eq!(
            f.get("ticket_ref").map(String::as_str),
            Some("month-end run")
        );
        assert_eq!(f.get("client_addr").map(String::as_str), Some("10.0.0.44"));
    }

    #[test]
    fn audit_sensitivity_flags_accept_bool_and_string() {
        // The app-supplied flags let garmr key on "sensitive"/"self" access
        // without holding a watchlist or a staff→record map. Both JSON bool and
        // string forms must land.
        let b = extract(r#"{"actor":"anna.h","target":"x","watched":true,"is_self":false}"#);
        assert_eq!(b.get("watched").map(String::as_str), Some("true"));
        assert_eq!(b.get("is_self").map(String::as_str), Some("false"));
        let s = extract(r#"{"actor":"anna.h","target":"x","self_lookup":"true"}"#);
        assert_eq!(s.get("is_self").map(String::as_str), Some("true"));
    }
}