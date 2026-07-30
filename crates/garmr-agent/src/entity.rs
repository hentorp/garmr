// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Entity pages — hosts, IPs and users as first-class objects (M3:
//! "institutional memory"). Each assembler composes read-only queries over
//! the events lakehouse plus the case store into one JSON document that the
//! API, CLI and UI all serve verbatim.
//!
//! Query hygiene matches the tool surface: string identifiers are
//! quote-escaped, LIKE needles escape their metacharacters, and IPs must parse
//! as real addresses (which also guarantees no SQL/LIKE metachars).

use garmr_core::{Case, Result};
use garmr_store::Store;
use serde_json::{json, Value};
use skade::arrow_array::{Int64Array, RecordBatch};

/// Escape a string literal for embedding in single quotes.
fn q(s: &str) -> String {
    s.replace('\'', "''")
}

/// Escape LIKE metacharacters so a needle matches literally (pair with
/// `ESCAPE '\'` in the query).
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// First column of the first row as i64, defaulting to 0 (count queries).
fn scalar_i64(batches: &[RecordBatch]) -> i64 {
    batches
        .first()
        .filter(|b| b.num_rows() > 0)
        .and_then(|b| b.column(0).as_any().downcast_ref::<Int64Array>())
        .map(|a| a.value(0))
        .unwrap_or(0)
}

/// Render batches to an array of `{col: "string"}` rows (the same stringly
/// shape the query API serves).
fn rows_json(batches: &[RecordBatch], cap: usize) -> Vec<Value> {
    use skade::arrow_cast::display::{ArrayFormatter, FormatOptions};
    let mut out = Vec::new();
    let opts = FormatOptions::default();
    for b in batches {
        let names: Vec<String> = b
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        let fmts: Vec<_> = b
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c.as_ref(), &opts))
            .collect::<std::result::Result<_, _>>()
            .unwrap_or_default();
        if fmts.len() != names.len() {
            continue;
        }
        for row in 0..b.num_rows() {
            if out.len() >= cap {
                return out;
            }
            let mut obj = serde_json::Map::new();
            for (i, name) in names.iter().enumerate() {
                obj.insert(name.clone(), Value::String(fmts[i].value(row).to_string()));
            }
            out.push(Value::Object(obj));
        }
    }
    out
}

/// Case summary for an entity page.
fn case_json(c: &Case) -> Value {
    json!({
        "id": c.id,
        "state": c.state,
        "rule": c.trigger.rule_id,
        "level": c.trigger.level,
        "host": c.trigger.event.host,
        "event_count": c.event_count,
        "opened_at": c.opened_at,
        "updated_at": c.updated_at,
        "disposition": c.verdict.as_ref().map(|v| &v.disposition),
    })
}

/// The host page: volume, first/last seen, service mix, severity histogram,
/// recent events, and every case whose triggering event ran on this host.
pub async fn host_page(store: &Store, host: &str) -> Result<Value> {
    let h = q(host);
    // The six panel scans are independent read-only queries with no data
    // dependency, so issue them CONCURRENTLY (async I/O overlap) instead of six
    // serial awaits — the page's wall latency drops from sum-of-queries to
    // max-of-queries. `tokio::join!` is cooperative async concurrency on the
    // existing runtime, NOT a CPU fan-out, so ROOT LAW #0 (no rayon/thread::spawn)
    // doesn't apply; and each result keeps its original error handling
    // (`total`/`last_24h` propagate; the panels degrade to default) after the join.
    let (total, last_24h, span, services, severities, recent) = tokio::join!(
        store
            .events
            .sql(format!("SELECT count(*) FROM events WHERE host = '{h}'")),
        store.events.sql(format!(
            "SELECT count(*) FROM events WHERE host = '{h}' \
             AND event_ts >= now() - INTERVAL '24 hours'"
        )),
        store.events.sql(format!(
            "SELECT min(event_ts) AS first_seen, max(event_ts) AS last_seen \
             FROM events WHERE host = '{h}'"
        )),
        store.events.sql(format!(
            "SELECT service, count(*) AS n FROM events WHERE host = '{h}' \
             AND event_ts >= now() - INTERVAL '30 days' \
             GROUP BY service ORDER BY n DESC LIMIT 10"
        )),
        store.events.sql(format!(
            "SELECT severity, count(*) AS n FROM events WHERE host = '{h}' \
             AND event_ts >= now() - INTERVAL '7 days' \
             GROUP BY severity ORDER BY n DESC LIMIT 10"
        )),
        store.events.sql(format!(
            "SELECT event_ts, service, severity, message FROM events \
             WHERE host = '{h}' ORDER BY event_ts DESC LIMIT 20"
        )),
    );
    let total = total?;
    let last_24h = last_24h?;
    let span = span.map(|b| rows_json(&b, 1)).unwrap_or_default();
    let services = services.map(|b| rows_json(&b, 10)).unwrap_or_default();
    let severities = severities.map(|b| rows_json(&b, 10)).unwrap_or_default();
    let recent = recent.map(|b| rows_json(&b, 20)).unwrap_or_default();
    let cases: Vec<Value> = store
        .state
        .list_cases()?
        .iter()
        .filter(|c| c.trigger.event.host == host)
        .map(case_json)
        .collect();

    Ok(json!({
        "entity": "host",
        "name": host,
        "events_total": scalar_i64(&total),
        "events_24h": scalar_i64(&last_24h),
        "span": span.first().cloned().unwrap_or(Value::Null),
        "top_services_30d": services,
        "severity_7d": severities,
        "recent_events": recent,
        "cases": cases,
    }))
}

/// The IP page: sightings across `fields.src_ip`, the hosts it touched,
/// recent events, and cases triggered by events carrying this address.
/// The address must parse — which also means it carries no metacharacters.
pub async fn ip_page(store: &Store, ip: &str) -> Result<Value> {
    let addr: std::net::IpAddr = ip
        .parse()
        .map_err(|_| garmr_core::Error::store(format!("invalid IP: {ip}")))?;
    let needle = format!("%\"src_ip\":\"{addr}\"%");
    // Independent read-only scans — run concurrently (see `host_page`).
    let (sightings, hosts, recent) = tokio::join!(
        store.events.sql(format!(
            "SELECT count(*) AS n, min(event_ts) AS first_seen, max(event_ts) AS last_seen \
             FROM events WHERE fields LIKE '{needle}'"
        )),
        store.events.sql(format!(
            "SELECT host, count(*) AS n FROM events WHERE fields LIKE '{needle}' \
             GROUP BY host ORDER BY n DESC LIMIT 10"
        )),
        store.events.sql(format!(
            "SELECT event_ts, host, service, severity, message FROM events \
             WHERE fields LIKE '{needle}' ORDER BY event_ts DESC LIMIT 20"
        )),
    );
    let sightings = sightings.map(|b| rows_json(&b, 1)).unwrap_or_default();
    let hosts = hosts.map(|b| rows_json(&b, 10)).unwrap_or_default();
    let recent = recent.map(|b| rows_json(&b, 20)).unwrap_or_default();
    let ip_str = addr.to_string();
    let cases: Vec<Value> = store
        .state
        .list_cases()?
        .iter()
        .filter(|c| {
            c.trigger
                .event
                .fields
                .get("src_ip")
                .is_some_and(|v| *v == ip_str)
        })
        .map(case_json)
        .collect();

    Ok(json!({
        "entity": "ip",
        "name": ip_str,
        "sightings": sightings.first().cloned().unwrap_or(Value::Null),
        "hosts": hosts,
        "recent_events": recent,
        "cases": cases,
    }))
}

/// The user page: activity across `fields.user`, the hosts the account was
/// seen on, recent events, and cases triggered by events carrying this user.
pub async fn user_page(store: &Store, user: &str) -> Result<Value> {
    // The fields column stores serde_json output, so the needle must match the
    // JSON ENCODING of the name (a user with `\` or `"` is stored escaped) —
    // encode first, then LIKE-escape, then quote-escape.
    // Slice exactly one quote off each end (trim_matches would also eat a
    // trailing ESCAPED quote's closing character).
    let json_encoded = serde_json::to_string(user).unwrap_or_else(|_| "\"\"".into());
    let inner = &json_encoded[1..json_encoded.len() - 1];
    let esc = q(&like_escape(inner));
    let needle = format!("%\"user\":\"{esc}\"%");
    // Independent read-only scans — run concurrently (see `host_page`).
    let (activity, hosts, recent) = tokio::join!(
        store.events.sql(format!(
            "SELECT count(*) AS n, min(event_ts) AS first_seen, max(event_ts) AS last_seen \
             FROM events WHERE fields LIKE '{needle}' ESCAPE '\\'"
        )),
        store.events.sql(format!(
            "SELECT host, count(*) AS n FROM events WHERE fields LIKE '{needle}' ESCAPE '\\' \
             GROUP BY host ORDER BY n DESC LIMIT 10"
        )),
        store.events.sql(format!(
            "SELECT event_ts, host, service, severity, message FROM events \
             WHERE fields LIKE '{needle}' ESCAPE '\\' ORDER BY event_ts DESC LIMIT 20"
        )),
    );
    let activity = activity.map(|b| rows_json(&b, 1)).unwrap_or_default();
    let hosts = hosts.map(|b| rows_json(&b, 10)).unwrap_or_default();
    let recent = recent.map(|b| rows_json(&b, 20)).unwrap_or_default();
    let cases: Vec<Value> = store
        .state
        .list_cases()?
        .iter()
        .filter(|c| {
            c.trigger
                .event
                .fields
                .get("user")
                .is_some_and(|v| v == user)
        })
        .map(case_json)
        .collect();

    Ok(json!({
        "entity": "user",
        "name": user,
        "activity": activity.first().cloned().unwrap_or(Value::Null),
        "hosts": hosts,
        "recent_events": recent,
        "cases": cases,
    }))
}

/// The LIKE needle matching `"<field>":"<value>"` in the serde_json `fields`
/// column: JSON-encode the value (so `\`/`"` match as stored), then LIKE-escape,
/// then quote-escape — the same hygiene as `user_page`. Pair with `ESCAPE '\\'`.
fn field_needle(field: &str, value: &str) -> String {
    let json_encoded = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into());
    let inner = &json_encoded[1..json_encoded.len() - 1];
    let esc = q(&like_escape(inner));
    format!("%\"{field}\":\"{esc}\"%")
}

/// A SQL fragment pulling `fields.<key>` out of the JSON column, NULL when the
/// key is absent (regexp_replace returns the whole input on no-match, so
/// `NULLIF(.., fields)` collapses that to NULL — a real capture is a strict
/// substring, never == fields). Mirrors the graph builder's extraction.
fn field_expr(key: &str) -> String {
    format!("NULLIF(regexp_replace(fields, '.*\"{key}\":\"([^\"]+)\".*', '$1'), fields)")
}

/// The staff (case officer) page — "what did staff member X look up?": lookup
/// volume, the persons and tables they touched most, recent lookups, and every
/// case the db_user triggered. One half of the registerkontroll investigation surface.
pub async fn staff_page(store: &Store, db_user: &str) -> Result<Value> {
    let needle = field_needle("db_user", db_user);
    let base = format!("FROM events WHERE fields LIKE '{needle}' ESCAPE '\\'");
    // Four independent read-only scans — run concurrently (see `host_page`).
    let (activity, top_targets, recent, recent_events) = tokio::join!(
        store.events.sql(format!(
            "SELECT count(*) AS n, min(event_ts) AS first_seen, max(event_ts) AS last_seen {base}"
        )),
        store.events.sql(format!(
            "SELECT {tp} AS target_person, count(*) AS n {base} \
             GROUP BY 1 ORDER BY n DESC LIMIT 10",
            tp = field_expr("target_person"),
        )),
        store.events.sql(format!(
            "SELECT event_ts, {tp} AS target_person, {ot} AS object_table, \
             {tr} AS ticket_ref {base} ORDER BY event_ts DESC LIMIT 25",
            tp = field_expr("target_person"),
            ot = field_expr("object_table"),
            tr = field_expr("ticket_ref"),
        )),
        // Standard-shape recent list so the kind-driven UI renderer reuses as-is.
        store.events.sql(format!(
            "SELECT event_ts, service, severity, message {base} ORDER BY event_ts DESC LIMIT 20"
        )),
    );
    let activity = activity.map(|b| rows_json(&b, 1)).unwrap_or_default();
    let top_targets = top_targets.map(|b| rows_json(&b, 10)).unwrap_or_default();
    let recent = recent.map(|b| rows_json(&b, 25)).unwrap_or_default();
    let recent_events = recent_events.map(|b| rows_json(&b, 20)).unwrap_or_default();
    let cases: Vec<Value> = store
        .state
        .list_cases()?
        .iter()
        .filter(|c| {
            c.trigger
                .event
                .fields
                .get("db_user")
                .is_some_and(|v| v == db_user)
        })
        .map(case_json)
        .collect();

    Ok(json!({
        "entity": "staff",
        "name": db_user,
        "activity": activity.first().cloned().unwrap_or(Value::Null),
        "top_targets": top_targets,
        "lookups": recent,
        "recent_events": recent_events,
        "cases": cases,
    }))
}

/// The person page — "who looked up person Y?": how often the record was read,
/// which case officer read it, recent lookups (with client + case ref), and cases
/// naming this person. The subject-side half of the investigation surface.
pub async fn person_page(store: &Store, target_person: &str) -> Result<Value> {
    let needle = field_needle("target_person", target_person);
    let base = format!("FROM events WHERE fields LIKE '{needle}' ESCAPE '\\'");
    // Four independent read-only scans — run concurrently (see `host_page`).
    let (activity, by_staff, recent, recent_events) = tokio::join!(
        store.events.sql(format!(
            "SELECT count(*) AS n, min(event_ts) AS first_seen, max(event_ts) AS last_seen {base}"
        )),
        store.events.sql(format!(
            "SELECT {du} AS db_user, count(*) AS n {base} \
             GROUP BY 1 ORDER BY n DESC LIMIT 10",
            du = field_expr("db_user"),
        )),
        store.events.sql(format!(
            "SELECT event_ts, {du} AS db_user, {ca} AS client_addr, {tr} AS ticket_ref {base} \
             ORDER BY event_ts DESC LIMIT 25",
            du = field_expr("db_user"),
            ca = field_expr("client_addr"),
            tr = field_expr("ticket_ref"),
        )),
        store.events.sql(format!(
            "SELECT event_ts, service, severity, message {base} ORDER BY event_ts DESC LIMIT 20"
        )),
    );
    let activity = activity.map(|b| rows_json(&b, 1)).unwrap_or_default();
    let by_staff = by_staff.map(|b| rows_json(&b, 10)).unwrap_or_default();
    let recent = recent.map(|b| rows_json(&b, 25)).unwrap_or_default();
    let recent_events = recent_events.map(|b| rows_json(&b, 20)).unwrap_or_default();
    let cases: Vec<Value> = store
        .state
        .list_cases()?
        .iter()
        .filter(|c| {
            c.trigger
                .event
                .fields
                .get("target_person")
                .is_some_and(|v| v == target_person)
        })
        .map(case_json)
        .collect();

    Ok(json!({
        "entity": "person",
        "name": target_person,
        "activity": activity.first().cloned().unwrap_or(Value::Null),
        "by_staff": by_staff,
        "lookups": recent,
        "recent_events": recent_events,
        "cases": cases,
    }))
}
