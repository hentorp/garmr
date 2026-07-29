// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 2 — first-class PostgreSQL / pgAudit ingestion.
//!
//! Parses PostgreSQL server logs into canonical audit [`Event`]s: the CSV log
//! format (`csvlog`), the JSON log format (`jsonlog`, PG 15+), and the pgAudit
//! extension's session/object entries embedded in either. Each parsed statement
//! is run through [`garmr_sql::analyze`] so its structure (tables, columns,
//! privilege targets, fingerprint, bulk/export/privilege flags) lands in the
//! event fields for policy, detectors, and search — without anyone re-parsing
//! the SQL downstream.
//!
//! The output speaks the Phase-1 canonical vocabulary
//! ([`garmr_core::AuditRecord`]): actor/database/statement/object/justification/
//! classification map onto the storage-canonical keys, so the existing access-
//! audit pipeline (correlation SQL, per-actor RBA, staff/person pivots, alert
//! bodies) works unchanged, and the richer typed model is available on top.
//!
//! Parsing is DEFENSIVE and never hard-fails a batch: a malformed row is
//! counted in [`PgParseHealth`] and skipped, so one bad line can't stop ingest.
//! The CSV reader handles multiline statements (newlines inside a quoted field),
//! doubled-quote escaping, commas in statements, and comments in SQL.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use garmr_core::app_audit::keys;
use garmr_core::{AuditRecord, Error, Event, Result};
use serde_json::Value;

use crate::adapter::Adapter;

/// The parser version, stamped onto every event's provenance and bumped on any
/// mapping change (so a downstream behavior change is auditable, not silent).
pub const PG_PARSER_VERSION: &str = "pg-1.0";

/// Health counters for a parse pass — surfaced to operators so silent data loss
/// or a format mismatch is visible rather than an unexplained gap.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PgParseHealth {
    /// Rows turned into events.
    pub parsed: u64,
    /// Rows that could not be parsed at all (skipped).
    pub rejected: u64,
    /// Rows parsed but missing an expected field (still emitted).
    pub partial: u64,
    /// Rows whose shape matched no known format.
    pub unknown_format: u64,
    /// Statements that appear truncated by the source.
    pub truncated_statement: u64,
    /// Rows with an unparseable timestamp (emitted with receive time).
    pub invalid_timestamp: u64,
    /// Rows with no principal (actor) — an audit event with no "who".
    pub missing_principal: u64,
    /// Rows with no database.
    pub missing_database: u64,
}

/// The subset of PostgreSQL log fields the canonical mapping needs, extracted
/// from either csvlog columns or jsonlog keys before the shared build step.
#[derive(Debug, Default, Clone)]
struct PgLogRecord {
    log_time: String,
    user_name: String,
    database_name: String,
    connection_from: String,
    session_id: String,
    transaction_id: String,
    error_severity: String,
    sql_state: String,
    message: String,
    /// The `query` / detail column, a fallback source of the statement text.
    query: String,
    command_tag: String,
    application_name: String,
    backend_type: String,
}

// -------------------------------------------------------------------------
// public entry points
// -------------------------------------------------------------------------

/// Parse PostgreSQL `csvlog` text into events + health. `host` labels the DB
/// server (csvlog carries no host); `default_environment` fills the env label.
pub fn parse_csvlog(
    text: &str,
    host: &str,
    default_environment: &str,
) -> (Vec<Event>, PgParseHealth) {
    let mut events = Vec::new();
    let mut health = PgParseHealth::default();
    for row in parse_csv_records(text) {
        if row.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        match csvlog_row_to_record(&row) {
            Some(rec) => {
                let ev = build_event(rec, host, default_environment, &mut health);
                events.push(ev);
            }
            None => health.rejected += 1,
        }
    }
    (events, health)
}

/// Parse PostgreSQL `jsonlog` (one JSON object per line, PG 15+) into events +
/// health.
pub fn parse_jsonlog(
    text: &str,
    host: &str,
    default_environment: &str,
) -> (Vec<Event>, PgParseHealth) {
    let mut events = Vec::new();
    let mut health = PgParseHealth::default();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => {
                let rec = jsonlog_value_to_record(&v);
                let ev = build_event(rec, host, default_environment, &mut health);
                events.push(ev);
            }
            Err(_) => health.rejected += 1,
        }
    }
    (events, health)
}

// -------------------------------------------------------------------------
// csvlog column mapping
// -------------------------------------------------------------------------

// PostgreSQL csvlog column order (stable prefix across supported versions).
const C_LOG_TIME: usize = 0;
const C_USER: usize = 1;
const C_DATABASE: usize = 2;
const C_CONNECTION_FROM: usize = 4;
const C_SESSION_ID: usize = 5;
const C_COMMAND_TAG: usize = 7;
const C_TRANSACTION_ID: usize = 10;
const C_ERROR_SEVERITY: usize = 11;
const C_SQL_STATE: usize = 12;
const C_MESSAGE: usize = 13;
const C_QUERY: usize = 19;
const C_APPLICATION_NAME: usize = 22;
const C_BACKEND_TYPE: usize = 23;

fn at(row: &[String], i: usize) -> String {
    row.get(i).cloned().unwrap_or_default()
}

fn csvlog_row_to_record(row: &[String]) -> Option<PgLogRecord> {
    // The stable prefix runs through the message column; require at least that.
    if row.len() <= C_MESSAGE {
        return None;
    }
    Some(PgLogRecord {
        log_time: at(row, C_LOG_TIME),
        user_name: at(row, C_USER),
        database_name: at(row, C_DATABASE),
        connection_from: at(row, C_CONNECTION_FROM),
        session_id: at(row, C_SESSION_ID),
        transaction_id: at(row, C_TRANSACTION_ID),
        error_severity: at(row, C_ERROR_SEVERITY),
        sql_state: at(row, C_SQL_STATE),
        message: at(row, C_MESSAGE),
        query: at(row, C_QUERY),
        command_tag: at(row, C_COMMAND_TAG),
        application_name: at(row, C_APPLICATION_NAME),
        backend_type: at(row, C_BACKEND_TYPE),
    })
}

fn json_str(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
        // jsonlog encodes some ids as numbers.
        if let Some(n) = v.get(*k).and_then(Value::as_i64) {
            return n.to_string();
        }
    }
    String::new()
}

fn jsonlog_value_to_record(v: &Value) -> PgLogRecord {
    PgLogRecord {
        log_time: json_str(v, &["timestamp", "log_time"]),
        user_name: json_str(v, &["user", "user_name", "session_user"]),
        database_name: json_str(v, &["dbname", "database_name", "database"]),
        connection_from: json_str(v, &["remote_host", "connection_from"]),
        session_id: json_str(v, &["session_id"]),
        transaction_id: json_str(v, &["txid", "transaction_id"]),
        error_severity: json_str(v, &["error_severity"]),
        sql_state: json_str(v, &["state_code", "sql_state_code"]),
        message: json_str(v, &["message"]),
        query: json_str(v, &["query", "statement"]),
        command_tag: json_str(v, &["command_tag"]),
        application_name: json_str(v, &["application_name"]),
        backend_type: json_str(v, &["backend_type"]),
    }
}

// -------------------------------------------------------------------------
// pgAudit message parsing
// -------------------------------------------------------------------------

/// The fields of a pgAudit log entry (session or object logging).
#[derive(Debug, Default, Clone)]
struct PgAudit {
    audit_type: String,
    class: String,
    command: String,
    object_type: String,
    object_name: String,
    statement: String,
}

/// Parse a pgAudit message: `AUDIT: SESSION,<sid>,<ssid>,<class>,<command>,
/// <object_type>,<object_name>,<statement>[,<parameter>]`. Returns `None` when
/// the message is not a pgAudit entry.
fn parse_pgaudit(message: &str) -> Option<PgAudit> {
    let body = message.trim_start().strip_prefix("AUDIT:")?.trim_start();
    // The body is itself CSV (the statement field may contain commas/quotes).
    let fields = parse_csv_records(body)
        .into_iter()
        .next()
        .unwrap_or_default();
    let g = |i: usize| fields.get(i).cloned().unwrap_or_default();
    Some(PgAudit {
        audit_type: g(0),
        class: g(3),
        command: g(4),
        object_type: g(5),
        object_name: g(6),
        statement: g(7),
    })
}

/// Pull a bare statement out of a plain (non-pgAudit) log message such as
/// `statement: SELECT …`, `execute <name>: SELECT …`, or
/// `duration: 1.2 ms  statement: SELECT …`.
fn statement_from_message(message: &str) -> Option<String> {
    let m = message.trim();
    for marker in ["statement:", "execute", "STATEMENT:"] {
        if let Some(pos) = m.find(marker) {
            let rest = &m[pos + marker.len()..];
            // `execute <name>: <sql>` — skip to the colon.
            let sql = match rest.find(':') {
                Some(c) if marker == "execute" => rest[c + 1..].trim(),
                _ => rest.trim_start_matches(':').trim(),
            };
            if !sql.is_empty() {
                return Some(sql.to_string());
            }
        }
    }
    None
}

// -------------------------------------------------------------------------
// shared record → event build
// -------------------------------------------------------------------------

fn build_event(
    rec: PgLogRecord,
    host: &str,
    default_environment: &str,
    health: &mut PgParseHealth,
) -> Event {
    let pgaudit = parse_pgaudit(&rec.message);
    let is_audit = pgaudit.is_some();

    // Resolve the statement text: pgAudit's field, else a `statement:`-style
    // message, else the query column.
    let statement = pgaudit
        .as_ref()
        .map(|p| p.statement.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| statement_from_message(&rec.message))
        .or_else(|| (!rec.query.is_empty()).then(|| rec.query.clone()))
        .unwrap_or_default();

    // Build the canonical typed record.
    let mut ar = AuditRecord::default();
    ar.actor.actor_id = rec.user_name.clone();
    if !rec.user_name.is_empty() {
        ar.actor.authenticated_identity = Some(rec.user_name.clone());
    }
    ar.context.database = non_empty(&rec.database_name);
    ar.context.session_id = non_empty(&rec.session_id);
    ar.context.transaction_id = non_empty(&rec.transaction_id);
    ar.context.client_application = non_empty(&rec.application_name);
    let (chost, cip) = split_host_port(&rec.connection_from);
    ar.context.client_host = non_empty(&chost);
    ar.context.client_ip = cip;

    if let Some(p) = &pgaudit {
        ar.action.action = non_empty(&p.command).or_else(|| non_empty(&rec.command_tag));
        ar.action.object_type = non_empty(&p.object_type);
        ar.action.object_name = non_empty(&p.object_name);
    } else {
        ar.action.action = non_empty(&rec.command_tag);
    }
    if !statement.is_empty() {
        ar.action.statement = Some(statement.clone());
    }
    ar.action.error_code = non_empty(&rec.sql_state);
    ar.action.outcome = outcome_of(&rec.error_severity, &rec.sql_state);

    ar.classification.source_trust = Some("postgres".to_string());
    ar.classification.parser_version = Some(PG_PARSER_VERSION.to_string());

    // Run the SQL analyzer over the statement and fold its structure in.
    let mut extra: BTreeMap<String, String> = BTreeMap::new();
    if !statement.is_empty() {
        let a = garmr_sql::analyze(&statement);
        // query_type / fingerprint / bulk / export / privilege / admin flags.
        extra.extend(a.to_audit_fields());
        put_list(&mut extra, "sql_read_tables", &a.read_tables);
        put_list(&mut extra, "sql_written_tables", &a.written_tables);
        put_list(&mut extra, "sql_columns", &a.referenced_columns);
        put_list(&mut extra, "sql_privilege_targets", &a.privilege_targets);
        put_list(&mut extra, "sql_role_changes", &a.role_changes);
        if !a.unresolved_objects.is_empty() {
            put_list(&mut extra, "sql_unresolved_objects", &a.unresolved_objects);
        }
        extra.insert(
            "sql_statement_type".to_string(),
            a.statement_type.as_str().to_string(),
        );
        extra.insert(
            "sql_parser_confidence".to_string(),
            format!("{:?}", a.parser_confidence).to_lowercase(),
        );
        // Statement truncation heuristic (pgAudit truncates very long SQL).
        if statement.trim_end().ends_with("...") || statement.len() >= 8192 {
            health.truncated_statement += 1;
        }
    }
    // pgAudit provenance for search/detectors.
    if let Some(p) = &pgaudit {
        insert_ne(&mut extra, "pgaudit_type", &p.audit_type);
        insert_ne(&mut extra, "pgaudit_class", &p.class);
        insert_ne(&mut extra, "pgaudit_command", &p.command);
    }
    insert_ne(&mut extra, "backend_type", &rec.backend_type);

    // Health accounting.
    if ar.actor.actor_id.is_empty() {
        health.missing_principal += 1;
    }
    if ar.context.database.is_none() {
        health.missing_database += 1;
    }
    if is_audit && (ar.actor.actor_id.is_empty() || statement.is_empty()) {
        health.partial += 1;
    }
    health.parsed += 1;

    // Timestamp.
    let ts = match parse_pg_ts(&rec.log_time) {
        Some(t) => t,
        None => {
            if !rec.log_time.is_empty() {
                health.invalid_timestamp += 1;
            }
            Utc::now()
        }
    };

    // Compose the fields map: canonical audit keys + SQL structure + legacy
    // compatibility keys the access-audit pipeline reads.
    let mut fields = ar.to_fields();
    for (k, v) in extra {
        fields.entry(k).or_insert(v);
    }
    // Backward-compat: AccessProjection + correlation SQL read `client_addr`.
    if !fields.contains_key(keys::CLIENT) {
        if let Some(c) = fields
            .get(keys::CLIENT_HOST)
            .or_else(|| fields.get(keys::CLIENT_IP))
            .cloned()
        {
            fields.insert(keys::CLIENT.to_string(), c);
        }
    }

    // The message is the grep/search surface and the raw-payload-hash basis: use
    // the statement when we have one, else the original log message.
    let message = if statement.is_empty() {
        rec.message.clone()
    } else {
        statement
    };

    Event {
        ts,
        host: host.into(),
        service: "postgres".into(),
        source: if is_audit {
            "pgaudit".into()
        } else {
            "postgres".into()
        },
        environment: default_environment.into(),
        severity: severity_of(&rec.error_severity).into(),
        // Audit-relevant if: a pgAudit entry, a statement log, OR a denied/failed
        // access by a known actor (a statement-less "permission denied for table
        // x" must still reach the audit plane so the probing detector can fire).
        // A bare connection/checkpoint log is app-level noise.
        log_type: if is_audit
            || fields.contains_key(keys::STATEMENT)
            || (ar.action.outcome.is_negative() && !ar.actor.actor_id.is_empty())
        {
            garmr_core::AUDIT_LOG_TYPE.into()
        } else {
            "app".into()
        },
        message,
        fields,
    }
}

// -------------------------------------------------------------------------
// small helpers
// -------------------------------------------------------------------------

fn non_empty(s: &str) -> Option<String> {
    (!s.trim().is_empty()).then(|| s.trim().to_string())
}

fn insert_ne(m: &mut BTreeMap<String, String>, k: &str, v: &str) {
    if !v.trim().is_empty() {
        m.insert(k.to_string(), v.trim().to_string());
    }
}

fn put_list(m: &mut BTreeMap<String, String>, k: &str, list: &[String]) {
    if !list.is_empty() {
        m.insert(k.to_string(), list.join(","));
    }
}

/// Split PostgreSQL's `connection_from` (`host:port`, `[local]`, or an IP) into
/// (host, optional-ip).
fn split_host_port(cf: &str) -> (String, Option<String>) {
    let cf = cf.trim();
    if cf.is_empty() || cf == "[local]" {
        return (cf.to_string(), None);
    }
    // Strip a trailing `:port` when the port is numeric.
    let host = match cf.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => cf,
    };
    let ip = host
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|_| host.to_string());
    (host.to_string(), ip)
}

fn severity_of(pg_severity: &str) -> String {
    match pg_severity.to_ascii_uppercase().as_str() {
        "PANIC" | "FATAL" => "critical",
        "ERROR" => "error",
        "WARNING" => "warning",
        "NOTICE" | "INFO" | "LOG" | "DEBUG" | "DEBUG1" | "DEBUG2" => "info",
        _ => "info",
    }
    .to_string()
}

fn outcome_of(pg_severity: &str, sql_state: &str) -> garmr_core::Outcome {
    use garmr_core::Outcome;
    // Insufficient privilege → denied, whatever the severity text.
    if sql_state == "42501" {
        return Outcome::Denied;
    }
    match pg_severity.to_ascii_uppercase().as_str() {
        "PANIC" | "FATAL" => Outcome::Error,
        "ERROR" => Outcome::Failure,
        "" => Outcome::Unknown,
        _ => Outcome::Success,
    }
}

/// Parse a PostgreSQL log timestamp (`2024-06-01 12:34:56.789 UTC`, a numeric
/// offset, or RFC3339 from jsonlog).
fn parse_pg_ts(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // jsonlog RFC3339 / ISO8601.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Numeric-offset csvlog: "2024-06-01 12:34:56.789+02".
    for fmt in ["%Y-%m-%d %H:%M:%S%.f%#z", "%Y-%m-%d %H:%M:%S%.f %z"] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    // Named-zone csvlog: strip the trailing zone token, treat the rest as UTC
    // (the common "… UTC"/"… GMT" case; other named zones lose their offset but
    // keep the wall-clock — better than dropping the event).
    let core = match s.rsplit_once(' ') {
        Some((dt, zone)) if !zone.is_empty() && !zone.chars().next().unwrap().is_ascii_digit() => {
            dt
        }
        _ => s,
    };
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(core, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
        }
    }
    None
}

// -------------------------------------------------------------------------
// a minimal RFC4180 CSV reader (multiline-aware)
// -------------------------------------------------------------------------

/// Parse CSV text into records (rows of fields). Handles quoted fields with
/// embedded commas / newlines and doubled-quote (`""`) escapes — the shape
/// PostgreSQL csvlog and pgAudit both emit. A record ends at a newline that is
/// not inside quotes.
fn parse_csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    let mut saw_any = false;

    while let Some(c) = chars.next() {
        saw_any = true;
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    record.push(std::mem::take(&mut field));
                }
                '\n' => {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                '\r' => {} // swallow CR (CRLF)
                _ => field.push(c),
            }
        }
    }
    // Flush a trailing field/record with no closing newline.
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    } else if !saw_any {
        // empty input → no records
    }
    records
}

// -------------------------------------------------------------------------
// adapters
// -------------------------------------------------------------------------

/// PostgreSQL csvlog adapter (with embedded pgAudit). The `host` label defaults
/// to `postgres` for the trait entry point; the offline-import path can set a
/// real host.
pub struct PgCsvlogAdapter;

impl Adapter for PgCsvlogAdapter {
    fn name(&self) -> &str {
        "postgres-csvlog"
    }
    fn version(&self) -> &str {
        PG_PARSER_VERSION
    }
    fn parse(&self, raw: &[u8], default_environment: &str) -> Result<Vec<Event>> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| Error::Ingest(format!("csvlog: invalid utf-8: {e}")))?;
        let (events, health) = parse_csvlog(text, "postgres", default_environment);
        tracing::info!(target: "garmr_ingest::pg", ?health, "parsed postgres csvlog");
        Ok(events)
    }
}

/// PostgreSQL jsonlog adapter (PG 15+, with embedded pgAudit).
pub struct PgJsonlogAdapter;

impl Adapter for PgJsonlogAdapter {
    fn name(&self) -> &str {
        "postgres-jsonlog"
    }
    fn version(&self) -> &str {
        PG_PARSER_VERSION
    }
    fn parse(&self, raw: &[u8], default_environment: &str) -> Result<Vec<Event>> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| Error::Ingest(format!("jsonlog: invalid utf-8: {e}")))?;
        let (events, health) = parse_jsonlog(text, "postgres", default_environment);
        tracing::info!(target: "garmr_ingest::pg", ?health, "parsed postgres jsonlog");
        Ok(events)
    }
}

#[cfg(test)]
mod tests;