// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use garmr_core::app_audit::keys;

/// Build a 26-column PostgreSQL csvlog line, quoting the message + application
/// columns (which may contain commas). Only the columns the parser reads are
/// meaningfully set; the rest are plausible placeholders.
#[allow(clippy::too_many_arguments)] // a test builder mirroring csvlog's columns
fn csvline(
    user: &str,
    db: &str,
    conn: &str,
    command_tag: &str,
    severity: &str,
    sqlstate: &str,
    message: &str,
    app: &str,
) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let cols = [
        "2024-06-01 12:00:00.123 UTC".to_string(), // 0 log_time
        q(user),                                   // 1 user
        q(db),                                     // 2 database
        "4711".to_string(),                        // 3 pid
        q(conn),                                   // 4 connection_from
        q("6650abcd.1"),                           // 5 session_id
        "1".to_string(),                           // 6 line
        q(command_tag),                            // 7 command_tag
        "2024-06-01 12:00:00 UTC".to_string(),     // 8 session_start
        q("3/15"),                                 // 9 vxid
        "0".to_string(),                           // 10 txid
        q(severity),                               // 11 severity
        q(sqlstate),                               // 12 sqlstate
        q(message),                                // 13 message
        String::new(),                             // 14 detail
        String::new(),                             // 15 hint
        String::new(),                             // 16 internal_query
        String::new(),                             // 17 iq_pos
        String::new(),                             // 18 context
        String::new(),                             // 19 query
        String::new(),                             // 20 q_pos
        q("auth.c:1"),                             // 21 location
        q(app),                                    // 22 application_name
        q("client backend"),                       // 23 backend_type
        String::new(),                             // 24 leader_pid
        String::new(),                             // 25 query_id
    ];
    cols.join(",")
}

/// A pgAudit SESSION message body for the message column.
fn pgaudit(class: &str, command: &str, obj_type: &str, obj_name: &str, stmt: &str) -> String {
    format!("AUDIT: SESSION,1,1,{class},{command},{obj_type},{obj_name},{stmt},<none>")
}

fn one_csv(line: &str) -> Event {
    let (ev, _h) = parse_csvlog(line, "db01", "prod");
    ev.into_iter().next().expect("one event")
}

#[test]
fn pgaudit_select_maps_to_canonical_and_analyzes_sql() {
    let msg = pgaudit(
        "READ",
        "SELECT",
        "TABLE",
        "public.persons",
        "SELECT pnr FROM public.persons WHERE id = 42",
    );
    let ev = one_csv(&csvline(
        "caseworker7",
        "registry",
        "10.0.0.5:52001",
        "SELECT",
        "LOG",
        "00000",
        &msg,
        "psql",
    ));
    // canonical + legacy compatibility keys.
    assert_eq!(ev.log_type, "audit");
    assert_eq!(ev.source, "pgaudit");
    assert_eq!(ev.field(keys::ACTOR), Some("caseworker7"));
    assert_eq!(ev.field(keys::DATABASE), Some("registry"));
    assert_eq!(ev.field(keys::OBJECT_NAME), Some("public.persons"));
    assert_eq!(ev.field(keys::CLIENT), Some("10.0.0.5")); // legacy client_addr for AccessProjection
    assert_eq!(ev.field("client_ip"), Some("10.0.0.5"));
    assert_eq!(ev.field("pgaudit_command"), Some("SELECT"));
    // SQL analysis folded in.
    assert_eq!(ev.field(keys::QUERY_TYPE), Some("select"));
    assert!(ev
        .field(keys::STATEMENT_FINGERPRINT)
        .unwrap()
        .starts_with("sql1:"));
    assert_eq!(ev.field("sql_read_tables"), Some("public.persons"));
    // AccessProjection (the existing access-audit lens) still works.
    let p = garmr_core::AccessProjection::from_event(&ev).unwrap();
    assert_eq!(p.actor.id, "caseworker7");
}

#[test]
fn dml_and_ddl_and_privilege_commands() {
    // want_qtype is the COARSE canonical query_type (garmr_core::QueryType).
    let cases = [
        (
            "INSERT",
            "WRITE",
            "INSERT INTO t VALUES (1)",
            "insert",
            false,
        ),
        (
            "UPDATE",
            "WRITE",
            "UPDATE t SET a = 1 WHERE id = 2",
            "update",
            false,
        ),
        (
            "DELETE",
            "WRITE",
            "DELETE FROM t WHERE id = 2",
            "delete",
            false,
        ),
        (
            "CREATE TABLE",
            "DDL",
            "CREATE TABLE public.t (id int)",
            "create",
            false,
        ),
        (
            "ALTER TABLE",
            "DDL",
            "ALTER TABLE t ADD COLUMN c int",
            "alter",
            false,
        ),
        ("DROP TABLE", "DDL", "DROP TABLE t", "drop", false),
        (
            "GRANT",
            "ROLE",
            "GRANT SELECT ON persons TO analyst",
            "grant",
            true,
        ),
        (
            "REVOKE",
            "ROLE",
            "REVOKE SELECT ON persons FROM analyst",
            "revoke",
            true,
        ),
    ];
    for (command, class, stmt, want_qtype, is_priv) in cases {
        let obj = if class == "DDL" { "TABLE" } else { "" };
        let msg = pgaudit(class, command, obj, "public.t", stmt);
        let ev = one_csv(&csvline(
            "dba", "app", "[local]", command, "LOG", "00000", &msg, "psql",
        ));
        assert_eq!(
            ev.field(keys::QUERY_TYPE),
            Some(want_qtype),
            "qtype for {command}"
        );
        if is_priv {
            assert_eq!(
                ev.field(keys::PRIVILEGE_OPERATION),
                Some("true"),
                "privilege flag for {command}"
            );
        }
    }
}

#[test]
fn set_role_is_a_privilege_operation() {
    let msg = pgaudit("ROLE", "SET", "", "", "SET ROLE dbadmin");
    let ev = one_csv(&csvline(
        "app", "app", "[local]", "SET", "LOG", "00000", &msg, "psql",
    ));
    assert_eq!(ev.field(keys::QUERY_TYPE), Some("set_role"));
    assert_eq!(ev.field(keys::PRIVILEGE_OPERATION), Some("true"));
    assert_eq!(ev.field("sql_role_changes"), Some("dbadmin"));
}

#[test]
fn copy_export_marks_bulk_and_export() {
    let msg = pgaudit(
        "READ",
        "COPY",
        "TABLE",
        "public.persons",
        "COPY public.persons TO '/tmp/x.csv'",
    );
    let ev = one_csv(&csvline(
        "etl",
        "registry",
        "10.0.0.9:5000",
        "COPY",
        "LOG",
        "00000",
        &msg,
        "psql",
    ));
    assert_eq!(ev.field(keys::QUERY_TYPE), Some("copy"));
    assert_eq!(ev.field(keys::EXPORT_OPERATION), Some("true"));
    assert_eq!(ev.field(keys::BULK_OPERATION), Some("true"));
}

#[test]
fn permission_denied_is_a_denied_outcome() {
    // A plain ERROR log (not pgAudit): permission denied, SQLSTATE 42501.
    let ev = one_csv(&csvline(
        "intern",
        "registry",
        "10.0.0.7:6001",
        "SELECT",
        "ERROR",
        "42501",
        "permission denied for table persons",
        "psql",
    ));
    assert_eq!(ev.field(keys::OUTCOME), Some("denied"));
    assert_eq!(ev.field(keys::ERROR_CODE), Some("42501"));
    assert_eq!(ev.severity, "error");
}

#[test]
fn permission_denied_without_statement_reaches_the_audit_plane() {
    // A statement-less "permission denied" by a known actor must be log_type=audit
    // so the probing detector can fire (review finding #9).
    let ev = one_csv(&csvline(
        "intern",
        "registry",
        "10.0.0.7:6001",
        "",
        "ERROR",
        "42501",
        "permission denied for table persons",
        "psql",
    ));
    assert_eq!(ev.log_type, "audit");
    assert_eq!(ev.field(keys::OUTCOME), Some("denied"));
}

#[test]
fn multiline_statement_with_commas_and_quotes() {
    // A DDL statement spanning multiple lines, with a comma and a quoted
    // identifier ("" escaped) inside the (quoted) message column.
    let stmt = "CREATE TABLE public.\"\"Mixed\"\" (\n  id int,\n  name text\n)";
    let msg = format!("AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.mixed,{stmt},<none>");
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
    let (events, health) = parse_csvlog(&line, "db01", "prod");
    assert_eq!(
        events.len(),
        1,
        "the embedded newlines must NOT split the row"
    );
    assert_eq!(health.parsed, 1);
    assert_eq!(health.rejected, 0);
    assert_eq!(events[0].field(keys::QUERY_TYPE), Some("create")); // coarse
    assert_eq!(events[0].field("sql_statement_type"), Some("create_table")); // fine
}

#[test]
fn unicode_identifiers_and_schemas() {
    let msg = pgaudit(
        "READ",
        "SELECT",
        "TABLE",
        "büro.personal",
        "SELECT * FROM büro.personal",
    );
    let ev = one_csv(&csvline(
        "chef", "hr", "[local]", "SELECT", "LOG", "00000", &msg, "psql",
    ));
    assert_eq!(ev.field(keys::OBJECT_NAME), Some("büro.personal"));
    assert_eq!(ev.field("sql_read_tables"), Some("büro.personal"));
    // an unbounded SELECT * is bulk.
    assert_eq!(ev.field(keys::BULK_OPERATION), Some("true"));
}

#[test]
fn jsonlog_maps_the_same_way() {
    let line = r#"{"timestamp":"2024-06-01 12:00:00.123 CEST","user":"svc_etl","dbname":"dwh","remote_host":"10.1.2.3","session_id":"a.b","txid":"55","error_severity":"LOG","state_code":"00000","message":"AUDIT: SESSION,1,1,READ,SELECT,TABLE,dwh.customers,SELECT * FROM dwh.customers,<none>","application_name":"python","backend_type":"client backend"}"#;
    let (events, health) = parse_jsonlog(line, "db02", "prod");
    assert_eq!(health.parsed, 1);
    let ev = &events[0];
    assert_eq!(ev.field(keys::ACTOR), Some("svc_etl"));
    assert_eq!(ev.field(keys::DATABASE), Some("dwh"));
    assert_eq!(ev.field(keys::QUERY_TYPE), Some("select"));
    assert_eq!(ev.field("sql_read_tables"), Some("dwh.customers"));
    assert_eq!(ev.field("client_ip"), Some("10.1.2.3"));
}

#[test]
fn health_counts_reject_and_missing_fields() {
    // Two good rows, one too-short (rejected) row.
    let good = pgaudit("READ", "SELECT", "TABLE", "t", "SELECT 1 FROM t");
    let text = format!(
        "{}\n{}\nnot,enough,columns\n",
        csvline("u1", "db", "[local]", "SELECT", "LOG", "00000", &good, "psql"),
        csvline("u2", "db", "[local]", "SELECT", "LOG", "00000", &good, "psql"),
    );
    let (events, health) = parse_csvlog(&text, "db01", "prod");
    assert_eq!(events.len(), 2);
    assert_eq!(health.parsed, 2);
    assert_eq!(health.rejected, 1);
}

#[test]
fn missing_principal_and_database_are_tracked() {
    let msg = pgaudit("READ", "SELECT", "TABLE", "t", "SELECT 1 FROM t");
    let (_ev, health) = parse_csvlog(
        &csvline("", "", "[local]", "SELECT", "LOG", "00000", &msg, "psql"),
        "db01",
        "prod",
    );
    assert_eq!(health.missing_principal, 1);
    assert_eq!(health.missing_database, 1);
}

#[test]
fn adapter_registry_exposes_pg_formats() {
    let r = crate::AdapterRegistry::with_builtin();
    let names = r.names();
    assert!(names.contains(&"postgres-csvlog".to_string()));
    assert!(names.contains(&"postgres-jsonlog".to_string()));
    assert_eq!(
        r.get("postgres-csvlog").unwrap().version(),
        PG_PARSER_VERSION
    );
}

#[test]
fn csv_reader_handles_quotes_newlines_and_escapes() {
    let recs = parse_csv_records("a,\"multi\nline\",\"with \"\"quote\"\"\",z\n");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0], vec!["a", "multi\nline", "with \"quote\"", "z"]);
}

#[test]
fn parses_the_jsonl_fixture_corpus() {
    // The committed synthetic corpus (also used by the Phase-19 lab scenarios).
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/pg/audit-corpus.jsonl"
    );
    let text = std::fs::read_to_string(path).expect("fixture corpus present");
    let (events, health) = parse_jsonlog(&text, "db-lab", "lab");
    assert_eq!(health.rejected, 0, "every corpus line must parse");
    assert!(events.len() >= 15, "corpus should be diverse");
    // Spot-check the diversity the corpus is meant to exercise.
    assert!(events
        .iter()
        .any(|e| e.field(keys::EXPORT_OPERATION) == Some("true")));
    assert!(events
        .iter()
        .any(|e| e.field(keys::PRIVILEGE_OPERATION) == Some("true")));
    assert!(events
        .iter()
        .any(|e| e.field(keys::OUTCOME) == Some("denied")));
    assert!(events
        .iter()
        .any(|e| e.field(keys::QUERY_TYPE) == Some("copy")));
    assert!(events.iter().any(|e| e.field("sql_role_changes").is_some()));
}

#[test]
fn timestamp_parsing_variants() {
    assert!(parse_pg_ts("2024-06-01 12:00:00.123 UTC").is_some());
    assert!(parse_pg_ts("2024-06-01 12:00:00.123+02").is_some());
    assert!(parse_pg_ts("2024-06-01T12:00:00.123+02:00").is_some());
    assert!(parse_pg_ts("2024-06-01 12:00:00 CEST").is_some());
    assert!(parse_pg_ts("garbage").is_none());
}
