// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn classifies_and_extracts_select_with_aliases_and_joins() {
    let a = analyze(
        "SELECT a.name, p.pnr FROM accounts AS a JOIN persons p ON a.id = p.account_id WHERE p.pnr = '123'",
    );
    assert_eq!(a.statement_type, StatementType::Select);
    assert_eq!(a.parser_confidence, ParserConfidence::High);
    assert!(a.read_tables.contains(&"accounts".to_string()));
    assert!(a.read_tables.contains(&"persons".to_string()));
    assert!(a.joined_resources.contains(&"persons".to_string()));
    // aliases (a, p) must NOT appear as tables.
    assert!(!a.read_tables.contains(&"a".to_string()));
    assert!(!a.read_tables.contains(&"p".to_string()));
    // qualified column references are captured.
    assert!(a.referenced_columns.iter().any(|c| c == "a.name"));
    assert!(a.has_where);
    // the WHERE predicate column is captured.
    assert!(a.predicates.iter().any(|c| c == "p.pnr"));
}

#[test]
fn cte_names_are_excluded_but_their_body_tables_are_captured() {
    let a = analyze(
        "WITH recent AS (SELECT * FROM events WHERE ts > now()) \
         SELECT * FROM recent JOIN persons ON recent.id = persons.id",
    );
    assert!(a.ctes.contains(&"recent".to_string()));
    // the CTE body's table is real access and must be captured.
    assert!(a.read_tables.contains(&"events".to_string()));
    assert!(a.read_tables.contains(&"persons".to_string()));
    // the CTE name itself is not a real table.
    assert!(!a.read_tables.contains(&"recent".to_string()));
}

#[test]
fn view_and_ddl_objects() {
    let a = analyze("CREATE VIEW sensitive_v AS SELECT pnr FROM persons");
    assert_eq!(a.statement_type, StatementType::CreateView);
    assert!(a.ddl_objects.contains(&"sensitive_v".to_string()));
    assert!(a.read_tables.contains(&"persons".to_string()));

    let d = analyze("DROP TABLE staging.tmp");
    assert_eq!(d.statement_type, StatementType::Drop);
    assert!(d.ddl_objects.contains(&"staging.tmp".to_string()));
    assert!(d.statement_type.is_ddl());
}

#[test]
fn multiline_and_comments_do_not_break_analysis() {
    let sql = "-- daily export\nSELECT *\nFROM customers /* the big table */\nWHERE region = 'EU' -- filter\n";
    let a = analyze(sql);
    assert_eq!(a.statement_type, StatementType::Select);
    assert!(a.read_tables.contains(&"customers".to_string()));
    assert!(a.has_where);
    assert!(a.wildcard_columns);
}

#[test]
fn parse_failure_degrades_gracefully_and_stays_visible() {
    // Not valid SQL, but lexable — extraction still runs, at Low confidence.
    let a = analyze("SELCT oops FROM secret_table WHERE");
    assert_eq!(a.parser_confidence, ParserConfidence::Low);
    assert!(a.parse_error.is_some());
    // the table is still surfaced, AND marked unresolved (never silently safe).
    assert!(a.read_tables.contains(&"secret_table".to_string()));
    assert!(a.unresolved_objects.contains(&"secret_table".to_string()));
}

#[test]
fn fingerprint_is_stable_across_literal_parameter_whitespace_case_and_comments() {
    // MANDATORY: equivalent statements differing only in literals/params/
    // whitespace/case/comments share ONE fingerprint.
    let base = fingerprint("SELECT * FROM t WHERE id = 5");
    assert_eq!(base, fingerprint("SELECT * FROM t WHERE id = 42"));
    assert_eq!(base, fingerprint("SELECT * FROM t WHERE id = $1"));
    assert_eq!(base, fingerprint("select   *   from   t   where id=5"));
    assert_eq!(
        base,
        fingerprint("SELECT * FROM t /* c */ WHERE id = 5 -- trailing\n")
    );
    assert_eq!(base, fingerprint("SELECT * FROM t WHERE id = 5;"));
    assert_eq!(base, fingerprint("SELECT * FROM t WHERE id = 'a-string'"));
}

#[test]
fn fingerprint_changes_on_security_relevant_differences() {
    // MANDATORY: different table / column / schema / operation / privilege target
    // MUST change the fingerprint.
    let f = fingerprint("SELECT a FROM t WHERE id = 1");
    assert_ne!(f, fingerprint("SELECT a FROM t2 WHERE id = 1"), "table");
    assert_ne!(f, fingerprint("SELECT b FROM t WHERE id = 1"), "column");
    assert_ne!(
        f,
        fingerprint("SELECT a FROM public.t WHERE id = 1"),
        "schema"
    );
    assert_ne!(f, fingerprint("DELETE FROM t WHERE id = 1"), "operation");

    let g = fingerprint("GRANT SELECT ON accounts TO analyst");
    assert_ne!(
        g,
        fingerprint("GRANT SELECT ON persons TO analyst"),
        "priv target"
    );
    assert_ne!(
        g,
        fingerprint("GRANT UPDATE ON accounts TO analyst"),
        "privilege"
    );
}

#[test]
fn copy_export_and_import_directions() {
    let out = analyze("COPY persons TO '/tmp/dump.csv'");
    assert_eq!(out.statement_type, StatementType::Copy);
    assert_eq!(out.copy_source.as_deref(), Some("persons"));
    assert!(out.is_export());
    assert!(out.read_tables.contains(&"persons".to_string()));
    assert!(out.estimated_bulk, "an export is bulk by nature");
    assert_eq!(
        out.to_audit_fields()
            .get("export_operation")
            .map(String::as_str),
        Some("true")
    );

    let inbound = analyze("COPY staging FROM '/tmp/in.csv'");
    assert_eq!(inbound.copy_destination.as_deref(), Some("staging"));
    assert!(inbound.written_tables.contains(&"staging".to_string()));
}

#[test]
fn grant_revoke_and_set_role() {
    let g = analyze("GRANT SELECT, UPDATE ON TABLE persons TO caseworker");
    assert_eq!(g.statement_type, StatementType::Grant);
    assert!(g.privilege_targets.contains(&"persons".to_string()));
    assert!(g.statement_type.is_privilege());
    assert_eq!(
        g.to_audit_fields()
            .get("privilege_operation")
            .map(String::as_str),
        Some("true")
    );

    let sr = analyze("SET ROLE dbadmin");
    assert_eq!(sr.statement_type, StatementType::SetRole);
    assert!(sr.role_changes.contains(&"dbadmin".to_string()));

    let sa = analyze("SET SESSION AUTHORIZATION alice");
    assert_eq!(sa.statement_type, StatementType::SetRole);
    assert!(sa.role_changes.contains(&"alice".to_string()));
}

#[test]
fn bulk_estimation_and_limit() {
    // Unbounded scan → bulk.
    let bulk = analyze("SELECT * FROM persons");
    assert!(bulk.estimated_bulk);
    assert!(bulk.wildcard_columns);
    // Bounded by WHERE → not bulk.
    let bounded = analyze("SELECT * FROM persons WHERE pnr = '1'");
    assert!(!bounded.estimated_bulk);
    // Bounded by LIMIT → not bulk, and the limit is captured.
    let limited = analyze("SELECT * FROM persons LIMIT 10");
    assert_eq!(limited.limit, Some(10));
    assert!(!limited.estimated_bulk);
}

#[test]
fn dml_write_targets() {
    assert!(analyze("INSERT INTO audit_log (a) VALUES (1)")
        .written_tables
        .contains(&"audit_log".to_string()));
    assert!(analyze("UPDATE accounts SET balance = 0 WHERE id = 1")
        .written_tables
        .contains(&"accounts".to_string()));
    let del = analyze("DELETE FROM sessions WHERE id = 1");
    assert!(del.written_tables.contains(&"sessions".to_string()));
    // DELETE target is a write, not a read.
    assert!(!del.read_tables.contains(&"sessions".to_string()));
}

#[test]
fn functions_and_procedures() {
    let a = analyze("SELECT count(*), lower(name) FROM persons");
    assert!(a.referenced_functions.iter().any(|f| f == "count"));
    assert!(a.referenced_functions.iter().any(|f| f == "lower"));

    let c = analyze("CALL refresh_materialized_views()");
    assert_eq!(c.statement_type, StatementType::Call);
    assert!(c
        .called_procedures
        .contains(&"refresh_materialized_views".to_string()));
}

#[test]
fn to_audit_fields_carries_type_and_fingerprint() {
    let a = analyze("SELECT * FROM persons WHERE pnr = '1'");
    let f = a.to_audit_fields();
    assert_eq!(f.get("query_type").map(String::as_str), Some("select"));
    assert!(f
        .get("statement_fingerprint")
        .is_some_and(|s| s.starts_with("sql1:")));
}

#[test]
fn parameterized_is_detected() {
    assert!(analyze("SELECT * FROM t WHERE id = $1").parameterized);
    assert!(!analyze("SELECT * FROM t WHERE id = 1").parameterized);
}

#[test]
fn unicode_and_quoted_identifiers_preserve_case() {
    // A quoted identifier keeps its case; an unquoted one is folded.
    let a = analyze("SELECT * FROM \"MixedCase\"");
    assert!(a.read_tables.iter().any(|t| t.contains("MixedCase")));
    let b = analyze("SELECT * FROM MixedCase");
    assert!(b.read_tables.contains(&"mixedcase".to_string()));
    // …so the two are DIFFERENT objects and fingerprint differently.
    assert_ne!(a.query_fingerprint, b.query_fingerprint);
}

// ---- regression tests for the adversarial-review findings --------------------

#[test]
fn grant_on_table_keyword_captures_the_real_object() {
    // Review #1: `ON TABLE x` must record x, not the literal "table".
    let g = analyze("GRANT SELECT ON TABLE persons TO caseworker");
    assert!(g.privilege_targets.contains(&"persons".to_string()));
    assert!(!g.privilege_targets.contains(&"table".to_string()));
    // single-privilege form (no comma) must also work.
    let s = analyze("GRANT SELECT ON SCHEMA hr TO app");
    assert!(s.privilege_targets.contains(&"hr".to_string()));
    let q = analyze("GRANT USAGE ON SEQUENCE seq1 TO app");
    assert!(q.privilege_targets.contains(&"seq1".to_string()));
}

#[test]
fn revoke_grantee_is_not_a_read_table() {
    // Review #4: REVOKE's `FROM <grantee>` must not become a read table.
    let r = analyze("REVOKE SELECT ON persons FROM analyst");
    assert!(r.privilege_targets.contains(&"persons".to_string()));
    assert!(!r.read_tables.contains(&"analyst".to_string()));
    assert!(!r.read_tables.contains(&"persons".to_string()));
}

#[test]
fn grant_on_all_tables_in_schema_captures_the_schema() {
    let g = analyze("GRANT SELECT ON ALL TABLES IN SCHEMA hr TO app");
    assert!(g.privilege_targets.contains(&"hr".to_string()));
    assert!(!g.privilege_targets.contains(&"all".to_string()));
}

#[test]
fn derived_table_inner_tables_are_captured() {
    // Review #2/#3: a subquery in the FROM list must not hide its source tables.
    let a = analyze("SELECT * FROM (SELECT ssn FROM persons) t");
    assert!(
        a.read_tables.contains(&"persons".to_string()),
        "got {:?}",
        a.read_tables
    );
    // and combined with a real join table.
    let b = analyze("SELECT * FROM accounts a JOIN (SELECT id FROM persons) p ON a.id = p.id");
    assert!(b.read_tables.contains(&"accounts".to_string()));
    assert!(b.read_tables.contains(&"persons".to_string()));
}

#[test]
fn named_tables_after_derived_tables_are_captured() {
    let a = analyze("SELECT * FROM (SELECT 1) d, sensitive_table s");
    assert!(a.read_tables.contains(&"sensitive_table".to_string()));

    let b = analyze("SELECT * FROM (SELECT id FROM safe_table) d, (SELECT 1) e, sensitive_table s");
    assert!(b.read_tables.contains(&"safe_table".to_string()));
    assert!(b.read_tables.contains(&"sensitive_table".to_string()));
}

#[test]
fn truncate_without_table_keyword_captures_target() {
    // Review #5.
    let t = analyze("TRUNCATE persons");
    assert!(t.written_tables.contains(&"persons".to_string()));
    assert!(t.ddl_objects.contains(&"persons".to_string()));
    let t2 = analyze("TRUNCATE TABLE staging.tmp, staging.tmp2");
    assert!(t2.written_tables.contains(&"staging.tmp".to_string()));
    assert!(t2.written_tables.contains(&"staging.tmp2".to_string()));
}

#[test]
fn merge_using_source_and_no_set_pseudo_table() {
    // Review #6: MERGE captures the USING source; `UPDATE SET` inside MERGE must
    // not record "set" as a written table.
    let m = analyze(
        "MERGE INTO target t USING source s ON t.id = s.id \
         WHEN MATCHED THEN UPDATE SET val = s.val",
    );
    assert!(
        m.read_tables.contains(&"source".to_string()),
        "got {:?}",
        m.read_tables
    );
    assert!(m.written_tables.contains(&"target".to_string()));
    assert!(!m.written_tables.contains(&"set".to_string()));
}

#[test]
fn plain_set_is_classified_as_set_not_other() {
    // Review #10.
    assert_eq!(
        analyze("SET search_path = myschema").statement_type,
        StatementType::Set
    );
}
