// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The read-only SQL AST guard: rejects anything that isn't a single
//! SELECT/WITH (optionally via EXPLAIN). It lives here (not in the agent) so
//! every SQL path — the agent's query tools AND the Phase 6 hybrid-query
//! executor — shares ONE guard without a cross-crate cycle. garmr-store already
//! depends on skade, which re-exports the DataFusion sqlparser.

/// Reject anything that isn't a single read-only query, enforced at the AST
/// level. Substring keyword matching (the old approach) both blocked legitimate
/// hunts (`... LIKE '%drop table%'`, a trailing `;`) and could be bypassed with
/// non-space whitespace (`INSERT\tINTO`); parsing eliminates both. Only a lone
/// `SELECT`/`WITH` query, or an `EXPLAIN` whose inner statement is such a query,
/// is allowed — so `EXPLAIN ANALYZE INSERT …` is rejected.
pub fn reject_non_readonly(sql: &str) -> std::result::Result<(), String> {
    use skade::datafusion::sql::sqlparser::ast::Statement;
    use skade::datafusion::sql::sqlparser::dialect::GenericDialect;
    use skade::datafusion::sql::sqlparser::parser::Parser;

    let statements = Parser::parse_sql(&GenericDialect {}, sql)
        .map_err(|e| format!("could not parse SQL: {e}"))?;
    if statements.len() != 1 {
        return Err("exactly one SQL statement is allowed".into());
    }
    fn is_read_only(s: &Statement) -> bool {
        match s {
            Statement::Query(_) => true,
            Statement::Explain { statement, .. } => is_read_only(statement),
            _ => false,
        }
    }
    if is_read_only(&statements[0]) {
        Ok(())
    } else {
        Err("only a single SELECT/WITH query (optionally via EXPLAIN) is allowed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::reject_non_readonly;

    #[test]
    fn allows_read_only_queries() {
        assert!(reject_non_readonly("SELECT count(*) FROM events").is_ok());
        assert!(reject_non_readonly("WITH t AS (SELECT 1) SELECT * FROM t").is_ok());
        assert!(reject_non_readonly("EXPLAIN SELECT * FROM events").is_ok());
        // A keyword inside a string literal must NOT be rejected (the old
        // substring guard blocked exactly this legitimate hunt query).
        assert!(
            reject_non_readonly("SELECT * FROM events WHERE message LIKE '%drop table%'").is_ok()
        );
    }

    #[test]
    fn rejects_writes_and_bypasses() {
        assert!(reject_non_readonly("INSERT INTO events VALUES (1)").is_err());
        assert!(reject_non_readonly("DELETE FROM events").is_err());
        assert!(reject_non_readonly("DROP TABLE events").is_err());
        // Non-space whitespace between keywords must not slip a write past the
        // guard (the substring bypass #9).
        assert!(reject_non_readonly("INSERT\tINTO events VALUES (1)").is_err());
        // EXPLAIN ANALYZE of a write is still a write.
        assert!(reject_non_readonly("EXPLAIN ANALYZE INSERT INTO events VALUES (1)").is_err());
        // Two statements (stacked query) rejected.
        assert!(reject_non_readonly("SELECT 1; DROP TABLE events").is_err());
        // COPY ... TO is a data-egress side effect, not a read — must stay rejected.
        assert!(reject_non_readonly("COPY events TO '/tmp/x.csv'").is_err());
        assert!(reject_non_readonly("CREATE TABLE x AS SELECT * FROM events").is_err());
    }
}
