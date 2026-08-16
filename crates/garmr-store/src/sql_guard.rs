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

/// The one base table a scoped query may read. Anything else is refused —
/// see [`constrain_sources`].
const EVENTS_TABLE: &str = "events";

/// Rewrite `sql` so every reference to the events table can only see `allowed`.
///
/// Each `events` reference becomes a derived table:
///
/// ```sql
/// FROM events                 -- becomes
/// FROM (SELECT * FROM events WHERE source IN ('a','b')) AS events
/// ```
///
/// so the constraint travels with the reference. Filtering by appending a
/// `WHERE` to the outer query would not: `SELECT * FROM events UNION SELECT *
/// FROM events` has two references and one outer WHERE, and a subquery or a
/// join would escape it entirely.
///
/// # Deny-unknown-tables
///
/// Any base table that is not `events` and is not a CTE defined in the same
/// query is an **error**, not a pass-through. That is the property that makes
/// this reviewable: an evasion has to get a *new table name* accepted rather
/// than merely find a spelling of `events` the rewriter missed. A sibling table
/// holding the same rows under another name, or a qualified `skade.ns.events`
/// the matcher did not recognise, both fail closed.
///
/// The alias is preserved so `t.source` still resolves; an unaliased reference
/// is aliased back to `events` so unqualified column references are unchanged.
pub fn constrain_sources(sql: &str, allowed: &[String]) -> std::result::Result<String, String> {
    use skade::datafusion::sql::sqlparser::ast::Statement;
    use skade::datafusion::sql::sqlparser::dialect::GenericDialect;
    use skade::datafusion::sql::sqlparser::parser::Parser;

    let mut statements = Parser::parse_sql(&GenericDialect {}, sql)
        .map_err(|e| format!("could not parse SQL: {e}"))?;
    if statements.len() != 1 {
        return Err("exactly one SQL statement is allowed".into());
    }
    match &mut statements[0] {
        Statement::Query(q) => rewrite_query(q, allowed, &mut Vec::new())?,
        Statement::Explain { statement, .. } => match statement.as_mut() {
            Statement::Query(q) => rewrite_query(q, allowed, &mut Vec::new())?,
            _ => return Err("only a single SELECT/WITH query is allowed".into()),
        },
        _ => return Err("only a single SELECT/WITH query is allowed".into()),
    }
    Ok(statements[0].to_string())
}

/// Rewrite one query, carrying the CTE names visible at this level.
///
/// `cte_scope` grows as we descend: a name defined by an enclosing `WITH` is
/// still a CTE inside a subquery, so it must not be mistaken for an unknown
/// base table and denied.
fn rewrite_query(
    q: &mut skade::datafusion::sql::sqlparser::ast::Query,
    allowed: &[String],
    cte_scope: &mut Vec<String>,
) -> std::result::Result<(), String> {
    let depth = cte_scope.len();
    if let Some(with) = q.with.as_mut() {
        for cte in with.cte_tables.iter_mut() {
            // Rewrite the CTE body BEFORE registering its name, so a CTE cannot
            // define itself in terms of its own name to dodge the check.
            rewrite_query(&mut cte.query, allowed, cte_scope)?;
            cte_scope.push(cte.alias.name.value.to_ascii_lowercase());
        }
    }
    rewrite_set_expr(&mut q.body, allowed, cte_scope)?;
    // Names defined here go out of scope for siblings.
    cte_scope.truncate(depth);
    Ok(())
}

fn rewrite_set_expr(
    body: &mut skade::datafusion::sql::sqlparser::ast::SetExpr,
    allowed: &[String],
    cte_scope: &mut Vec<String>,
) -> std::result::Result<(), String> {
    use skade::datafusion::sql::sqlparser::ast::SetExpr;
    match body {
        SetExpr::Select(select) => {
            for twj in select.from.iter_mut() {
                rewrite_factor(&mut twj.relation, allowed, cte_scope)?;
                for join in twj.joins.iter_mut() {
                    rewrite_factor(&mut join.relation, allowed, cte_scope)?;
                }
            }
            Ok(())
        }
        SetExpr::Query(q) => rewrite_query(q, allowed, cte_scope),
        SetExpr::SetOperation { left, right, .. } => {
            rewrite_set_expr(left, allowed, cte_scope)?;
            rewrite_set_expr(right, allowed, cte_scope)
        }
        // VALUES / INSERT / UPDATE / TABLE bodies carry no base-table read of
        // ours. reject_non_readonly has already refused the mutating ones.
        _ => Ok(()),
    }
}

fn rewrite_factor(
    factor: &mut skade::datafusion::sql::sqlparser::ast::TableFactor,
    allowed: &[String],
    cte_scope: &mut Vec<String>,
) -> std::result::Result<(), String> {
    use skade::datafusion::sql::sqlparser::ast::TableFactor;
    match factor {
        TableFactor::Table { name, alias, .. } => {
            let parts: Vec<String> = name
                .0
                .iter()
                .map(|p| p.to_string().trim_matches('"').to_ascii_lowercase())
                .collect();
            let last = parts.last().cloned().unwrap_or_default();
            // A CTE reference: not a base table, nothing to constrain.
            if parts.len() == 1 && cte_scope.contains(&last) {
                return Ok(());
            }
            if last != EVENTS_TABLE {
                return Err(format!(
                    "table `{}` is not readable under a source-scoped credential; \
                     only `events` is",
                    name
                ));
            }
            // Keep the caller's alias, or bind the derived table back to
            // `events` so unqualified column references still resolve.
            let alias_name = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .unwrap_or_else(|| EVENTS_TABLE.to_string());
            *factor = derived_events(allowed, &alias_name)?;
            Ok(())
        }
        TableFactor::Derived { subquery, .. } => rewrite_query(subquery, allowed, cte_scope),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            rewrite_factor(&mut table_with_joins.relation, allowed, cte_scope)?;
            for join in table_with_joins.joins.iter_mut() {
                rewrite_factor(&mut join.relation, allowed, cte_scope)?;
            }
            Ok(())
        }
        // Table functions, UNNEST, pivots and the rest read no garmr base table.
        // They are refused rather than silently allowed: under a scoped
        // credential the safe default for a construct we have not reasoned about
        // is no.
        _ => Err("this FROM construct is not available to a source-scoped credential".into()),
    }
}

/// Build `(SELECT * FROM events WHERE source IN (…)) AS <alias>` by PARSING it
/// rather than hand-constructing AST nodes.
///
/// Parsing keeps this correct across sqlparser upgrades: `TableFactor::Derived`
/// has gained fields before (sampling, ordinality) and a hand-built literal
/// would need editing each time — a rewrite that fails to compile is fine, but
/// one that silently drops a new field is not.
///
/// Source values are emitted as single-quoted literals with `'` doubled. They
/// come from configuration rather than from a request, but the escaping is not
/// optional: an unescaped quote here would let a configured source name change
/// the shape of the predicate it appears in.
fn derived_events(
    allowed: &[String],
    alias: &str,
) -> std::result::Result<skade::datafusion::sql::sqlparser::ast::TableFactor, String> {
    use skade::datafusion::sql::sqlparser::ast::{SetExpr, Statement};
    use skade::datafusion::sql::sqlparser::dialect::GenericDialect;
    use skade::datafusion::sql::sqlparser::parser::Parser;

    let list = if allowed.is_empty() {
        // An empty allow-list means "read nothing". `IN ()` is not valid SQL, so
        // express it as a predicate that is false for every row — including rows
        // where `source` is NULL, which `source IN ('')` would not exclude.
        "SELECT * FROM events WHERE 1 = 0".to_string()
    } else {
        let values: Vec<String> = allowed
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .collect();
        format!(
            "SELECT * FROM events WHERE source IN ({})",
            values.join(", ")
        )
    };
    let alias_ident = alias.replace('"', "\"\"");
    let template = format!("SELECT * FROM ({list}) AS \"{alias_ident}\"");
    let mut parsed = Parser::parse_sql(&GenericDialect {}, &template)
        .map_err(|e| format!("internal: scoped-subquery template failed to parse: {e}"))?;
    let Some(Statement::Query(q)) = parsed.pop() else {
        return Err("internal: scoped-subquery template was not a query".into());
    };
    let SetExpr::Select(select) = *q.body else {
        return Err("internal: scoped-subquery template was not a SELECT".into());
    };
    select
        .from
        .into_iter()
        .next()
        .map(|twj| twj.relation)
        .ok_or_else(|| "internal: scoped-subquery template had no FROM".to_string())
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

    use super::constrain_sources;

    fn hr() -> Vec<String> {
        vec!["hr".to_string()]
    }

    /// Every `events` reference in the output must be wrapped in the scoped
    /// subquery. Counting is the point: one rewritten reference and one missed
    /// is a leak, and "it contains the predicate" would pass that.
    fn scoped_refs(out: &str) -> usize {
        out.matches("SELECT * FROM events WHERE source IN").count()
    }

    #[test]
    fn a_bare_reference_is_wrapped_and_aliased_back_to_events() {
        let out = constrain_sources("SELECT count(*) FROM events", &hr()).unwrap();
        assert_eq!(scoped_refs(&out), 1, "{out}");
        // Aliased back, so unqualified column references still resolve.
        assert!(out.contains("AS \"events\""), "{out}");
    }

    #[test]
    fn an_alias_is_preserved_so_qualified_columns_still_resolve() {
        let out = constrain_sources("SELECT t.source FROM events AS t", &hr()).unwrap();
        assert_eq!(scoped_refs(&out), 1, "{out}");
        assert!(out.contains("AS \"t\""), "{out}");
    }

    #[test]
    fn every_branch_of_a_union_is_constrained() {
        // The case an outer WHERE cannot cover: two references, one query.
        let out = constrain_sources(
            "SELECT source FROM events UNION ALL SELECT source FROM events",
            &hr(),
        )
        .unwrap();
        assert_eq!(scoped_refs(&out), 2, "{out}");
    }

    #[test]
    fn joins_subqueries_and_nested_joins_are_all_constrained() {
        let out = constrain_sources(
            "SELECT a.source FROM events a JOIN events b ON a.host = b.host",
            &hr(),
        )
        .unwrap();
        assert_eq!(scoped_refs(&out), 2, "{out}");

        let out = constrain_sources("SELECT * FROM (SELECT source FROM events) x", &hr()).unwrap();
        assert_eq!(scoped_refs(&out), 1, "{out}");

        let out = constrain_sources(
            "SELECT * FROM (events a JOIN events b ON a.host = b.host)",
            &hr(),
        )
        .unwrap();
        assert_eq!(scoped_refs(&out), 2, "{out}");
    }

    #[test]
    fn a_cte_is_not_a_base_table_but_its_body_is_constrained() {
        let out = constrain_sources(
            "WITH t AS (SELECT source FROM events) SELECT * FROM t",
            &hr(),
        )
        .unwrap();
        // The CTE body is scoped; referencing `t` afterwards is not an unknown
        // table and must not be denied.
        assert_eq!(scoped_refs(&out), 1, "{out}");
    }

    #[test]
    fn a_cte_cannot_shadow_events_to_escape_the_rewrite() {
        // `WITH events AS (SELECT * FROM events)` — the body still gets scoped,
        // so the shadowing name can only ever see already-constrained rows.
        let out = constrain_sources(
            "WITH events AS (SELECT * FROM events) SELECT * FROM events",
            &hr(),
        )
        .unwrap();
        assert_eq!(
            scoped_refs(&out),
            1,
            "the CTE body must be constrained even when it shadows the table name: {out}"
        );
    }

    #[test]
    fn a_sibling_table_is_denied_rather_than_passed_through() {
        // The evasion deny-unknown-tables exists for: another table holding the
        // same rows under a different name.
        let err = constrain_sources("SELECT * FROM events_raw", &hr()).unwrap_err();
        assert!(err.contains("not readable"), "{err}");
        let err =
            constrain_sources("SELECT * FROM events JOIN secrets ON true", &hr()).unwrap_err();
        assert!(err.contains("not readable"), "{err}");
    }

    #[test]
    fn a_qualified_events_name_is_still_recognised_and_constrained() {
        // skade.<ns>.events must not slip past by being spelled in full.
        let out = constrain_sources("SELECT count(*) FROM skade.public.events", &hr()).unwrap();
        assert_eq!(scoped_refs(&out), 1, "{out}");
    }

    #[test]
    fn an_empty_allow_list_reads_nothing_rather_than_everything() {
        // The footgun this guards: treating `sources: []` as unrestricted would
        // make the most locked-down configuration the most permissive one.
        let out = constrain_sources("SELECT count(*) FROM events", &[]).unwrap();
        assert!(out.contains("1 = 0"), "{out}");
        assert!(!out.contains("source IN"), "{out}");
    }

    #[test]
    fn a_quote_in_a_configured_source_cannot_reshape_the_predicate() {
        let out = constrain_sources("SELECT count(*) FROM events", &["it's".to_string()]).unwrap();
        assert!(out.contains("'it''s'"), "{out}");
        // Still exactly one scoped reference — the quote did not split the IN list.
        assert_eq!(scoped_refs(&out), 1, "{out}");
    }

    #[test]
    fn explain_is_rewritten_too_so_a_plan_cannot_reveal_unscoped_rows() {
        let out = constrain_sources("EXPLAIN SELECT * FROM events", &hr()).unwrap();
        assert_eq!(scoped_refs(&out), 1, "{out}");
        assert!(out.starts_with("EXPLAIN"), "{out}");
    }

    #[test]
    fn the_rewritten_sql_still_parses_and_stays_read_only() {
        // The output is fed back to DataFusion, so it must survive its own guard.
        for q in [
            "SELECT count(*) FROM events",
            "WITH t AS (SELECT source FROM events) SELECT * FROM t",
            "SELECT a.source FROM events a JOIN events b ON a.host = b.host",
            "SELECT source FROM events UNION ALL SELECT source FROM events",
        ] {
            let out = constrain_sources(q, &hr()).unwrap();
            assert!(
                reject_non_readonly(&out).is_ok(),
                "rewritten SQL must still pass the read-only guard: {out}"
            );
            assert!(
                constrain_sources(&out, &hr()).is_ok(),
                "rewriting is idempotent-safe (re-parses): {out}"
            );
        }
    }

    #[test]
    fn a_string_literal_naming_another_table_is_inert() {
        // Injection through a literal must not become a table reference.
        let out = constrain_sources(
            "SELECT * FROM events WHERE message LIKE '%FROM secrets%'",
            &hr(),
        )
        .unwrap();
        assert_eq!(scoped_refs(&out), 1, "{out}");
    }
}
