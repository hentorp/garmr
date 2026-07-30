// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The safety centerpiece: compile a [`StructuredFilter`] to BOUNDED, read-only
//! SQL that no model-authored string can turn into an injection or exfil.
//!
//! Four independent properties make injection structurally impossible:
//!   1. CLOSED IDENTIFIER SET — the table (`events`), every column name, the
//!      projection, ORDER BY and LIMIT are compile-time `&'static str`. A typed
//!      per-column IR makes an "arbitrary column" unrepresentable: there is no
//!      `format!` that ever places input where an identifier goes.
//!   2. SINGLE VALUE CHOKEPOINT — model/analyst input reaches SQL ONLY inside a
//!      quoted literal via [`sql_lit`] (doubles `'`); `fields` key=value goes
//!      through [`like_escape`] (escapes `\ % _ '`) into a `LIKE … ESCAPE '\'`
//!      pattern, and the KEY is escaped too (so a `_` in `src_ip` matches
//!      literally, not as a wildcard).
//!   3. BOUNDED BY CONSTRUCTION — time bounds are numeric only, compiled with the
//!      proven `to_timestamp_micros(<i64>)` idiom; the compiler always appends a
//!      clamped `LIMIT` and emits exactly ONE `SELECT` (no `;`, no stacked
//!      statement).
//!   4. DEFENSE IN DEPTH — the executor still runs the compiled string through
//!      `reject_non_readonly` + a query timeout (never trusting the compiler).

use crate::ir::{is_valid_field_key, StructuredFilter};

/// The fixed projection every hybrid SQL emits (the columns a `ResultItem`
/// needs). A `&'static str`, never built from input.
pub const PROJECTION: &str = "event_ts, host, service, severity, message";

/// A SQL string literal: single-quoted, embedded quotes doubled.
pub fn sql_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Escape a substring for a `LIKE` pattern used with `ESCAPE '\'`: the `\`, `%`,
/// `_` wildcards become literals and single quotes are doubled so the enclosing
/// literal stays well-formed. Applied to BOTH the key and the value of a field
/// predicate.
pub fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
}

/// One `IN (...)` (or `= 'x'`) predicate over a fixed column, or `None` when the
/// value list is empty.
fn in_clause(col: &'static str, vals: &[String]) -> Option<String> {
    match vals {
        [] => None,
        [one] => Some(format!("{col} = {}", sql_lit(one))),
        many => {
            let list = many
                .iter()
                .map(|v| sql_lit(v))
                .collect::<Vec<_>>()
                .join(", ");
            Some(format!("{col} IN ({list})"))
        }
    }
}

impl StructuredFilter {
    /// Compile to a single bounded read-only `SELECT`, or `None` when the filter
    /// is entirely empty (no structured signal — the caller relies on text /
    /// semantic only). `now_micros` anchors relative time bounds; `cap` is the
    /// (already-clamped) candidate `LIMIT`.
    pub fn compile_sql(&self, cap: usize, now_micros: i64) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut conj: Vec<String> = Vec::new();

        // Time bounds — numeric only, via the proven to_timestamp_micros idiom.
        if let Some(h) = self.time.last_hours {
            let cutoff = now_micros.saturating_sub((h * 3_600_000_000.0) as i64);
            conj.push(format!("event_ts >= to_timestamp_micros({cutoff})"));
        }
        if let Some(from) = self.time.from_micros {
            conj.push(format!("event_ts >= to_timestamp_micros({from})"));
        }
        if let Some(to) = self.time.to_micros {
            conj.push(format!("event_ts <= to_timestamp_micros({to})"));
        }

        // Label columns — closed identifier set, values only inside sql_lit.
        for (col, vals) in [
            ("host", &self.host),
            ("service", &self.service),
            ("source", &self.source),
            ("environment", &self.environment),
            ("severity", &self.severity),
            ("log_type", &self.log_type),
        ] {
            if let Some(c) = in_clause(col, vals) {
                conj.push(c);
            }
        }

        // fields key=value — LIKE over the compact-JSON `fields` column. Key AND
        // value are like_escaped so their `_`/`%` match literally.
        for f in &self.fields {
            if !is_valid_field_key(&f.key) {
                continue; // validate() already rejected these; belt-and-braces
            }
            let pat = format!("\"{}\":\"{}\"", like_escape(&f.key), like_escape(&f.value));
            let like = format!("fields LIKE '%{pat}%' ESCAPE '\\'");
            conj.push(if f.negate {
                format!("NOT ({like})")
            } else {
                like
            });
        }

        // If everything was empty (e.g. only unknown field keys), no structured
        // signal after all.
        if conj.is_empty() {
            return None;
        }
        Some(format!(
            "SELECT {PROJECTION} FROM events WHERE {} ORDER BY event_ts DESC LIMIT {cap}",
            conj.join(" AND ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::ir::{FieldPredicate, StructuredFilter, TimeRange};

    fn sf() -> StructuredFilter {
        StructuredFilter::default()
    }

    #[test]
    fn empty_filter_compiles_to_none() {
        assert!(sf().compile_sql(500, 0).is_none());
    }

    #[test]
    fn single_and_set_membership() {
        let mut f = sf();
        f.host = vec!["web01".into()];
        assert!(f.compile_sql(500, 0).unwrap().contains("host = 'web01'"));
        f.host = vec!["web01".into(), "web02".into()];
        assert!(f
            .compile_sql(500, 0)
            .unwrap()
            .contains("host IN ('web01', 'web02')"));
    }

    #[test]
    fn injection_attempts_become_inert_literals() {
        let mut f = sf();
        f.host = vec!["x'; DROP TABLE events; --".into()];
        let sql = f.compile_sql(500, 0).unwrap();
        // The quote is doubled, so the whole payload is one harmless literal —
        // its `;` and `--` live INSIDE the quotes, not as SQL syntax.
        assert!(sql.contains("host = 'x''; DROP TABLE events; --'"));
        // Always exactly one bounded SELECT.
        assert!(sql.ends_with("LIMIT 500"));
        assert!(sql.starts_with("SELECT event_ts, host, service, severity, message FROM events"));
    }

    #[test]
    fn field_key_and_value_are_like_escaped() {
        let mut f = sf();
        f.fields = vec![FieldPredicate {
            key: "src_ip".into(),
            value: "10.0.0.1".into(),
            negate: false,
        }];
        let sql = f.compile_sql(500, 0).unwrap();
        // The underscore in the KEY is escaped so it matches literally, not as a
        // LIKE wildcard.
        assert!(
            sql.contains(r#"fields LIKE '%"src\_ip":"10.0.0.1"%' ESCAPE '\'"#),
            "{sql}"
        );
    }

    #[test]
    fn negated_field_wraps_in_not() {
        let mut f = sf();
        f.fields = vec![FieldPredicate {
            key: "user".into(),
            value: "root".into(),
            negate: true,
        }];
        let sql = f.compile_sql(500, 0).unwrap();
        assert!(sql.contains("NOT (fields LIKE"));
    }

    #[test]
    fn time_bounds_use_to_timestamp_micros() {
        let mut f = sf();
        f.time = TimeRange {
            last_hours: Some(2.0),
            from_micros: None,
            to_micros: Some(1_000_000),
        };
        let sql = f.compile_sql(500, 10_000_000_000).unwrap();
        // last 2h => now - 7.2e9 micros
        assert!(
            sql.contains("event_ts >= to_timestamp_micros(2800000000)"),
            "{sql}"
        );
        assert!(sql.contains("event_ts <= to_timestamp_micros(1000000)"));
    }

    #[test]
    fn value_with_wildcards_matches_literally() {
        let mut f = sf();
        f.fields = vec![FieldPredicate {
            key: "path".into(),
            value: "100%_done".into(),
            negate: false,
        }];
        let sql = f.compile_sql(500, 0).unwrap();
        assert!(sql.contains(r#""path":"100\%\_done""#), "{sql}");
    }
}
