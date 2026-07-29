// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! SQL input safety for the agent's query tools: the read-only AST guard that
//! rejects anything that isn't a single SELECT/WITH (optionally via EXPLAIN),
//! and the LIKE-pattern escaper that keeps a user substring from being read as
//! wildcards. Both sit between an LLM-issued value and the events lakehouse.

/// The read-only AST guard now lives in garmr-store so the Phase 6 hybrid-query
/// executor shares it without a cross-crate cycle; re-exported here so the
/// agent's existing callers (and `pub use` in tools/mod + lib) are unchanged.
pub use garmr_store::reject_non_readonly;

/// Escape a substring for use as a SQL `LIKE`/`ILIKE` pattern with `ESCAPE '\'`:
/// backslash + the `%`/`_` wildcards become literals, and single quotes are
/// doubled to keep the string literal well-formed.
pub(super) fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
}

// reject_non_readonly's tests moved to garmr-store/src/sql_guard.rs with the fn.