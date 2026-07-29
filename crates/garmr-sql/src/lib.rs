// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 3 — PostgreSQL-aware SQL semantic analysis.
//!
//! [`analyze`] turns a raw SQL statement into a normalized [`SqlAccessAnalysis`]:
//! which tables it reads and writes, the columns / functions / procedures it
//! touches, whether it exports, changes privileges, or runs DDL, plus a stable
//! [`SqlAccessAnalysis::query_fingerprint`]. Policy evaluation (Phase 5) and the
//! application-audit detectors (Phase 8) consume this instead of grepping SQL
//! text.
//!
//! ## A layered parser with graceful degradation
//!
//! This is NOT text matching. Two layers, both from `sqlparser`'s PostgreSQL
//! dialect:
//!
//! 1. **Full AST parse** ([`sqlparser::parser::Parser`]) — validates the
//!    statement and yields the authoritative [`StatementType`]. When it succeeds,
//!    [`ParserConfidence::High`].
//! 2. **Tokenizer lexer** ([`sqlparser::tokenizer`]) — drives structural
//!    extraction across *every* statement shape. The lexer correctly handles
//!    comments, single/double-quoted and dollar-quoted strings, quoted
//!    identifiers, and placeholders, so extraction never trips on a comment or a
//!    string literal the way a regex would. When the AST parse fails, the
//!    tokenizer still runs, extraction proceeds at [`ParserConfidence::Low`], and
//!    the parse error is recorded — unresolved access stays VISIBLE, never
//!    silently treated as safe.
//!
//! ## Fingerprint contract
//!
//! The fingerprint normalizes away whitespace, comments, and literal/parameter
//! VALUES (so `WHERE id = 5`, `WHERE id = 42`, and `WHERE id = $1` share one
//! fingerprint) but PRESERVES every security-relevant difference: different
//! tables, columns, schemas, operations, privilege targets, and COPY
//! destinations all change the fingerprint. Keyword case and identifier case
//! (for unquoted identifiers, which PostgreSQL folds) are normalized; quoted
//! identifiers keep their case.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sqlparser::ast::Statement;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::keywords::Keyword;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Word};

/// The analyzer/fingerprint format version. Bumping it invalidates stored
/// fingerprints deliberately; it is the prefix of every [`SqlAccessAnalysis::query_fingerprint`].
pub const FINGERPRINT_VERSION: &str = "sql1";

/// How confident the analysis is, set by which layer produced it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserConfidence {
    /// The full AST parse succeeded.
    High,
    /// The AST parse failed; extraction ran on the token stream only.
    Low,
    /// The input could not even be tokenized.
    #[default]
    None,
}

/// The authoritative statement class. `Other` is the forward-compatible
/// catch-all; `Unknown` means neither the AST nor the leading keyword classified
/// it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementType {
    Select,
    Insert,
    Update,
    Delete,
    Copy,
    CreateTable,
    CreateView,
    CreateIndex,
    CreateSchema,
    CreateFunction,
    AlterTable,
    AlterRole,
    Drop,
    Truncate,
    Grant,
    Revoke,
    Call,
    SetRole,
    Merge,
    Analyze,
    Explain,
    Set,
    Other,
    #[default]
    Unknown,
}

impl StatementType {
    pub fn as_str(self) -> &'static str {
        match self {
            StatementType::Select => "select",
            StatementType::Insert => "insert",
            StatementType::Update => "update",
            StatementType::Delete => "delete",
            StatementType::Copy => "copy",
            StatementType::CreateTable => "create_table",
            StatementType::CreateView => "create_view",
            StatementType::CreateIndex => "create_index",
            StatementType::CreateSchema => "create_schema",
            StatementType::CreateFunction => "create_function",
            StatementType::AlterTable => "alter_table",
            StatementType::AlterRole => "alter_role",
            StatementType::Drop => "drop",
            StatementType::Truncate => "truncate",
            StatementType::Grant => "grant",
            StatementType::Revoke => "revoke",
            StatementType::Call => "call",
            StatementType::SetRole => "set_role",
            StatementType::Merge => "merge",
            StatementType::Analyze => "analyze",
            StatementType::Explain => "explain",
            StatementType::Set => "set",
            StatementType::Other => "other",
            StatementType::Unknown => "unknown",
        }
    }

    /// Map to the coarse [`garmr_core::QueryType`] carried on an
    /// [`garmr_core::AuditRecord`].
    pub fn to_query_type(self) -> garmr_core::QueryType {
        use garmr_core::QueryType as Q;
        match self {
            StatementType::Select | StatementType::Analyze | StatementType::Explain => Q::Select,
            StatementType::Insert | StatementType::Merge => Q::Insert,
            StatementType::Update => Q::Update,
            StatementType::Delete => Q::Delete,
            StatementType::Copy => Q::Copy,
            StatementType::CreateTable
            | StatementType::CreateView
            | StatementType::CreateIndex
            | StatementType::CreateSchema
            | StatementType::CreateFunction => Q::Create,
            StatementType::AlterTable | StatementType::AlterRole => Q::Alter,
            StatementType::Drop => Q::Drop,
            StatementType::Truncate => Q::Truncate,
            StatementType::Grant => Q::Grant,
            StatementType::Revoke => Q::Revoke,
            StatementType::SetRole => Q::SetRole,
            StatementType::Call => Q::Call,
            StatementType::Set | StatementType::Other | StatementType::Unknown => Q::Other,
        }
    }

    /// A privilege / access-control changing statement.
    pub fn is_privilege(self) -> bool {
        matches!(
            self,
            StatementType::Grant | StatementType::Revoke | StatementType::SetRole
        )
    }

    /// A schema-changing DDL statement.
    pub fn is_ddl(self) -> bool {
        matches!(
            self,
            StatementType::CreateTable
                | StatementType::CreateView
                | StatementType::CreateIndex
                | StatementType::CreateSchema
                | StatementType::CreateFunction
                | StatementType::AlterTable
                | StatementType::Drop
                | StatementType::Truncate
        )
    }
}

/// The normalized result of analyzing one SQL statement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlAccessAnalysis {
    /// Stable, security-preserving fingerprint (`sql1:<hex>`). See the module docs.
    pub query_fingerprint: String,
    /// The statement re-serialized with whitespace/comments collapsed and
    /// literals/parameters masked to `?`. The pre-image of the fingerprint.
    pub normalized_statement: String,
    pub statement_type: StatementType,
    /// Tables (and views — unresolved until the catalog resolves them) read from.
    pub read_tables: Vec<String>,
    /// Tables written to (INSERT/UPDATE/DELETE target, COPY … FROM, CREATE/…).
    pub written_tables: Vec<String>,
    /// Every object name seen in an object position — the catalog resolves each
    /// to a table / view / other and to a sensitivity in Phase 4.
    pub referenced_objects: Vec<String>,
    /// Columns referenced (qualified `table.column`), best-effort.
    pub referenced_columns: Vec<String>,
    /// Functions invoked (`name(` … `)`).
    pub referenced_functions: Vec<String>,
    /// Stored procedures invoked via `CALL`.
    pub called_procedures: Vec<String>,
    /// Tables brought in specifically through a `JOIN`.
    pub joined_resources: Vec<String>,
    /// Column references appearing in the `WHERE` predicate, best-effort.
    pub predicates: Vec<String>,
    pub has_where: bool,
    pub grouping: bool,
    pub ordering: bool,
    /// The `LIMIT` value, if a literal one is present.
    pub limit: Option<u64>,
    /// Count of nested sub-`SELECT`s.
    pub subqueries: usize,
    /// Common-table-expression names (excluded from real tables).
    pub ctes: Vec<String>,
    /// For `COPY … TO`: the object data is read out of (an export).
    pub copy_source: Option<String>,
    /// For `COPY … FROM`: the object data is written into.
    pub copy_destination: Option<String>,
    /// Objects targeted by `GRANT`/`REVOKE`.
    pub privilege_targets: Vec<String>,
    /// Role/authorization switches (`SET ROLE`, `SET SESSION AUTHORIZATION`).
    pub role_changes: Vec<String>,
    /// Objects created/altered/dropped/truncated.
    pub ddl_objects: Vec<String>,
    /// The statement selects `*` (wildcard columns).
    pub wildcard_columns: bool,
    /// Heuristic: an unbounded read / bulk operation (a `SELECT`/`COPY` with no
    /// `WHERE` and no `LIMIT`, or any export). Refined by row counts at runtime.
    pub estimated_bulk: bool,
    /// The statement uses bind parameters / placeholders (`$1`, `?`, `:name`).
    pub parameterized: bool,
    /// Sensitive objects hit — filled by the catalog in Phase 4; empty here.
    pub sensitive_resource_hits: Vec<String>,
    pub parser_confidence: ParserConfidence,
    /// Object names extraction could not confidently classify (kept visible so a
    /// consumer never mistakes "unresolved" for "safe").
    pub unresolved_objects: Vec<String>,
    /// The AST parse error, when the parse failed (degraded to token layer).
    pub parse_error: Option<String>,
}

impl SqlAccessAnalysis {
    /// Canonical audit fields derived from this analysis, keyed by the
    /// [`garmr_core::app_audit::keys`] the [`garmr_core::AuditRecord`] reads.
    /// Phase 2's pgAudit adapter merges these onto the event so the statement's
    /// structure is searchable and drives detectors — without re-parsing.
    pub fn to_audit_fields(&self) -> std::collections::BTreeMap<String, String> {
        use garmr_core::app_audit::keys;
        let mut m = std::collections::BTreeMap::new();
        if !self.query_fingerprint.is_empty() {
            m.insert(
                keys::STATEMENT_FINGERPRINT.to_string(),
                self.query_fingerprint.clone(),
            );
        }
        m.insert(
            keys::QUERY_TYPE.to_string(),
            self.statement_type.to_query_type().as_str().to_string(),
        );
        if self.estimated_bulk {
            m.insert(keys::BULK_OPERATION.to_string(), "true".to_string());
        }
        if self.is_export() {
            m.insert(keys::EXPORT_OPERATION.to_string(), "true".to_string());
        }
        if self.statement_type.is_privilege() {
            m.insert(keys::PRIVILEGE_OPERATION.to_string(), "true".to_string());
        }
        if self.statement_type.is_ddl() {
            m.insert(
                keys::ADMINISTRATIVE_OPERATION.to_string(),
                "true".to_string(),
            );
        }
        m
    }

    /// True if the statement exports data (a `COPY … TO`).
    pub fn is_export(&self) -> bool {
        self.copy_source.is_some()
    }
}

/// Fingerprint a SQL statement (the `sql1:<hex>` string only). Equivalent to
/// `analyze(sql).query_fingerprint` but skips structural extraction.
pub fn fingerprint(sql: &str) -> String {
    let dialect = PostgreSqlDialect {};
    match Tokenizer::new(&dialect, sql).tokenize() {
        Ok(tokens) => fingerprint_tokens(&tokens),
        // Unlexable input: fall back to a whitespace-collapsed raw fingerprint so
        // two byte-identical-modulo-whitespace strings still match.
        Err(_) => {
            let norm = sql
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            format!("{FINGERPRINT_VERSION}:{}", short_hash(&norm))
        }
    }
}

/// Analyze a SQL statement into a [`SqlAccessAnalysis`]. Never panics and never
/// returns an error — an unparseable statement degrades to the token layer with
/// [`ParserConfidence::Low`] (or [`ParserConfidence::None`] if even tokenizing
/// fails), the error recorded in [`SqlAccessAnalysis::parse_error`].
pub fn analyze(sql: &str) -> SqlAccessAnalysis {
    let dialect = PostgreSqlDialect {};

    let tokens = match Tokenizer::new(&dialect, sql).tokenize() {
        Ok(t) => t,
        Err(e) => {
            // Cannot even lex — surface everything as unresolved.
            let norm = sql
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            return SqlAccessAnalysis {
                query_fingerprint: format!("{FINGERPRINT_VERSION}:{}", short_hash(&norm)),
                normalized_statement: norm,
                parser_confidence: ParserConfidence::None,
                parse_error: Some(format!("tokenizer: {e}")),
                ..Default::default()
            };
        }
    };

    let mut a = extract_from_tokens(&tokens);
    a.query_fingerprint = fingerprint_tokens(&tokens);

    // Layer 1: authoritative statement type + confidence from the AST.
    match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => {
            a.parser_confidence = ParserConfidence::High;
            if let Some(first) = stmts.first() {
                let ast_ty = classify_ast(first);
                // The AST is authoritative when it classifies the statement, but
                // it must not clobber a precise token-derived type with `Other`:
                // SET ROLE / SET SESSION AUTHORIZATION (token → SetRole) and a
                // plain SET (token → Set) both fold to Other in classify_ast.
                if a.statement_type != StatementType::SetRole && ast_ty != StatementType::Other {
                    a.statement_type = ast_ty;
                }
            }
        }
        Err(e) => {
            a.parser_confidence = ParserConfidence::Low;
            a.parse_error = Some(e.to_string());
            // Everything extracted from tokens after a parse failure is
            // lower-trust: mirror the object names into unresolved_objects.
            for o in a.read_tables.iter().chain(a.written_tables.iter()) {
                if !a.unresolved_objects.contains(o) {
                    a.unresolved_objects.push(o.clone());
                }
            }
            a.unresolved_objects.sort();
        }
    }

    a
}

// -------------------------------------------------------------------------
// fingerprint
// -------------------------------------------------------------------------

fn short_hash(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex()[..32].to_string()
}

/// Normalize a word for the fingerprint / extraction: unquoted keyword →
/// UPPERCASE, unquoted identifier → lowercase (PostgreSQL folds these), quoted
/// identifier → preserved and re-quoted with double quotes.
fn norm_word(w: &Word) -> String {
    if w.quote_style.is_some() {
        format!("\"{}\"", w.value)
    } else if w.keyword != Keyword::NoKeyword {
        w.value.to_ascii_uppercase()
    } else {
        w.value.to_ascii_lowercase()
    }
}

/// Normalize a word used AS AN IDENTIFIER (a name part or function name): quoted
/// identifiers keep their case; everything else (including non-reserved keywords
/// used as identifiers, e.g. `name`, `count`) is folded to lowercase like
/// PostgreSQL folds unquoted identifiers.
fn ident_norm(w: &Word) -> String {
    if w.quote_style.is_some() {
        format!("\"{}\"", w.value)
    } else {
        w.value.to_ascii_lowercase()
    }
}

/// A literal/parameter token whose VALUE must be masked out of the fingerprint.
/// Double-quoted strings are excluded — under the PostgreSQL dialect those are
/// delimited identifiers (emitted as quoted `Word`s), so a stray
/// `DoubleQuotedString` is treated as an identifier and kept, never masked.
fn is_masked_literal(t: &Token) -> bool {
    matches!(
        t,
        Token::Number(_, _)
            | Token::SingleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedByteStringLiteral(_)
            | Token::TripleDoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedRawStringLiteral(_)
            | Token::TripleDoubleQuotedRawStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_)
            | Token::Placeholder(_)
    )
}

fn fingerprint_tokens(tokens: &[Token]) -> String {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    for t in tokens {
        match t {
            Token::Whitespace(_) => continue,
            Token::SemiColon => continue, // statement terminator carries no identity
            Token::Word(w) => out.push(norm_word(w)),
            other if is_masked_literal(other) => out.push("?".to_string()),
            other => out.push(other.to_string()),
        }
    }
    let normalized = out.join(" ");
    format!("{FINGERPRINT_VERSION}:{}", short_hash(&normalized))
}

// -------------------------------------------------------------------------
// AST classification (robust: `{..}`/`(_)` patterns ignore inner fields)
// -------------------------------------------------------------------------

fn classify_ast(stmt: &Statement) -> StatementType {
    match stmt {
        Statement::Query(_) => StatementType::Select,
        Statement::Insert(_) => StatementType::Insert,
        Statement::Update(_) => StatementType::Update,
        Statement::Delete(_) => StatementType::Delete,
        Statement::Copy { .. } => StatementType::Copy,
        Statement::CreateTable(_) => StatementType::CreateTable,
        Statement::CreateView(_) => StatementType::CreateView,
        Statement::CreateIndex(_) => StatementType::CreateIndex,
        Statement::CreateSchema { .. } => StatementType::CreateSchema,
        Statement::CreateFunction(_) => StatementType::CreateFunction,
        Statement::AlterTable(_) => StatementType::AlterTable,
        Statement::AlterRole { .. } => StatementType::AlterRole,
        Statement::Drop { .. } => StatementType::Drop,
        Statement::Truncate(_) => StatementType::Truncate,
        Statement::Grant(_) => StatementType::Grant,
        Statement::Revoke(_) => StatementType::Revoke,
        Statement::Call(_) => StatementType::Call,
        Statement::Merge(_) => StatementType::Merge,
        Statement::Analyze(_) => StatementType::Analyze,
        Statement::Explain { .. } | Statement::ExplainTable { .. } => StatementType::Explain,
        _ => StatementType::Other,
    }
}

// -------------------------------------------------------------------------
// token-driven structural extraction
// -------------------------------------------------------------------------

/// A filtered, whitespace/comment-free view of the token stream, with helpers
/// for reading qualified names.
struct Toks<'a> {
    v: Vec<&'a Token>,
}

impl<'a> Toks<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        let v = tokens
            .iter()
            .filter(|t| !matches!(t, Token::Whitespace(_)))
            .collect();
        Toks { v }
    }

    fn kw(&self, i: usize) -> Option<Keyword> {
        match self.v.get(i) {
            Some(Token::Word(w)) if w.quote_style.is_none() && w.keyword != Keyword::NoKeyword => {
                Some(w.keyword)
            }
            _ => None,
        }
    }

    /// The identifier text at `i` (a non-keyword word, or any quoted word). Used
    /// to START a name — keywords in a value position (e.g. a bare `WHERE`) are
    /// rejected so the scanner doesn't mistake a clause for a name.
    fn ident(&self, i: usize) -> Option<String> {
        match self.v.get(i) {
            Some(Token::Word(w)) if w.quote_style.is_some() || w.keyword == Keyword::NoKeyword => {
                Some(norm_word(w))
            }
            _ => None,
        }
    }

    /// The text of ANY word token at `i` (keyword or not). Used for name parts
    /// after a `.`, where PostgreSQL allows many non-reserved keywords as
    /// identifiers (e.g. `t.name`, `a.value`).
    fn any_word(&self, i: usize) -> Option<String> {
        match self.v.get(i) {
            Some(Token::Word(w)) => Some(ident_norm(w)),
            _ => None,
        }
    }

    /// Read a possibly-qualified name (`a`, `a.b`, `a.b.c`) starting at `i`.
    /// Returns the normalized dotted name and the index just past it. Any word
    /// may start a name, since many object/schema names are non-reserved
    /// keywords (`public.persons`, `user.data`). Callers only invoke this after a
    /// name-introducing keyword, or in the else-branch where the current token is
    /// already known to be a non-keyword, so a clause keyword is never read here.
    fn read_name(&self, i: usize) -> Option<(String, usize)> {
        // Reject a leading RESERVED clause keyword so a clause word is never read
        // as an object name (e.g. `UPDATE SET …`, `REVOKE … FROM role`). Non-
        // reserved keywords (public, name, user) remain valid name starts.
        if let Some(Token::Word(w)) = self.v.get(i) {
            if w.quote_style.is_none() && is_reserved_clause_kw(w.keyword) {
                return None;
            }
        }
        let mut parts = vec![self.any_word(i)?];
        let mut j = i + 1;
        while matches!(self.v.get(j), Some(Token::Period)) {
            // `t.*` — a wildcard part; stop, leaving the `*` to the caller.
            if matches!(self.v.get(j + 1), Some(Token::Mul)) {
                break;
            }
            match self.any_word(j + 1) {
                Some(p) => {
                    parts.push(p);
                    j += 2;
                }
                None => break,
            }
        }
        Some((parts.join("."), j))
    }

    /// If `i` is a word directly followed by `(` and is not a control keyword
    /// that also takes parentheses, return the function name.
    fn function_at(&self, i: usize) -> Option<String> {
        let name = match self.v.get(i) {
            Some(Token::Word(w)) => ident_norm(w),
            _ => return None,
        };
        if !matches!(self.v.get(i + 1), Some(Token::LParen)) {
            return None;
        }
        const NOT_FUNCS: &[&str] = &[
            "IN", "VALUES", "EXISTS", "ARRAY", "ROW", "ALL", "ANY", "SOME", "OVER", "FILTER",
            "USING", "ON", "AND", "OR", "NOT", "CASE", "SELECT", "TABLE", "WHEN", "FROM", "WHERE",
        ];
        if NOT_FUNCS.contains(&name.to_ascii_uppercase().as_str()) {
            return None;
        }
        Some(name)
    }
}

/// The clause region within a statement, used to attribute column references.
#[derive(Clone, Copy, PartialEq)]
enum Region {
    Projection,
    Where,
    Other,
}

fn extract_from_tokens(tokens: &[Token]) -> SqlAccessAnalysis {
    let t = Toks::new(tokens);
    let n = t.v.len();

    let mut read = BTreeSet::new();
    let mut written = BTreeSet::new();
    let mut objects = BTreeSet::new();
    let mut columns = BTreeSet::new();
    let mut functions = BTreeSet::new();
    let mut procedures = BTreeSet::new();
    let mut joined = BTreeSet::new();
    let mut predicates = BTreeSet::new();
    let mut ctes = BTreeSet::new();
    let mut privilege_targets = BTreeSet::new();
    let mut role_changes = BTreeSet::new();
    let mut ddl_objects = BTreeSet::new();
    let unresolved = BTreeSet::new();

    let mut a = SqlAccessAnalysis::default();

    let first_kw = (0..n).find_map(|i| t.kw(i));
    a.statement_type = first_kw
        .map(stmt_type_from_kw)
        .unwrap_or(StatementType::Unknown);

    let mut region = match first_kw {
        Some(Keyword::SELECT) | Some(Keyword::WITH) => Region::Projection,
        _ => Region::Other,
    };
    let mut delete_target_taken = false;

    let mut i = 0usize;
    while i < n {
        // Placeholders anywhere ⇒ parameterized.
        if matches!(t.v[i], Token::Placeholder(_)) {
            a.parameterized = true;
        }
        // Nested sub-SELECT: `(` immediately followed by SELECT.
        if matches!(t.v[i], Token::LParen) && t.kw(i + 1) == Some(Keyword::SELECT) {
            a.subqueries += 1;
        }
        // Function call: any word directly followed by `(` (catches aggregate/
        // builtin keywords like count/lower that are keyword-classified). This
        // only records — it never advances the cursor.
        if let Some(fname) = t.function_at(i) {
            functions.insert(fname);
        }

        let Some(kw) = t.kw(i) else {
            // Not a keyword. Capture compound column references outside table
            // positions (best-effort). A bare `*` in the projection ⇒ wildcard.
            if matches!(t.v[i], Token::Mul) && region == Region::Projection {
                a.wildcard_columns = true;
            }
            if let Some((name, next)) = t.read_name(i) {
                // A qualified reference in a value position (not a function call)
                // is a column. Function calls are recorded by `function_at` above.
                if name.contains('.')
                    && !name.ends_with(".*")
                    && !matches!(t.v.get(next), Some(Token::LParen))
                {
                    if region != Region::Other {
                        columns.insert(name.clone());
                    }
                    if region == Region::Where {
                        predicates.insert(name.clone());
                    }
                }
                i = next;
                continue;
            }
            i += 1;
            continue;
        };

        match kw {
            Keyword::WITH => {
                i = scan_ctes(&t, i + 1, &mut ctes);
                region = Region::Projection;
            }
            Keyword::SELECT => {
                region = Region::Projection;
                i += 1;
            }
            Keyword::WHERE => {
                a.has_where = true;
                region = Region::Where;
                i += 1;
            }
            Keyword::GROUP => {
                a.grouping = true;
                region = Region::Other;
                i += 1;
            }
            Keyword::ORDER => {
                a.ordering = true;
                region = Region::Other;
                i += 1;
            }
            Keyword::HAVING => {
                region = Region::Other;
                i += 1;
            }
            Keyword::LIMIT => {
                if let Some(Token::Number(nstr, _)) = t.v.get(i + 1) {
                    a.limit = nstr.parse::<u64>().ok();
                }
                region = Region::Other;
                i += 1;
            }
            Keyword::FROM => {
                region = Region::Other;
                // REVOKE … FROM <grantee>: the FROM clause is the grantee list,
                // NOT tables — do not capture grantees as read tables.
                if first_kw == Some(Keyword::REVOKE) {
                    i += 1;
                } else {
                    // DELETE FROM <t> → the first FROM target is written.
                    let to_written = first_kw == Some(Keyword::DELETE) && !delete_target_taken;
                    i = read_table_list(&t, i + 1, |name| {
                        objects.insert(name.to_string());
                        if to_written {
                            written.insert(name.to_string());
                        } else {
                            read.insert(name.to_string());
                        }
                    });
                    delete_target_taken = true;
                }
            }
            Keyword::JOIN => {
                if let Some((name, next)) = read_one_table(&t, i + 1) {
                    objects.insert(name.clone());
                    read.insert(name.clone());
                    joined.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::INTO => {
                // INSERT INTO <t> / SELECT … INTO <t>.
                if let Some((name, next)) = read_one_table(&t, i + 1) {
                    objects.insert(name.clone());
                    written.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::UPDATE => {
                if let Some((name, next)) = read_one_table(&t, i + 1) {
                    objects.insert(name.clone());
                    written.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::TABLE => {
                // GRANT/REVOKE … ON TABLE x → privilege target, not DDL.
                let in_priv = matches!(first_kw, Some(Keyword::GRANT) | Some(Keyword::REVOKE));
                if let Some((name, next)) = t.read_name(i + 1) {
                    objects.insert(name.clone());
                    if in_priv {
                        privilege_targets.insert(name);
                    } else {
                        ddl_objects.insert(name.clone());
                        // CREATE/ALTER TABLE writes; TRUNCATE/DROP affect it too.
                        written.insert(name);
                    }
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::VIEW | Keyword::INDEX => {
                if let Some((name, next)) = t.read_name(i + 1) {
                    objects.insert(name.clone());
                    ddl_objects.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::TRUNCATE => {
                // TRUNCATE [TABLE] [ONLY] name [, …] — a write + DDL on each table.
                let mut j = i + 1;
                if t.kw(j) == Some(Keyword::TABLE) {
                    j += 1;
                }
                i = read_table_list(&t, j, |name| {
                    objects.insert(name.to_string());
                    ddl_objects.insert(name.to_string());
                    written.insert(name.to_string());
                });
            }
            Keyword::USING => {
                // MERGE … USING <source> — a read. (JOIN … USING (cols) has `(`
                // next, so read_one_table returns None and it is skipped.)
                if let Some((name, next)) = read_one_table(&t, i + 1) {
                    objects.insert(name.clone());
                    read.insert(name.clone());
                    joined.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::COPY => {
                i = scan_copy(&t, i + 1, &mut a, &mut read, &mut written, &mut objects);
            }
            Keyword::CALL | Keyword::EXECUTE => {
                if let Some((name, next)) = t.read_name(i + 1) {
                    procedures.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::ROLE if first_kw == Some(Keyword::SET) => {
                a.statement_type = StatementType::SetRole;
                if let Some((name, next)) = t.read_name(i + 1) {
                    role_changes.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::AUTHORIZATION if first_kw == Some(Keyword::SET) => {
                a.statement_type = StatementType::SetRole;
                if let Some((name, next)) = t.read_name(i + 1) {
                    role_changes.insert(name);
                    i = next;
                } else {
                    i += 1;
                }
            }
            Keyword::ON if matches!(first_kw, Some(Keyword::GRANT) | Some(Keyword::REVOKE)) => {
                // GRANT/REVOKE … ON <objs> TO/FROM … : read the privilege target(s)
                // until TO/FROM/end. The object class must be skipped first, or it
                // would be read as the target (the `ON TABLE persons` / pg_dump form).
                let mut j = i + 1;
                if t.kw(j) == Some(Keyword::ALL) {
                    // `ON ALL <plural> IN SCHEMA <schema>`: the scope IS the schema.
                    // Advance to just after SCHEMA and record the schema name.
                    while j < n
                        && t.kw(j) != Some(Keyword::SCHEMA)
                        && !matches!(t.v.get(j), Some(Token::SemiColon))
                    {
                        if matches!(t.kw(j), Some(Keyword::TO) | Some(Keyword::FROM)) {
                            break;
                        }
                        j += 1;
                    }
                    if t.kw(j) == Some(Keyword::SCHEMA) {
                        if let Some((name, next)) = t.read_name(j + 1) {
                            objects.insert(name.clone());
                            privilege_targets.insert(name);
                            j = next;
                        }
                    }
                } else {
                    // Skip one leading object-class keyword (TABLE/SCHEMA/SEQUENCE/…).
                    if t.kw(j).is_some_and(is_object_class_kw) {
                        j += 1;
                    }
                    while let Some((name, next)) = t.read_name(j) {
                        objects.insert(name.clone());
                        privilege_targets.insert(name);
                        j = next;
                        if matches!(t.v.get(j), Some(Token::Comma)) {
                            j += 1;
                            continue;
                        }
                        break;
                    }
                }
                i = j;
            }
            _ => {
                i += 1;
            }
        }
    }

    let to_vec = |s: BTreeSet<String>| s.into_iter().collect::<Vec<_>>();
    a.read_tables = to_vec(read);
    a.written_tables = to_vec(written);
    a.referenced_objects = to_vec(objects);
    a.referenced_columns = to_vec(columns);
    a.referenced_functions = to_vec(functions);
    a.called_procedures = to_vec(procedures);
    a.joined_resources = to_vec(joined);
    a.predicates = to_vec(predicates);
    a.ctes = to_vec(ctes);
    a.privilege_targets = to_vec(privilege_targets);
    a.role_changes = to_vec(role_changes);
    a.ddl_objects = to_vec(ddl_objects);
    a.unresolved_objects = to_vec(unresolved);

    // A CTE name is not a real table: it can appear in a later FROM.
    a.read_tables.retain(|x| !a.ctes.contains(x));
    a.written_tables.retain(|x| !a.ctes.contains(x));
    a.referenced_objects.retain(|x| !a.ctes.contains(x));

    a.estimated_bulk = a.is_export()
        || (matches!(
            a.statement_type,
            StatementType::Select | StatementType::Copy
        ) && !a.has_where
            && a.limit.is_none()
            && !a.read_tables.is_empty());

    a
}

/// Collect the CTE names introduced by a `WITH` clause starting at `start`
/// (just past the `WITH` keyword). This ONLY records names — it deliberately
/// does not advance the main scan past the CTE bodies, so the main loop still
/// traverses each body and captures the tables it reads. A CTE name is later
/// filtered out of `read_tables`/`written_tables`, so a `FROM recent` over a CTE
/// does not masquerade as a real table.
fn scan_ctes(t: &Toks, start: usize, ctes: &mut BTreeSet<String>) -> usize {
    let mut i = start;
    if t.kw(i) == Some(Keyword::RECURSIVE) {
        i += 1;
    }
    while let Some(name) = t.ident(i) {
        let mut j = i + 1;
        if matches!(t.v.get(j), Some(Token::LParen)) {
            j = skip_parens(t, j); // optional column list
        }
        if t.kw(j) != Some(Keyword::AS) {
            break;
        }
        j += 1;
        if !matches!(t.v.get(j), Some(Token::LParen)) {
            break;
        }
        ctes.insert(name);
        let after_body = skip_parens(t, j);
        if matches!(t.v.get(after_body), Some(Token::Comma)) {
            i = after_body + 1;
            continue;
        }
        break;
    }
    // Return `start` so the main loop re-traverses the CTE bodies for table
    // extraction; names are already collected above.
    start
}

/// Skip a balanced parenthesized group starting at `lparen` (which must index a
/// `(`). Returns the index just past the matching `)`.
fn skip_parens(t: &Toks, lparen: usize) -> usize {
    let n = t.v.len();
    let mut depth = 0usize;
    let mut i = lparen;
    while i < n {
        match t.v[i] {
            Token::LParen => depth += 1,
            Token::RParen => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    n
}

/// Read one table reference (optionally schema-qualified) plus a trailing alias,
/// skipping a leading `ONLY`. Returns `(name, next_index)` or `None` if the next
/// token isn't a table (e.g. a subquery `(`).
fn read_one_table(t: &Toks, start: usize) -> Option<(String, usize)> {
    let mut i = start;
    if t.kw(i) == Some(Keyword::ONLY) {
        i += 1;
    }
    if matches!(t.v.get(i), Some(Token::LParen)) {
        // subquery / derived table — skip it, not a named table.
        return Some((String::new(), skip_parens(t, i))).filter(|(s, _)| !s.is_empty());
    }
    let (name, mut j) = t.read_name(i)?;
    // skip `AS alias` or a bare alias.
    if t.kw(j) == Some(Keyword::AS) {
        j += 1;
        if t.ident(j).is_some() {
            j += 1;
        }
    } else if t.ident(j).is_some() && t.kw(j).is_none() {
        j += 1;
    }
    Some((name, j))
}

/// Read a comma-separated FROM table list (old-style joins), invoking `sink`
/// for each named table. Returns the index past the list.
fn read_table_list(t: &Toks, start: usize, mut sink: impl FnMut(&str)) -> usize {
    let mut i = start;
    loop {
        // A derived table must remain visible to the main loop so its source
        // tables are captured. Before returning to that loop, also inspect the
        // rest of this comma-separated list for named tables.
        if matches!(t.v.get(i), Some(Token::LParen)) {
            let mut j = skip_table_alias(t, skip_parens(t, i));
            while matches!(t.v.get(j), Some(Token::Comma)) {
                j += 1;
                if matches!(t.v.get(j), Some(Token::LParen)) {
                    j = skip_table_alias(t, skip_parens(t, j));
                } else if let Some((name, next)) = read_one_table(t, j) {
                    sink(&name);
                    j = next;
                } else {
                    break;
                }
            }
            break;
        }
        if let Some((name, next)) = read_one_table(t, i) {
            sink(&name);
            i = next;
        } else {
            break;
        }
        if matches!(t.v.get(i), Some(Token::Comma)) {
            i += 1;
            continue;
        }
        break;
    }
    i
}

fn skip_table_alias(t: &Toks, mut i: usize) -> usize {
    if t.kw(i) == Some(Keyword::AS) {
        i += 1;
    }
    if t.ident(i).is_some() && t.kw(i).is_none() {
        i += 1;
    }
    i
}

/// Scan a `COPY` statement body starting just after the `COPY` keyword.
fn scan_copy(
    t: &Toks,
    start: usize,
    a: &mut SqlAccessAnalysis,
    read: &mut BTreeSet<String>,
    written: &mut BTreeSet<String>,
    objects: &mut BTreeSet<String>,
) -> usize {
    let mut i = start;
    // COPY ( SELECT … ) TO …  → export of a subquery.
    if matches!(t.v.get(i), Some(Token::LParen)) {
        let after = skip_parens(t, i);
        a.copy_source = Some("(subquery)".to_string());
        return after;
    }
    let Some((name, mut j)) = t.read_name(i) else {
        return i + 1;
    };
    objects.insert(name.clone());
    // skip an optional column list.
    if matches!(t.v.get(j), Some(Token::LParen)) {
        j = skip_parens(t, j);
    }
    match t.kw(j) {
        Some(Keyword::TO) => {
            read.insert(name.clone());
            a.copy_source = Some(name);
        }
        Some(Keyword::FROM) => {
            written.insert(name.clone());
            a.copy_destination = Some(name);
        }
        _ => {
            // direction unknown — keep it visible as a read.
            read.insert(name.clone());
            a.copy_source = Some(name);
        }
    }
    i = j;
    i
}

/// Reserved clause keywords that must never be read as an object/table name.
/// Non-reserved keywords (public, name, user, …) are deliberately absent so
/// schema/table names spelled as non-reserved keywords still extract.
fn is_reserved_clause_kw(kw: Keyword) -> bool {
    matches!(
        kw,
        Keyword::SET
            | Keyword::SELECT
            | Keyword::FROM
            | Keyword::WHERE
            | Keyword::GROUP
            | Keyword::ORDER
            | Keyword::HAVING
            | Keyword::LIMIT
            | Keyword::OFFSET
            | Keyword::VALUES
            | Keyword::ON
            | Keyword::AND
            | Keyword::OR
            | Keyword::AS
            | Keyword::INTO
            | Keyword::JOIN
            | Keyword::UNION
            | Keyword::TO
            | Keyword::USING
            | Keyword::WHEN
            | Keyword::THEN
    )
}

/// Object-class keywords that introduce a GRANT/REVOKE target
/// (`GRANT … ON TABLE x`, `ON SCHEMA s`, `ON SEQUENCE q`, …).
fn is_object_class_kw(kw: Keyword) -> bool {
    matches!(
        kw,
        Keyword::TABLE
            | Keyword::SCHEMA
            | Keyword::SEQUENCE
            | Keyword::FUNCTION
            | Keyword::PROCEDURE
            | Keyword::DATABASE
            | Keyword::DOMAIN
            | Keyword::TYPE
            | Keyword::VIEW
    )
}

fn stmt_type_from_kw(kw: Keyword) -> StatementType {
    match kw {
        Keyword::SELECT | Keyword::WITH => StatementType::Select,
        Keyword::INSERT => StatementType::Insert,
        Keyword::UPDATE => StatementType::Update,
        Keyword::DELETE => StatementType::Delete,
        Keyword::COPY => StatementType::Copy,
        Keyword::TRUNCATE => StatementType::Truncate,
        Keyword::GRANT => StatementType::Grant,
        Keyword::REVOKE => StatementType::Revoke,
        Keyword::CALL | Keyword::EXECUTE => StatementType::Call,
        Keyword::MERGE => StatementType::Merge,
        Keyword::ANALYZE => StatementType::Analyze,
        Keyword::EXPLAIN => StatementType::Explain,
        Keyword::SET => StatementType::Set,
        Keyword::CREATE => StatementType::CreateTable, // refined by AST when it parses
        Keyword::ALTER => StatementType::AlterTable,
        Keyword::DROP => StatementType::Drop,
        _ => StatementType::Other,
    }
}

#[cfg(test)]
mod tests;