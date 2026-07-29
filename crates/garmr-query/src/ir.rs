// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The typed hybrid-query IR the agent composes. Every struct is
//! `#[serde(default)]` (a partial query fills sensible defaults) and
//! `#[serde(deny_unknown_fields)]` (a typo'd key is a HARD error, never a
//! silently-dropped predicate that would widen a security filter). The IR carries
//! only the six generic event labels + a generic JSON `fields` key=value, so it
//! stays domain-neutral — register vocabulary can appear only as an
//! operator-supplied VALUE, never as an IR variant.

use serde::{Deserialize, Serialize};

/// Upper bounds enforced by [`HybridQuery::validate`] (clamped, never rejected,
/// except where noted).
pub const MAX_LIMIT: usize = 200;
pub const MAX_PER_SIGNAL_K: usize = 500;
pub const MAX_CANDIDATE_CAP: usize = 5_000;
/// Longest a filter value / field value may be (rejected, not truncated).
pub const MAX_VALUE_LEN: usize = 512;
/// Longest a field KEY may be.
pub const MAX_KEY_LEN: usize = 64;
/// Longest a text / semantic query string may be.
pub const MAX_QUERY_LEN: usize = 2_048;
/// The widest time window a query may request (in hours) — one leap year.
pub const MAX_LAST_HOURS: f64 = 24.0 * 366.0;

/// A hybrid query: a structured filter plus optional full-text and semantic
/// clauses, fused into one ranked result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HybridQuery {
    /// Typed structured predicates (may be empty).
    pub filter: StructuredFilter,
    /// Full-text (Tantivy BM25) signal.
    pub text: Option<TextClause>,
    /// Semantic (natural-language embedding) signal.
    pub semantic: Option<SemanticClause>,
    pub fusion: FusionConfig,
}

/// Typed per-column structured predicates. Each label column is a `Vec` — OR
/// within a column (`col IN (...)`), AND across columns. An "arbitrary column" is
/// UNREPRESENTABLE, which is the root of the injection-safety guarantee.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StructuredFilter {
    pub time: TimeRange,
    pub host: Vec<String>,
    pub service: Vec<String>,
    pub source: Vec<String>,
    pub environment: Vec<String>,
    pub severity: Vec<String>,
    pub log_type: Vec<String>,
    /// AND-ed `key=value` predicates over the JSON `fields` column.
    pub fields: Vec<FieldPredicate>,
}

impl StructuredFilter {
    /// True when no predicate at all is set (an unbounded scan if it were the
    /// only clause).
    pub fn is_empty(&self) -> bool {
        self.time.is_empty()
            && self.host.is_empty()
            && self.service.is_empty()
            && self.source.is_empty()
            && self.environment.is_empty()
            && self.severity.is_empty()
            && self.log_type.is_empty()
            && self.fields.is_empty()
    }
}

/// One `fields` predicate: an exact `"key":"value"` match (JSON substring),
/// optionally negated.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FieldPredicate {
    pub key: String,
    pub value: String,
    pub negate: bool,
}

/// The only range predicate — numeric only (never text), so it cannot inject.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeRange {
    /// Relative: events within the last N hours.
    pub last_hours: Option<f64>,
    /// Absolute lower bound (unix micros).
    pub from_micros: Option<i64>,
    /// Absolute upper bound (unix micros).
    pub to_micros: Option<i64>,
}

impl TimeRange {
    pub fn is_empty(&self) -> bool {
        self.last_hours.is_none() && self.from_micros.is_none() && self.to_micros.is_none()
    }
}

/// A full-text clause (Tantivy query syntax, as today).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TextClause {
    pub query: String,
}

/// A semantic clause (natural-language, embedded then cosine-matched).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SemanticClause {
    pub query: String,
}

/// How the signals are fused and how much of each is pulled/kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FusionConfig {
    pub method: FusionMethod,
    pub text_weight: f32,
    pub semantic_weight: f32,
    pub structured_weight: f32,
    /// Hits pulled per signal before fusion.
    pub per_signal_k: usize,
    /// Final results returned.
    pub limit: usize,
    /// The structured-gate SQL `LIMIT` (the candidate set the other signals are
    /// intersected against).
    pub candidate_cap: usize,
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            method: FusionMethod::default(),
            text_weight: 1.0,
            semantic_weight: 1.0,
            structured_weight: 1.0,
            per_signal_k: 100,
            limit: 20,
            candidate_cap: 500,
        }
    }
}

/// The fusion algorithm. RRF is the default — it ranks on ordinal position only,
/// so it fuses BM25 (unbounded), cosine ([-1,1]), and boolean structured
/// membership without any score calibration.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionMethod {
    /// Reciprocal Rank Fusion with the given `k`.
    Rrf { k: u32 },
    /// Weighted reciprocal-rank sum: each signal contributes
    /// `weight * (1 / rank)`. Like RRF it fuses on ordinal position (raw
    /// BM25/cosine magnitudes are NOT calibrated — deliberately, since cross-
    /// signal score normalization over a sliding vector window is unstable),
    /// but it weights the signals and does not soften the head with an RRF `k`.
    WeightedNormalized,
}

impl Default for FusionMethod {
    fn default() -> Self {
        FusionMethod::Rrf { k: 60 }
    }
}

/// True if `key` is a safe field key: `[A-Za-z0-9_.-]`, non-empty, bounded. A
/// safe key can carry neither a quote nor a JSON metacharacter into the compiled
/// `"key":` fragment (its `_`/`%` are still LIKE-escaped at compile time).
pub fn is_valid_field_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl HybridQuery {
    /// Validate + clamp in place. Clamps the fusion bounds, rejects an entirely
    /// unbounded query (no filter dimension, no text, no semantic — never an
    /// unbounded scan), rejects an oversized/ill-formed value or field key, and
    /// bounds the time window. Returns the reason on rejection.
    pub fn validate(&mut self) -> Result<(), String> {
        // Clamp the fusion knobs.
        self.fusion.limit = self.fusion.limit.clamp(1, MAX_LIMIT);
        self.fusion.per_signal_k = self.fusion.per_signal_k.clamp(1, MAX_PER_SIGNAL_K);
        self.fusion.candidate_cap = self.fusion.candidate_cap.clamp(1, MAX_CANDIDATE_CAP);
        for w in [
            &mut self.fusion.text_weight,
            &mut self.fusion.semantic_weight,
            &mut self.fusion.structured_weight,
        ] {
            if !w.is_finite() || *w < 0.0 {
                *w = 0.0;
            }
        }

        // Never allow an unbounded scan: at least one retrieval dimension.
        if self.filter.is_empty() && self.text.is_none() && self.semantic.is_none() {
            return Err(
                "empty query: give a structured filter, a text clause, or a semantic clause".into(),
            );
        }

        // Bound every model-supplied string.
        for (col, vals) in [
            ("host", &self.filter.host),
            ("service", &self.filter.service),
            ("source", &self.filter.source),
            ("environment", &self.filter.environment),
            ("severity", &self.filter.severity),
            ("log_type", &self.filter.log_type),
        ] {
            for v in vals {
                check_value(col, v)?;
            }
        }
        for f in &self.filter.fields {
            if !is_valid_field_key(&f.key) {
                return Err(format!(
                    "invalid field key '{}': must be [A-Za-z0-9_.-], 1..={MAX_KEY_LEN} chars",
                    f.key
                ));
            }
            check_value("field value", &f.value)?;
        }
        if let Some(t) = &self.text {
            check_query("text", &t.query)?;
        }
        if let Some(s) = &self.semantic {
            check_query("semantic", &s.query)?;
        }

        // Bound the time window.
        if let Some(h) = self.filter.time.last_hours {
            if !h.is_finite() || h <= 0.0 || h > MAX_LAST_HOURS {
                return Err(format!("last_hours must be in (0, {MAX_LAST_HOURS}]"));
            }
        }
        if let (Some(from), Some(to)) = (self.filter.time.from_micros, self.filter.time.to_micros) {
            if from > to {
                return Err("time range from_micros must be <= to_micros".into());
            }
        }
        Ok(())
    }
}

/// A NUL byte can terminate a C string in a downstream layer — reject it
/// everywhere. Also enforce the length bound.
fn check_value(what: &str, v: &str) -> Result<(), String> {
    if v.len() > MAX_VALUE_LEN {
        return Err(format!("{what} value too long (> {MAX_VALUE_LEN} bytes)"));
    }
    if v.contains('\0') {
        return Err(format!("{what} value contains a NUL byte"));
    }
    Ok(())
}

fn check_query(what: &str, q: &str) -> Result<(), String> {
    if q.trim().is_empty() {
        return Err(format!("{what} query is empty"));
    }
    if q.len() > MAX_QUERY_LEN {
        return Err(format!("{what} query too long (> {MAX_QUERY_LEN} bytes)"));
    }
    if q.contains('\0') {
        return Err(format!("{what} query contains a NUL byte"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_round_trip() {
        let q = HybridQuery::default();
        let s = serde_json::to_string(&q).unwrap();
        let back: HybridQuery = serde_json::from_str(&s).unwrap();
        assert_eq!(q, back);
        assert_eq!(q.fusion.limit, 20);
        assert!(matches!(q.fusion.method, FusionMethod::Rrf { k: 60 }));
    }

    #[test]
    fn deny_unknown_fields_rejects_typos() {
        // A typo'd key must be a hard error, never a silently-dropped predicate.
        assert!(serde_json::from_str::<HybridQuery>(r#"{"filterr":{}}"#).is_err());
        assert!(serde_json::from_str::<StructuredFilter>(r#"{"hostz":["a"]}"#).is_err());
        assert!(serde_json::from_str::<FusionConfig>(r#"{"lim":5}"#).is_err());
    }

    #[test]
    fn validate_rejects_empty_query() {
        let mut q = HybridQuery::default();
        assert!(q.validate().is_err(), "no dimension → rejected");
        // A time bound alone is a valid bounded query.
        q.filter.time.last_hours = Some(24.0);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn validate_clamps_fusion_bounds() {
        let mut q = HybridQuery::default();
        q.filter.host = vec!["web01".into()];
        q.fusion.limit = 100_000;
        q.fusion.candidate_cap = 1_000_000;
        q.fusion.per_signal_k = 99_999;
        q.fusion.text_weight = f32::NAN;
        q.validate().unwrap();
        assert_eq!(q.fusion.limit, MAX_LIMIT);
        assert_eq!(q.fusion.candidate_cap, MAX_CANDIDATE_CAP);
        assert_eq!(q.fusion.per_signal_k, MAX_PER_SIGNAL_K);
        assert_eq!(q.fusion.text_weight, 0.0);
    }

    #[test]
    fn validate_rejects_bad_field_key_and_oversized_value() {
        let mut q = HybridQuery::default();
        q.filter.fields = vec![FieldPredicate {
            key: "src ip".into(), // space is not allowed
            value: "x".into(),
            negate: false,
        }];
        assert!(q.validate().is_err());

        let mut q2 = HybridQuery::default();
        q2.filter.host = vec!["a".repeat(MAX_VALUE_LEN + 1)];
        assert!(q2.validate().is_err());
    }

    #[test]
    fn field_key_validity() {
        assert!(is_valid_field_key("src_ip"));
        assert!(is_valid_field_key("db.user-1"));
        assert!(!is_valid_field_key(""));
        assert!(!is_valid_field_key("a b"));
        assert!(!is_valid_field_key("a'b"));
        assert!(!is_valid_field_key(&"a".repeat(MAX_KEY_LEN + 1)));
    }
}