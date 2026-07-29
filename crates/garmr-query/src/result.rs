// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The hybrid-search result: ranked event rows with per-item PROVENANCE (which
//! signals matched, at what rank/score) so a result is explainable — not an
//! opaque ordering.

use serde::Serialize;

/// The full fused result.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct HybridResult {
    pub items: Vec<ResultItem>,
    /// Whether the semantic clause actually ran (honest about a missing model).
    pub semantic_status: SemanticStatus,
    /// True when more results existed than the query's `limit`.
    pub truncated: bool,
}

/// One ranked event row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResultItem {
    pub ts_micros: i64,
    pub host: String,
    pub service: String,
    pub severity: String,
    pub message: String,
    /// The fused score (higher = better); scale depends on the fusion method.
    pub fused_score: f32,
    /// Which signals contributed to this item, and how.
    pub provenance: Vec<SignalMatch>,
}

/// One signal's contribution to a fused item.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SignalMatch {
    pub signal: Signal,
    /// 1-based rank of this item within that signal's result list.
    pub rank: usize,
    /// The signal's raw score, when it has one (BM25/cosine; structured is
    /// boolean membership and carries `None`).
    pub raw_score: Option<f32>,
}

/// The three retrieval signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    Structured,
    FullText,
    Semantic,
}

impl Signal {
    /// A one-letter tag for a compact `[S/F/V]` provenance render.
    pub fn tag(self) -> char {
        match self {
            Signal::Structured => 'S',
            Signal::FullText => 'F',
            Signal::Semantic => 'V',
        }
    }
}

/// Whether the semantic clause ran — surfaced so a caller knows a query that
/// requested semantics on a build/deploy without a model got a
/// structured+full-text answer, not a silently-degraded one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStatus {
    /// The query did not request a semantic clause.
    #[default]
    NotRequested,
    /// Requested and used.
    Used,
    /// Requested, but no semantic backend was available (feature off / no model).
    RequestedButUnavailable,
}