// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Risk-based attack-path ranking over the entity graph. Given a pivot start,
//! finds every reachable *case* that carries risk and ranks them by that risk —
//! case level × verdict disposition, the same weights RBA uses to score hosts —
//! so the graph surfaces "which adjudicated threats is this entity connected
//! to, worst first" with the shortest route to each.

use crate::{Graph, Node, RankedPath, KIND_CASE};

impl Graph {
    /// Attack paths from `start`: every CASE reachable within `depth` hops that
    /// carries risk, ranked by that risk (case level × verdict disposition,
    /// same weights as RBA), each with the shortest route to it. Highest first.
    pub fn rank_paths(&self, start: &str, depth: usize) -> Vec<RankedPath<'_>> {
        let mut out = Vec::new();
        for hit in self.pivot(start, depth) {
            if hit.node.kind != KIND_CASE {
                continue;
            }
            let score = case_risk(hit.node);
            if score <= 0.0 {
                continue; // benign / no-signal case — not an attack path
            }
            let path = self
                .shortest_path(start, &hit.node.id)
                .map(|p| p.iter().map(|n| n.id.clone()).collect())
                .unwrap_or_default();
            out.push(RankedPath {
                score,
                target: hit.node,
                path,
            });
        }
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }
}

/// A case node's risk = level weight × disposition multiplier (mirrors RBA, so
/// the graph ranks attack paths the same way risk scores hosts). Reads the
/// level/disposition from the node's `meta`.
fn case_risk(node: &Node) -> f64 {
    let level = node.meta.get("level").map(String::as_str).unwrap_or("");
    let base = match level.to_ascii_lowercase().as_str() {
        "critical" => 13.0,
        "high" => 8.0,
        "medium" => 4.0,
        "low" => 2.0,
        "informational" | "info" => 1.0,
        _ => 2.0,
    };
    // `disposition` is only present once the case is triaged.
    let mult = match node.meta.get("disposition").map(String::as_str) {
        Some("malicious") => 2.0,
        Some("suspicious") | Some("needs_human") => 1.0,
        Some("benign") => 0.0,
        Some(_) => 1.0,
        None => 0.5, // untriaged / in-flight — partial credit
    };
    base * mult
}