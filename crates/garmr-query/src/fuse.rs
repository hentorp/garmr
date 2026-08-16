// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Signal fusion. Reciprocal Rank Fusion (RRF) is the default: it ranks on
//! ordinal position only, so it fuses BM25 (unbounded), cosine ([-1,1]), and
//! boolean structured membership WITHOUT any score calibration.
//!
//! The subtle part (design-review FIX #1): the semantic index is built by
//! grouping `host,service,message` and taking `max(event_ts)`, so a semantic hit
//! is NOT tied to a specific event timestamp. Structured and full-text hits ARE
//! per-event. So the fuser uses TWO key kinds: an event-key (ts+host+service+
//! message) for structured/full-text, and a msg-key (host+service+message) for
//! semantic — and a semantic hit reinforces ALL events sharing its msg triple,
//! never a single ts-bearing row it can't actually name.

use std::collections::HashMap;

use crate::ir::{FusionConfig, FusionMethod, Window};
use crate::result::{HybridResult, ResultItem, SemanticStatus, Signal, SignalMatch};

/// One event row shuttled from the executor into fusion (and out as a
/// `ResultItem`).
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub ts_micros: i64,
    pub host: String,
    pub service: String,
    pub severity: String,
    pub message: String,
}

/// A trait the executor uses to reach a semantic backend (the local
/// Embedder+VectorStore, or an API adapter) WITHOUT garmr-query depending on
/// candle — the semantic side is dependency-injected, so the base build has no
/// embed edge and the fusion path is mockable in tests.
pub trait SemanticSearch: Send + Sync {
    /// Top-`k` semantically-nearest event rows for a natural-language query.
    fn search(&self, nl: &str, k: usize) -> Vec<SemanticHit>;
}

/// One semantic hit. `ts_micros` is the group's representative (max) timestamp —
/// used only to render a semantic-ONLY result, never to key fusion.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticHit {
    pub ts_micros: i64,
    pub host: String,
    pub service: String,
    pub message: String,
    pub score: f32,
    /// Ingest origin, so the semantic leg can be filtered by a credential's data
    /// scope. Additive with a `Default` of empty — a backend that does not
    /// populate it produces hits no CONFINED credential can see, which is the
    /// safe direction for a field whose absence means "unattributable".
    pub source: String,
}

/// The per-event fusion key (16-byte BLAKE3 of the event identity).
fn event_key(r: &Row) -> [u8; 16] {
    frame16(&[
        &r.ts_micros.to_le_bytes(),
        r.host.as_bytes(),
        r.service.as_bytes(),
        r.message.as_bytes(),
    ])
}

/// The message-identity key (no timestamp) — how a semantic hit aligns with the
/// per-event signals.
fn msg_key(host: &str, service: &str, message: &str) -> [u8; 16] {
    frame16(&[host.as_bytes(), service.as_bytes(), message.as_bytes()])
}

fn frame16(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full.as_bytes()[..16]);
    out
}

/// Fuse the three signals into one ranked, deduplicated, provenance-carrying
/// result. `has_structured_signal` means a structured filter compiled to SQL and
/// its `structured` rows are the GATE: when true, text/semantic contributions
/// only count for events in the structured candidate set. Inputs are in each
/// signal's own rank order (index 0 = best).
///
/// `window` is the query's resolved time window and is enforced here as the LAST
/// word: each leg already bounds itself, so this only ever catches a leg that
/// failed to — but it makes "no result ever falls outside the requested window"
/// a property of the fuser rather than a promise spread across three legs. It
/// also decides the one case a leg genuinely cannot: a semantic hit names a
/// message group, not an event, so it may only stand alone as a row when its
/// own (group-max) timestamp is inside the window.
#[allow(clippy::too_many_arguments)]
pub fn fuse(
    structured: &[Row],
    has_structured_signal: bool,
    fulltext: &[(Row, f32)],
    semantic: &[SemanticHit],
    semantic_status: SemanticStatus,
    window: Window,
    cfg: &FusionConfig,
) -> HybridResult {
    let mut rows: HashMap<[u8; 16], Row> = HashMap::new();
    let mut prov: HashMap<[u8; 16], Vec<SignalMatch>> = HashMap::new();

    // NOTE: the per-row `event_key`/`score_key` work here is intentionally SERIAL.
    // A gatling fan-out was tried and MEASURED net-negative (5000-row universe:
    // 193 -> 134 fusions/s) — the BLAKE3-of-four-short-fields is too cheap to
    // amortize the scoped-thread spawn, and the HashMap build (+ per-row `Row`
    // clone) dominates and cannot be parallelized. garm's fusion CPU is small;
    // the real search_sql cost is skade-internal. See hot path 8 in the audit.

    // 1. Structured rows define the gate universe (when present).
    let mut gate: Option<std::collections::HashSet<[u8; 16]>> = if has_structured_signal {
        Some(std::collections::HashSet::new())
    } else {
        None
    };
    for (i, r) in structured.iter().enumerate() {
        if !window.contains(r.ts_micros) {
            continue;
        }
        let k = event_key(r);
        rows.insert(k, r.clone());
        prov.entry(k).or_default().push(SignalMatch {
            signal: Signal::Structured,
            rank: i + 1,
            raw_score: None,
        });
        if let Some(g) = gate.as_mut() {
            g.insert(k);
        }
    }

    // 2. Full-text hits — gated by event-key membership when a gate is active.
    for (i, (r, score)) in fulltext.iter().enumerate() {
        if !window.contains(r.ts_micros) {
            continue;
        }
        let k = event_key(r);
        if let Some(g) = &gate {
            if !g.contains(&k) {
                continue;
            }
        }
        rows.entry(k).or_insert_with(|| r.clone());
        prov.entry(k).or_default().push(SignalMatch {
            signal: Signal::FullText,
            rank: i + 1,
            raw_score: Some(*score),
        });
    }

    // 3. Build the msg-key -> event-keys index over the CURRENT universe (the
    //    events a semantic hit is allowed to reinforce).
    let mut by_msg: HashMap<[u8; 16], Vec<[u8; 16]>> = HashMap::new();
    for (k, r) in &rows {
        by_msg
            .entry(msg_key(&r.host, &r.service, &r.message))
            .or_default()
            .push(*k);
    }

    // 4. Semantic hits attribute their rank to ALL events sharing the triple;
    //    with no such event and no gate, the hit stands alone (its group-max ts).
    for (i, h) in semantic.iter().enumerate() {
        let mk = msg_key(&h.host, &h.service, &h.message);
        let targets = by_msg.get(&mk).cloned().unwrap_or_default();
        if targets.is_empty() {
            if gate.is_some() {
                continue; // outside the structured candidate set
            }
            if !window.contains(h.ts_micros) {
                // Standing alone, the hit would be RENDERED at its group-max
                // timestamp — a row outside the window the analyst asked for.
                // Reinforcing an in-window event (the branch below) is fine:
                // that event's own timestamp is what the row shows.
                continue;
            }
            let r = Row {
                ts_micros: h.ts_micros,
                host: h.host.clone(),
                service: h.service.clone(),
                severity: String::new(),
                message: h.message.clone(),
            };
            let k = event_key(&r);
            rows.insert(k, r);
            prov.entry(k).or_default().push(SignalMatch {
                signal: Signal::Semantic,
                rank: i + 1,
                raw_score: Some(h.score),
            });
        } else {
            for k in targets {
                prov.entry(k).or_default().push(SignalMatch {
                    signal: Signal::Semantic,
                    rank: i + 1,
                    raw_score: Some(h.score),
                });
            }
        }
    }

    // 5. Score, sort (stable tie-break by key), truncate. (Serial — see the note
    //    at the top of `fuse`: the fan-out was measured net-negative.)
    let mut scored: Vec<([u8; 16], f32)> = rows
        .keys()
        .map(|k| (*k, score_key(&prov[k], cfg)))
        .collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    let total = scored.len();
    let truncated = total > cfg.limit;

    let items = scored
        .into_iter()
        .take(cfg.limit)
        .map(|(k, s)| {
            let r = &rows[&k];
            let mut p = prov.remove(&k).unwrap_or_default();
            p.sort_by_key(|m| (signal_ord(m.signal), m.rank));
            ResultItem {
                ts_micros: r.ts_micros,
                host: r.host.clone(),
                service: r.service.clone(),
                severity: r.severity.clone(),
                message: r.message.clone(),
                fused_score: s,
                provenance: p,
            }
        })
        .collect();

    HybridResult {
        items,
        semantic_status,
        truncated,
    }
}

fn signal_ord(s: Signal) -> u8 {
    match s {
        Signal::Structured => 0,
        Signal::FullText => 1,
        Signal::Semantic => 2,
    }
}

/// The fused score of one event from its per-signal matches.
fn score_key(matches: &[SignalMatch], cfg: &FusionConfig) -> f32 {
    let weight = |s: Signal| match s {
        Signal::Structured => cfg.structured_weight,
        Signal::FullText => cfg.text_weight,
        Signal::Semantic => cfg.semantic_weight,
    };
    match cfg.method {
        FusionMethod::Rrf { k } => matches
            .iter()
            .map(|m| weight(m.signal) / (k as f32 + m.rank as f32))
            .sum(),
        FusionMethod::WeightedNormalized => {
            // Weighted reciprocal-rank: weight * (1/rank). Fuses on ordinal
            // position like RRF (raw score magnitudes are intentionally not
            // calibrated) but weights the signals without RRF's `k` softening.
            matches
                .iter()
                .map(|m| weight(m.signal) * (1.0 / m.rank as f32))
                .sum()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ts: i64, host: &str, msg: &str) -> Row {
        Row {
            ts_micros: ts,
            host: host.into(),
            service: "svc".into(),
            severity: "low".into(),
            message: msg.into(),
        }
    }

    fn cfg() -> FusionConfig {
        FusionConfig::default()
    }

    /// A WIDE fusion must still rank correctly and deterministically — the
    /// multi-signal event tops the result even amid thousands of filler rows.
    /// Guards the fusion invariant on a large universe (the width a search-side
    /// audit cares about), independent of any parallelization decision.
    #[test]
    fn wide_fuse_is_deterministic_and_correct() {
        let mut structured: Vec<Row> = (0..3_000)
            .map(|i| row(i as i64, "h", &format!("filler {i}")))
            .collect();
        let hot = row(999_999, "h", "the doubly matched event");
        structured.push(hot.clone());
        let res = fuse(
            &structured,
            true,
            &[(hot.clone(), 9.0)], // full-text reinforces the hot event
            &[],
            SemanticStatus::NotRequested,
            Window::default(),
            &cfg(),
        );
        assert_eq!(res.items[0].message, "the doubly matched event");
        assert_eq!(res.items[0].provenance.len(), 2);
    }

    #[test]
    fn rrf_ranks_multi_signal_hits_above_single() {
        // Event A matched by BOTH full-text and structured; event B by one.
        let a = row(1, "h", "failed password A");
        let b = row(2, "h", "note B");
        let res = fuse(
            &[a.clone(), b.clone()], // structured: A rank1, B rank2
            true,
            &[(a.clone(), 5.0)], // full-text: A rank1
            &[],
            SemanticStatus::NotRequested,
            Window::default(),
            &cfg(),
        );
        assert_eq!(res.items.len(), 2);
        // A has two signals → outranks B.
        assert_eq!(res.items[0].message, "failed password A");
        assert_eq!(res.items[0].provenance.len(), 2);
    }

    #[test]
    fn semantic_reinforces_all_events_with_the_same_triple() {
        // Two events, same (host,service,message) at different timestamps.
        let e1 = row(100, "h", "Failed password for root");
        let e2 = row(200, "h", "Failed password for root");
        // Semantic hit keyed by the msg triple (group-max ts=200).
        let sem = vec![SemanticHit {
            ts_micros: 200,
            host: "h".into(),
            service: "svc".into(),
            message: "Failed password for root".into(),
            source: "journald".into(),
            score: 0.9,
        }];
        let res = fuse(
            &[e1.clone(), e2.clone()],
            true,
            &[],
            &sem,
            SemanticStatus::Used,
            Window::default(),
            &cfg(),
        );
        // BOTH events get a semantic provenance entry (the FIX #1 behaviour).
        assert_eq!(res.items.len(), 2);
        assert!(res
            .items
            .iter()
            .all(|it| it.provenance.iter().any(|p| p.signal == Signal::Semantic)));
    }

    #[test]
    fn gate_drops_fulltext_outside_the_structured_set() {
        let inside = row(1, "web01", "x");
        let outside = row(2, "web99", "y");
        let res = fuse(
            std::slice::from_ref(&inside), // structured gate = {inside}
            true,
            &[(outside.clone(), 9.0)], // full-text hit outside the gate
            &[],
            SemanticStatus::NotRequested,
            Window::default(),
            &cfg(),
        );
        assert_eq!(res.items.len(), 1);
        assert_eq!(res.items[0].host, "web01");
    }

    #[test]
    fn semantic_only_query_returns_semantic_rows() {
        let sem = vec![SemanticHit {
            ts_micros: 42,
            host: "h".into(),
            service: "svc".into(),
            message: "anomalous login".into(),
            source: "journald".into(),
            score: 0.7,
        }];
        let res = fuse(
            &[],
            false,
            &[],
            &sem,
            SemanticStatus::Used,
            Window::default(),
            &cfg(),
        );
        assert_eq!(res.items.len(), 1);
        assert_eq!(res.items[0].message, "anomalous login");
    }

    // ---- the window is the fuser's last word --------------------------------

    fn window(from: i64, to: i64) -> Window {
        Window {
            from_us: Some(from),
            to_us: Some(to),
        }
    }

    #[test]
    fn no_signal_can_place_a_row_outside_the_window() {
        // Each leg bounds itself; the fuser is the backstop that makes it an
        // invariant. Feed every leg an out-of-window row and expect none back.
        let inside = row(150, "h", "inside");
        let early = row(50, "h", "too early");
        let late = row(250, "h", "too late");
        let res = fuse(
            &[inside.clone(), early.clone()],
            true,
            &[(late.clone(), 9.0)],
            &[],
            SemanticStatus::NotRequested,
            window(100, 200),
            &cfg(),
        );
        assert_eq!(res.items.len(), 1);
        assert_eq!(res.items[0].message, "inside");
    }

    #[test]
    fn a_semantic_hit_may_reinforce_in_window_events_but_not_stand_outside() {
        // The hit's timestamp is its message group's MAX (200 = out of window),
        // yet an in-window event shares the triple: reinforcing THAT event is
        // honest — the row shows the event's own in-window timestamp.
        let e = row(150, "h", "Failed password for root");
        let sem = vec![SemanticHit {
            ts_micros: 200,
            host: "h".into(),
            service: "svc".into(),
            message: "Failed password for root".into(),
            source: "journald".into(),
            score: 0.9,
        }];
        let res = fuse(
            std::slice::from_ref(&e),
            false,
            &[],
            &sem,
            SemanticStatus::Used,
            window(100, 200),
            &cfg(),
        );
        assert_eq!(res.items.len(), 1);
        assert_eq!(res.items[0].ts_micros, 150);
        assert!(res.items[0]
            .provenance
            .iter()
            .any(|p| p.signal == Signal::Semantic));

        // With no event to reinforce, the same hit would have to be rendered at
        // its own out-of-window timestamp — so it is dropped instead.
        let alone = fuse(
            &[],
            false,
            &[],
            &sem,
            SemanticStatus::Used,
            window(100, 200),
            &cfg(),
        );
        assert!(alone.items.is_empty());
    }

    #[test]
    fn truncates_to_limit() {
        let mut c = cfg();
        c.limit = 1;
        let rows: Vec<Row> = (0..5).map(|i| row(i, "h", &format!("m{i}"))).collect();
        let res = fuse(
            &rows,
            true,
            &[],
            &[],
            SemanticStatus::NotRequested,
            Window::default(),
            &c,
        );
        assert_eq!(res.items.len(), 1);
        assert!(res.truncated);
    }
}
