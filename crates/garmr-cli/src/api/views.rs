// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Assembled read views: cases list + detail (with the Phase-3 `current`
//! block), ATT&CK coverage of the configured ruleset, the entity-graph pivot +
//! the full topology graph for the 3D map, per-host AND per-entity risk
//! (RBA), the cached events-total tile (single-flight background count), and
//! the ingest-quality surfaces: per-source event-lag/staleness and
//! per-collector delivery-sequence integrity.

use super::*;

/// GET /api/cases — all triage cases, newest first.
pub(super) async fn cases(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let mut cases = st.store.state.list_cases().map_err(oops)?;
    // Queue filters (2.9): exact matches, applied server-side so a two-analyst
    // queue ("mine", "unassigned", "tagged escalation") is one request, not a
    // client-side scan of everything.
    if let Some(a) = p.get("assignee") {
        match a.as_str() {
            // The queue's third lane: nobody's yet.
            "" | "(unassigned)" => cases.retain(|c| c.assignee.is_none()),
            a => cases.retain(|c| c.assignee.as_deref() == Some(a)),
        }
    }
    if let Some(t) = p.get("tag") {
        let t = t.to_lowercase();
        cases.retain(|c| c.tags.contains(&t));
    }
    if let Some(s) = p.get("state") {
        cases.retain(|c| format!("{:?}", c.state).eq_ignore_ascii_case(s));
    }
    // With SLAs configured, each case carries its computed clock position —
    // computed at read time, never stored, so the numbers cannot go stale.
    let sla_cfg = &st.cfg.cases.sla;
    if sla_cfg.ack_minutes > 0 || sla_cfg.resolve_minutes > 0 {
        let now = chrono::Utc::now();
        let rows: Vec<serde_json::Value> = cases
            .iter()
            .map(|c| {
                let mut v = serde_json::to_value(c).unwrap_or_default();
                if let (Some(obj), Some(sla)) = (
                    v.as_object_mut(),
                    garmr_core::sla::sla_status(c, sla_cfg, now),
                ) {
                    obj.insert("sla".into(), serde_json::to_value(sla).unwrap_or_default());
                }
                v
            })
            .collect();
        return Ok(Json(Page::from_query(&p).envelope("cases", rows)));
    }
    Ok(Json(Page::from_query(&p).envelope("cases", cases)))
}

/// GET /api/attack/coverage — MITRE ATT&CK coverage of the configured detection
/// ruleset (Sigma + correlation, re-read from the rule dirs), aggregated by
/// technique and by the 14 enterprise tactics. Shows what the rules cover and,
/// per Sigma tactic tags, which tactics have rule coverage, plus rules carrying
/// no ATT&CK technique tag at all. NOTE: tactic credit comes from Sigma tactic
/// tags only — correlation rules contribute techniques but carry no tactic tag.
pub(super) async fn attack_coverage(State(st): State<ApiState>) -> ApiResult {
    use std::collections::{BTreeMap, BTreeSet};

    // Enterprise tactics in kill-chain order (Sigma tag form, hyphenated).
    const TACTICS: [&str; 14] = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ];

    struct R {
        id: String,
        title: String,
        level: String,
        source: &'static str,
        techniques: Vec<String>,
        tactics: Vec<String>,
    }
    let mut rules: Vec<R> = Vec::new();

    // Sigma rules (best-effort: a missing dir / parse error yields no rules).
    for m in garmr_detect::rule_metas(&st.cfg.detect.rules_dir).unwrap_or_default() {
        rules.push(R {
            id: m.id,
            title: m.title,
            level: m.level,
            source: "sigma",
            techniques: m.techniques,
            tactics: m.tactics,
        });
    }
    // Correlation rules: `attack = "T1110->T1078"` → technique ids (no tactics).
    // Validate the T<digits> shape (as the Sigma path does) so free-text like
    // "brute force" / "TBD" can't pollute the map with bogus techniques + dead
    // MITRE links; dedup a self-referential chain (T1110->T1110).
    for r in garmr_correlate::load_rules(&st.cfg.detect.correlations_dir) {
        let mut techniques: Vec<String> = r
            .attack
            .split("->")
            .map(str::trim)
            .map(str::to_ascii_uppercase)
            .filter(|s| is_technique_id(s))
            .collect();
        techniques.sort();
        techniques.dedup();
        rules.push(R {
            id: r.id,
            title: r.title,
            level: r.severity,
            source: "correlation",
            techniques,
            tactics: Vec::new(),
        });
    }

    // Builtin (synthetic) detectors: the insider/app-audit plane and the
    // environment-drift plane. These are code, not rule files, so without them
    // the matrix reported zero coverage exactly where garmr is differentiated —
    // a buyer asking "what does it detect on day one" got the most misleading
    // possible answer. Each crate derives its inventory from the same constants
    // its detectors fire on, so this cannot drift from real behaviour.
    for (id, title, level, techniques) in garmr_appdetect::detector_inventory() {
        rules.push(R {
            id: id.to_string(),
            title: title.to_string(),
            level: level.to_string(),
            source: "builtin",
            techniques,
            // No tactic tags: these declare techniques only, and inferring a
            // tactic from a technique would be this endpoint inventing coverage
            // its inputs never claimed.
            tactics: Vec::new(),
        });
    }
    for (id, title, level, techniques) in garmr_analytics::envdetect::ENV_DETECTORS {
        rules.push(R {
            id: (*id).to_string(),
            title: (*title).to_string(),
            level: (*level).to_string(),
            source: "builtin",
            techniques: techniques.iter().map(|t| (*t).to_string()).collect(),
            tactics: Vec::new(),
        });
    }

    // technique id → rules covering it
    let mut by_tech: BTreeMap<String, Vec<&R>> = BTreeMap::new();
    for r in &rules {
        for t in &r.techniques {
            by_tech.entry(t.clone()).or_default().push(r);
        }
    }
    let techniques: Vec<Value> = by_tech
        .iter()
        .map(|(tech, rs)| {
            json!({
                "id": tech,
                "rule_count": rs.len(),
                "max_level": max_level(rs.iter().map(|r| r.level.as_str())),
                "rules": rs.iter().map(|r| json!({
                    "id": r.id, "title": r.title, "level": r.level, "source": r.source,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    // Tactic coverage from explicit tactic tags (Sigma). A tactic with 0
    // techniques is a visible blind spot.
    let mut tactic_rules: BTreeMap<&str, usize> = BTreeMap::new();
    let mut tactic_tech: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for r in &rules {
        for t in &r.tactics {
            if let Some(canon) = TACTICS.iter().find(|c| **c == t.as_str()) {
                *tactic_rules.entry(*canon).or_default() += 1;
                let set = tactic_tech.entry(*canon).or_default();
                for tech in &r.techniques {
                    set.insert(tech.clone());
                }
            }
        }
    }
    let tactics: Vec<Value> = TACTICS
        .iter()
        .map(|t| {
            json!({
                "name": t,
                "rules": tactic_rules.get(t).copied().unwrap_or(0),
                "techniques": tactic_tech.get(t).map(BTreeSet::len).unwrap_or(0),
            })
        })
        .collect();

    // Rules with no ATT&CK technique tag — blind spots in your own ruleset.
    let untagged: Vec<Value> = rules
        .iter()
        .filter(|r| r.techniques.is_empty())
        .map(|r| json!({ "id": r.id, "title": r.title, "source": r.source }))
        .collect();

    Ok(Json(json!({
        "rules_total": rules.len(),
        "techniques_covered": by_tech.len(),
        "tactics": tactics,
        "techniques": techniques,
        "untagged_rules": untagged,
    })))
}

/// Is `s` an ATT&CK technique id — `T` + digits, optional `.subid` (T1110 / T1110.001)?
fn is_technique_id(s: &str) -> bool {
    s.strip_prefix('T').is_some_and(|rest| {
        rest.starts_with(|c: char| c.is_ascii_digit())
            && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
    })
}

/// Highest severity level present, ranked critical>high>medium>low>info.
fn max_level<'a>(levels: impl Iterator<Item = &'a str>) -> String {
    fn rank(l: &str) -> u8 {
        match l {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "informational" | "info" => 1,
            _ => 3,
        }
    }
    levels
        .max_by_key(|l| rank(l))
        .unwrap_or("medium")
        .to_string()
}

/// GET /api/graph/pivot?kind=&name=&depth= — entities/cases connected to an
/// entity in the case graph (host↔ip↔user↔case), BFS to `depth` hops.
pub(super) async fn graph_pivot(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let kind = p.get("kind").ok_or_else(|| bad("missing ?kind="))?;
    let name = p.get("name").ok_or_else(|| bad("missing ?name="))?;
    let depth = p
        .get("depth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2usize)
        .min(6);
    // Shared, time-bounded build (case edges + best-effort event edges).
    let graph = st.graph_cache.get(&st.store).await.map_err(oops)?;
    let start = garmr_graph::node_id(kind, name);
    let (nodes, _edges) = graph.size();
    let degraded = graph.degraded();
    if !graph.contains(&start) {
        return Ok(Json(
            json!({ "start": start, "found": false, "degraded": degraded, "graph_nodes": nodes, "connected": [], "edges": [], "edges_truncated": false, "attack_paths": [] }),
        ));
    }
    let hits = graph.pivot(&start, depth);
    let connected: Vec<Value> = hits
        .iter()
        .map(|h| {
            let n = h.node;
            json!({ "hop": h.hop, "via": h.via.as_str(), "id": n.id, "kind": n.kind, "name": n.name, "label": n.label, "meta": n.meta })
        })
        .collect();
    // Induced edges among the reached nodes (+ the start) so the console can
    // draw a node-link graph, not just the grouped list. Bounded: a hub pivot
    // over a dense event graph would otherwise emit an O(n²) edge payload the
    // console can't draw anyway — take the BFS-closest nodes and cap the list,
    // flagging the truncation.
    const EDGE_NODE_CAP: usize = 256;
    const EDGE_CAP: usize = 2000;
    let mut ids: std::collections::BTreeSet<String> = hits
        .iter()
        .take(EDGE_NODE_CAP)
        .map(|h| h.node.id.clone())
        .collect();
    ids.insert(start.clone());
    let all_edges = graph.edges_among(&ids);
    let edges_truncated = all_edges.len() > EDGE_CAP;
    let edges: Vec<Value> = all_edges
        .into_iter()
        .take(EDGE_CAP)
        .map(|(a, b, k)| json!({ "source": a, "target": b, "via": k.as_str() }))
        .collect();
    // Attack paths: reachable non-benign cases, ranked by risk.
    let attack_paths: Vec<Value> = graph
        .rank_paths(&start, depth)
        .into_iter()
        .take(10)
        .map(|rp| json!({ "score": rp.score, "case": rp.target.name, "rule": rp.target.label, "path": rp.path }))
        .collect();
    Ok(Json(json!({
        "start": start, "found": true, "degraded": degraded, "graph_nodes": nodes,
        "connected": connected, "edges": edges, "edges_truncated": edges_truncated,
        "attack_paths": attack_paths,
    })))
}

/// GET /api/graph — the WHOLE monitored entity graph (all nodes + edges) for
/// the 3D topology map, not a pivot. Capped: if the graph exceeds the caps the
/// highest-degree nodes win (hosts prioritised so the server backbone always
/// survives a cap), plus the edges among the kept nodes.
pub(super) async fn graph_full(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    const NODE_CAP: usize = 400;
    const EDGE_CAP: usize = 4000;
    // Time window (explicit windows go through the bounded windowed cache —
    // issue #23 — so distinct windows queue on one build lock instead of
    // fanning out concurrent lake scans):
    //   ?from=&to=  epoch-millis absolute [from, to) — scopes hosts AND edges;
    //   ?hours=N    last-N-hours relative — edges to that span, hosts keep the
    //               ≥14d floor so the node set stays monotonic (clamped (0,1yr]);
    //   neither     → the cached default graph.
    let range = p
        .get("from")
        .and_then(|s| s.parse::<i64>().ok())
        .zip(p.get("to").and_then(|s| s.parse::<i64>().ok()))
        .filter(|(from, to)| from < to);
    let graph = if let Some((from_ms, to_ms)) = range {
        let rfc = |ms: i64| {
            chrono::DateTime::from_timestamp_millis(ms)
                .unwrap_or_default()
                .to_rfc3339()
        };
        let win = garmr_graph::TimeWindow::Range {
            from: rfc(from_ms),
            to: rfc(to_ms),
        };
        st.graph_cache
            .get_window(&st.store, win.clone(), win)
            .await
            .map_err(oops)?
    } else if let Some(hours) = p
        .get("hours")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|h| h.clamp(1, 8760))
    {
        st.graph_cache
            .get_window(
                &st.store,
                garmr_graph::TimeWindow::LastHours(hours),
                garmr_graph::TimeWindow::LastHours(hours.max(336)),
            )
            .await
            .map_err(oops)?
    } else {
        st.graph_cache.get(&st.store).await.map_err(oops)?
    };
    let (total_nodes, total_edges) = graph.size();
    let degraded = graph.degraded();

    // Rank: hosts first (the backbone), then by degree, then id for stability.
    let mut nodes: Vec<_> = graph.all_nodes().collect();
    nodes.sort_by(|a, b| {
        let ha = u8::from(a.kind != "host");
        let hb = u8::from(b.kind != "host");
        ha.cmp(&hb)
            .then_with(|| graph.degree(&b.id).cmp(&graph.degree(&a.id)))
            .then_with(|| a.id.cmp(&b.id))
    });
    let node_truncated = nodes.len() > NODE_CAP;
    nodes.truncate(NODE_CAP);
    let kept: std::collections::BTreeSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let node_json: Vec<Value> = nodes
        .iter()
        .map(|n| {
            json!({ "id": n.id, "kind": n.kind, "name": n.name, "label": n.label,
                    "degree": graph.degree(&n.id),
                    "device_type": garmr_graph::node_device_type(n) })
        })
        .collect();

    let all = graph.edges_among(&kept);
    let edge_truncated = all.len() > EDGE_CAP;
    let edges: Vec<Value> = all
        .into_iter()
        .take(EDGE_CAP)
        .map(|(a, b, k)| json!({ "source": a, "target": b, "via": k.as_str() }))
        .collect();

    Ok(Json(json!({
        "nodes": node_json,
        "edges": edges,
        "node_count": total_nodes,
        "edge_count": total_edges,
        "shown_nodes": node_json.len(),
        "shown_edges": edges.len(),
        "truncated": node_truncated || edge_truncated,
        "degraded": degraded,
    })))
}

/// GET /api/risk — current RBA scores (adjudicated risk, decayed over the
/// scoring window), highest first, each with its top contributing cases. Covers
/// BOTH axes: per-host and per-entity (staff / db_user) — the same view the
/// `risk_loop` acts on and `garmr risk` prints. Each row carries its `kind`.
pub(super) async fn risk(State(st): State<ApiState>) -> ApiResult {
    let params = garmr_analytics::RiskParams {
        threshold: st.cfg.detect.risk_threshold,
        halflife_hours: st.cfg.detect.risk_halflife_hours,
        realert_secs: st.cfg.detect.risk_realert_secs,
        prediction_discount: st.cfg.detect.prediction_discount,
    };
    let cases = st.store.state.list_cases().map_err(oops)?;
    // Resolve each case through the Phase-3 trust precedence so a human decision
    // or incident outcome outweighs the discounted agent prediction.
    let index = garmr_analytics::OutcomeIndex::build(
        &cases,
        &st.store.state.list_incident_outcomes().map_err(oops)?,
        &st.store.state.list_decisions().map_err(oops)?,
        &st.store.state.list_predictions().map_err(oops)?,
    );
    let now = chrono::Utc::now();
    let mut objects = garmr_analytics::score_hosts_with(&cases, now, &params, &index);
    objects.extend(garmr_analytics::score_staff_with(
        &cases, now, &params, &index,
    ));
    objects.sort_by(|a, b| b.score.total_cmp(&a.score));
    let rows: Vec<Value> = objects
        .iter()
        .map(|o| {
            json!({
                "kind": o.kind,
                "host": o.host,
                "score": o.score,
                "over_threshold": o.score >= params.threshold,
                "contributors": o.contributors.iter().take(10).map(|c| json!({
                    "case_id": c.case_id,
                    "rule_id": c.rule_id,
                    "level": c.level,
                    "contribution": c.contribution,
                    "trust": format!("{:?}", c.trust),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(json!({
        "threshold": params.threshold,
        "window_hours": garmr_analytics::WINDOW_HOURS,
        "risk": rows,
    })))
}

/// `GET /api/events/total` — total events row count for the console tile.
///
/// A plain `SELECT count(*) FROM events` is a FULL-TABLE scan that decompresses
/// every data file (~13 s here); polling THAT on the console's 5 s sweep was the
/// load source that pegged the box. iceberg-rust does not maintain a cumulative
/// `total-records` across fast-appends, so a metadata hint is unreliable — so we
/// compute the exact count at most once per TTL in the BACKGROUND (single-flight)
/// and serve the cached value instantly. The tile does not need finer freshness;
/// `total` is null only until the first background count completes.
static EVENTS_TOTAL_CACHE: std::sync::Mutex<Option<(i64, i64)>> = std::sync::Mutex::new(None);
static EVENTS_TOTAL_REFRESHING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(super) async fn events_total(State(st): State<ApiState>) -> ApiResult {
    use std::sync::atomic::Ordering;
    const TTL_SECS: i64 = 300;
    let now = chrono::Utc::now().timestamp();
    let (cached, stale) = match *EVENTS_TOTAL_CACHE.lock().unwrap() {
        Some((c, ts)) => (Some(c), now - ts >= TTL_SECS),
        None => (None, true),
    };
    if stale && !EVENTS_TOTAL_REFRESHING.swap(true, Ordering::SeqCst) {
        let store = st.store.clone();
        tokio::spawn(async move {
            let n = store
                .events
                .sql("SELECT count(*) AS n FROM events")
                .await
                .ok()
                .and_then(|b| count_scalar(&b));
            if let Some(n) = n {
                *EVENTS_TOTAL_CACHE.lock().unwrap() = Some((n, chrono::Utc::now().timestamp()));
            }
            EVENTS_TOTAL_REFRESHING.store(false, Ordering::SeqCst);
        });
    }
    Ok(Json(json!({ "total": cached })))
}

/// Pull a single scalar `i64` (e.g. a `count(*)`) out of a query result.
fn count_scalar(batches: &[skade::arrow_array::RecordBatch]) -> Option<i64> {
    use skade::arrow_array::{Array, Int64Array};
    let col = batches
        .first()?
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()?;
    (!col.is_empty()).then(|| col.value(0))
}

/// GET /api/cases/{id} — one case (prefix match allowed), with transcript.
pub(super) async fn case_by_id(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.store.state.get_case(&id) {
        Ok(Some(c)) => Ok(Json(case_json(&st, &c))),
        Ok(None) => {
            // Fall back to a short-id prefix match.
            match st.store.state.list_cases() {
                Ok(list) => match list.into_iter().find(|c| c.id.starts_with(&id)) {
                    Some(c) => Ok(Json(case_json(&st, &c))),
                    None => Err((StatusCode::NOT_FOUND, format!("no case matching {id}"))),
                },
                Err(e) => Err(oops(e)),
            }
        }
        Err(e) => Err(oops(e)),
    }
}

/// Serialize a case and additively merge a Phase-3 `current` block (latest
/// prediction + non-superseded decision + incident outcome, and the effective
/// trusted disposition). Backward compatible: every existing key is preserved
/// and `current` is added alongside. A store-read error on the record tables
/// degrades to the bare case rather than turning a case fetch into a 500.
fn case_json(st: &ApiState, c: &garmr_core::Case) -> Value {
    let mut v = json!(c);
    if let (Some(obj), Ok(view)) = (v.as_object_mut(), st.store.state.case_view(&c.id)) {
        let prediction = garmr_core::current_prediction(&view.predictions);
        let decision = garmr_core::current_decision(&view.decisions);
        let outcome = garmr_core::current_outcome(&view.outcomes);
        // Effective disposition: trusted outcome > analyst decision > prediction
        // > the shadow verdict.
        let effective = outcome
            .map(|o| o.disposition)
            .or_else(|| decision.map(|d| d.disposition))
            .or_else(|| prediction.map(|p| p.disposition))
            .or_else(|| c.verdict.as_ref().map(|vd| vd.disposition));
        obj.insert(
            "current".to_string(),
            json!({
                "effective_disposition": effective.map(|d| format!("{d:?}")),
                "prediction_count": view.predictions.len(),
                "decision_count": view.decisions.len(),
                "has_incident_outcome": !view.outcomes.is_empty(),
                "prediction": prediction,
                "decision": decision,
                "outcome": outcome,
            }),
        );
    }
    v
}

/// GET /api/collectors — per-collector DELIVERY-SEQUENCE integrity, distinct from
/// `/api/ingest/health`'s event-lag view: for each authenticated `(collector,
/// epoch)` the first/high sequence, confirmed gaps (lost batches), still-
/// outstanding seqs (lost or in flight), replays (duplicate delivery), and last
/// update. This is exactly the sequence tracking `garmr ingest-health` shows on
/// the host, exposed so the console has a Collectors surface. Paginated envelope.
pub(super) async fn collectors(
    State(st): State<ApiState>,
    Query(p): Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    let health = st.store.state.ingest_seq_health().map_err(oops)?;
    Ok(Json(Page::from_query(&p).envelope("collectors", health)))
}

/// GET /api/ingest/health[?hours=168] — per-source ingest quality from the Event
/// V2 provenance columns: event count, last event/ingest time, ingest lag
/// (ingest_time − event_ts) and staleness (now − last ingest). Read-only; the
/// building block for source-heartbeat and data-quality monitoring. Sources with
/// only legacy (V1) rows report null ingest metrics.
pub(super) async fn ingest_health(
    State(st): State<ApiState>,
    Query(p): Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    use skade::arrow_array::{Array, Int64Array, StringArray, TimestampMicrosecondArray};
    let hours: i64 = p
        .get("hours")
        .and_then(|s| s.parse().ok())
        .unwrap_or(168)
        .clamp(1, 8760);
    let sql = format!(
        "SELECT source, count(*) AS events, max(event_ts) AS last_event, \
         max(ingest_time) AS last_ingest FROM events \
         WHERE event_ts >= now() - INTERVAL '{hours} hours' \
         GROUP BY source ORDER BY events DESC"
    );
    let batches = st.store.events.sql(sql).await.map_err(oops)?;
    let now_us = chrono::Utc::now().timestamp_micros();
    let mut sources = Vec::new();
    for b in &batches {
        let source = b
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| oops("ingest-health: source column"))?;
        let events = b
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| oops("ingest-health: events column"))?;
        let last_event = b
            .column(2)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| oops("ingest-health: last_event column"))?;
        let last_ingest = b
            .column(3)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| oops("ingest-health: last_ingest column"))?;
        for i in 0..b.num_rows() {
            let le = (!last_event.is_null(i)).then(|| last_event.value(i));
            let li = (!last_ingest.is_null(i)).then(|| last_ingest.value(i));
            let staleness = li.map(|v| (now_us - v) / 1_000_000);
            let lag = match (li, le) {
                (Some(a), Some(e)) => Some((a - e) / 1_000_000),
                _ => None,
            };
            sources.push(json!({
                "source": source.value(i),
                "events": events.value(i),
                "last_event_us": le,
                "last_ingest_us": li,
                "ingest_lag_secs": lag,
                "staleness_secs": staleness,
            }));
        }
    }
    Ok(Json(json!({
        "window_hours": hours,
        "generated_us": now_us,
        "sources": sources,
    })))
}

/// GET /api/entities/search?q=&limit= — a bounded, read-only lookup across the
/// entity types the console can navigate to.
///
/// The command palette previously had no server-side search to call, so it
/// pulled whole collections into the browser and filtered them there — and, for
/// users and hosts, simply fabricated a destination from whatever had been typed.
/// This endpoint is the honest floor: it returns only entities that exist, it is
/// hard-bounded so a one-character query cannot become a table scan into the DOM,
/// and it never invents a row.
///
/// Read-only by construction: it lists what other read views already expose and
/// applies a substring filter. Authorization is the same as every other `/api`
/// read — the server decides, not the caller.
pub(super) async fn entities_search(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let q = p
        .get("q")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    // An empty query matches nothing. Returning "everything" for "" is how a
    // search endpoint becomes an accidental bulk export.
    if q.is_empty() {
        return Ok(Json(serde_json::json!({
            "query": "", "groups": [], "truncated": false,
        })));
    }
    let per_kind = entity_search_cap(p.get("limit").map(String::as_str));

    let hit = |hay: &str| entity_search_hit(hay, &q);
    let mut groups: Vec<serde_json::Value> = Vec::new();
    let mut truncated = false;

    // ---- investigations ----------------------------------------------------
    let cases = st.store.state.list_cases().map_err(oops)?;
    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut total = 0usize;
    for c in &cases {
        let v = serde_json::to_value(c).unwrap_or(serde_json::Value::Null);
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or_default();
        let title = v
            .get("trigger")
            .and_then(|t| t.get("rule_title").or_else(|| t.get("rule_id")))
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        let host = v
            .get("trigger")
            .and_then(|t| t.get("event"))
            .and_then(|e| e.get("host"))
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        if !hit(id) && !hit(title) && !hit(host) {
            continue;
        }
        total += 1;
        if items.len() < per_kind {
            items.push(serde_json::json!({
                "id": id, "label": title, "hint": host, "path": format!("/investigations/{id}"),
            }));
        }
    }
    if total > items.len() {
        truncated = true;
    }
    if total > 0 {
        groups.push(serde_json::json!({
            "kind": "investigation", "label": "Investigations",
            "total": total, "items": items,
        }));
    }

    // ---- policies ----------------------------------------------------------
    // Policies come from the same enforced set the /api/policies view exposes, so
    // search can never surface a policy that view would not show.
    let (all, _source) = super::policies::enforced_policies(&st);
    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut total = 0usize;
    for pol in &all {
        let v = serde_json::to_value(pol).unwrap_or(serde_json::Value::Null);
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or_default();
        let title = v.get("title").and_then(|x| x.as_str()).unwrap_or_default();
        if !hit(id) && !hit(title) {
            continue;
        }
        total += 1;
        if items.len() < per_kind {
            items.push(serde_json::json!({
                "id": id,
                "label": if title.is_empty() { id } else { title },
                "hint": id,
                "path": format!("/policies/{id}"),
            }));
        }
    }
    if total > items.len() {
        truncated = true;
    }
    if total > 0 {
        groups.push(serde_json::json!({
            "kind": "policy", "label": "Policies", "total": total, "items": items,
        }));
    }

    // ---- users and applications --------------------------------------------
    // Both come from the app-audit baseline snapshot, which is the same source
    // the Users and Applications views list from. Deliberately NOT joined against
    // the activity SQL those views also run: search needs names, and a per-query
    // warehouse scan is exactly the cost this endpoint exists to avoid.
    if let Some(aa) = &st.app_audit {
        use garmr_baseline::EntityKind;
        let store = aa.baseline_snapshot();

        for (kind, entity_kind, label, prefix) in [
            ("user", EntityKind::User, "Users", "/users"),
            (
                "application",
                EntityKind::Application,
                "Applications",
                "/applications",
            ),
        ] {
            let mut items: Vec<serde_json::Value> = Vec::new();
            let mut total = 0usize;
            for pf in store.profiles().filter(|pf| pf.entity.kind == entity_kind) {
                let name = pf.entity.id.as_str();
                if !hit(name) {
                    continue;
                }
                total += 1;
                if items.len() < per_kind {
                    items.push(serde_json::json!({
                        "id": name,
                        "label": name,
                        "hint": kind,
                        "path": format!("{prefix}/{}", urlencoding_min(name)),
                    }));
                }
            }
            if total > items.len() {
                truncated = true;
            }
            if total > 0 {
                groups.push(serde_json::json!({
                    "kind": kind, "label": label, "total": total, "items": items,
                }));
            }
        }

        // ---- resources ------------------------------------------------------
        // Catalogued data resources, matched on id and object pattern. Like the
        // two kinds above, this deliberately skips the access scan the Resources
        // view runs — that is a warehouse query per request, and search does not
        // need access counts to point at the right resource.
        let catalog = aa.catalog_snapshot();
        let mut items: Vec<serde_json::Value> = Vec::new();
        let mut total = 0usize;
        for e in catalog.entries.iter() {
            let Some(pattern) = e.object_pattern() else {
                continue;
            };
            let id = e.id.as_str();
            if !hit(id) && !hit(pattern) {
                continue;
            }
            total += 1;
            if items.len() < per_kind {
                let app = e
                    .object_summary()
                    .and_then(|sm| sm.application.clone())
                    .unwrap_or_default();
                items.push(serde_json::json!({
                    "id": id,
                    "label": if pattern.is_empty() { id } else { pattern },
                    "hint": if app.is_empty() { "resource".to_string() } else { app },
                    "path": format!("/resources/{}", urlencoding_min(id)),
                }));
            }
        }
        if total > items.len() {
            truncated = true;
        }
        if total > 0 {
            groups.push(serde_json::json!({
                "kind": "resource", "label": "Resources", "total": total, "items": items,
            }));
        }
    }

    Ok(Json(serde_json::json!({
        "query": q,
        "groups": groups,
        // Stated, never silent: the console says "N more not shown" from this.
        "truncated": truncated,
        "per_kind_cap": per_kind,
    })))
}

/// Hard ceiling on entity-search results per kind, independent of `?limit=`.
///
/// A palette shows a handful of hits. Letting the caller raise this would turn a
/// one-character query into a table scan served over HTTP.
pub(super) const MAX_ENTITY_HITS_PER_KIND: usize = 10;

/// The effective per-kind result cap for a caller-supplied `?limit=`.
///
/// Anything unparseable, zero, negative-shaped or absurd resolves to something
/// safe rather than to an error — a search box should not 400 because of a typo
/// in a query string it built itself.
pub(super) fn entity_search_cap(limit: Option<&str>) -> usize {
    limit
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(MAX_ENTITY_HITS_PER_KIND)
        .clamp(1, MAX_ENTITY_HITS_PER_KIND)
}

/// Does `haystack` match the already-lowercased, already-trimmed query?
///
/// An empty query matches NOTHING. Answering "" with everything is how a search
/// endpoint quietly becomes a bulk export of the case store.
pub(super) fn entity_search_hit(haystack: &str, query_lc: &str) -> bool {
    !query_lc.is_empty() && haystack.to_lowercase().contains(query_lc)
}

/// Percent-encode the path-unsafe characters in an entity id.
///
/// Entity ids here are hostnames, account names and application names, which can
/// legitimately contain `/`, spaces or `@`. A raw id in the path would resolve to
/// the wrong entity — or to nothing — when the console follows the link.
fn urlencoding_min(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod entity_search_tests {
    use super::*;

    #[test]
    fn an_empty_query_matches_nothing() {
        assert!(!entity_search_hit("anything at all", ""));
        assert!(!entity_search_hit("", ""));
    }

    #[test]
    fn matching_is_case_insensitive_substring() {
        assert!(entity_search_hit("PVE-Daemon", "pve"));
        assert!(entity_search_hit("root@pam", "@pam"));
        assert!(!entity_search_hit("abc", "xyz"));
    }

    #[test]
    fn the_caller_cannot_raise_the_ceiling() {
        assert_eq!(entity_search_cap(Some("9999")), MAX_ENTITY_HITS_PER_KIND);
        assert_eq!(entity_search_cap(Some("11")), MAX_ENTITY_HITS_PER_KIND);
        assert_eq!(entity_search_cap(None), MAX_ENTITY_HITS_PER_KIND);
    }

    #[test]
    fn a_smaller_limit_is_honoured() {
        assert_eq!(entity_search_cap(Some("3")), 3);
        assert_eq!(entity_search_cap(Some("1")), 1);
    }

    #[test]
    fn a_nonsense_limit_is_safe_not_an_error() {
        // Zero would return nothing; a negative or unparseable value must not
        // crash or 400 a search box.
        assert_eq!(entity_search_cap(Some("0")), 1);
        assert_eq!(entity_search_cap(Some("-5")), MAX_ENTITY_HITS_PER_KIND);
        assert_eq!(entity_search_cap(Some("abc")), MAX_ENTITY_HITS_PER_KIND);
        assert_eq!(entity_search_cap(Some("")), MAX_ENTITY_HITS_PER_KIND);
    }
}
