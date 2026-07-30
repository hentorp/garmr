// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The read-query surface: SQL (`/api/query`), cold-tier query, full-text
//! search, live tail, and the per-entity pivot pages (host/ip/user).

use super::*;

/// GET /api/search?q=<query>&limit=20 — full-text search over messages.
pub(super) async fn search(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let q = p.get("q").ok_or_else(|| bad("missing ?q="))?.clone();
    // Clamp: a huge ?limit flows into Tantivy TopDocs and would attempt a
    // multi-GB allocation (process abort).
    let limit = p
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20usize)
        .min(MAX_SEARCH_LIMIT);
    // Tantivy `search` is synchronous + CPU-bound: a high-document-frequency term
    // (e.g. a k8s label matching millions of postings) scores the whole posting
    // list to fill the TopDocs heap. Run it on the blocking pool so it can't
    // stall an async worker (which serves the console's concurrent polling), and
    // bound it with the same timeout every other read endpoint uses so the
    // request can't hang the caller in "searching…" indefinitely. Move a
    // semaphore permit into the closure: timing out detaches `spawn_blocking`,
    // so the work (not merely the HTTP request) must retain the permit until it
    // actually finishes. This bounds detached searches as well as live ones.
    let store = st.store.clone();
    let permits = st.search_permits.clone();
    let search_fut = async move {
        let permit = permits.acquire_owned().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("search limiter closed: {e}"),
            )
        })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.search.search(&q, limit)
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("search task: {e}"),
            )
        })?
        .map_err(oops)
    };
    let hits = match tokio::time::timeout(
        std::time::Duration::from_secs(QUERY_TIMEOUT_SECS),
        search_fut,
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                format!("search exceeded {QUERY_TIMEOUT_SECS}s — narrow the query"),
            ))
        }
    };
    let rows: Vec<Value> = hits
        .into_iter()
        .map(|h| {
            json!({
                "score": h.score,
                "ts_micros": h.ts_micros,
                "host": h.host,
                "service": h.service,
                "severity": h.severity,
                "message": h.message,
            })
        })
        .collect();
    Ok(Json(json!({ "hits": rows })))
}

/// GET /api/query?sql=<SELECT…> — read-only SQL over the events lakehouse.
pub(super) async fn query(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let sql = p.get("sql").ok_or_else(|| bad("missing ?sql="))?;
    // Same AST-level read-only guard the agent's query tool uses.
    garmr_agent::reject_non_readonly(sql).map_err(bad)?;
    // Bound the wait so a runaway query can't hang the caller. (Reads run off
    // the append actor, so this never stalls ingest either way.)
    let fut = st.store.events.sql(sql.clone());
    let batches =
        match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), fut).await {
            Ok(r) => r.map_err(oops)?,
            Err(_) => {
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    format!("query exceeded {QUERY_TIMEOUT_SECS}s"),
                ))
            }
        };
    let (rows, truncated) = batches_to_json(&batches, MAX_QUERY_ROWS);
    Ok(Json(json!({ "rows": rows, "truncated": truncated })))
}

/// GET /api/query/cold?sql=<SELECT…>&from=<rfc3339>&to=<rfc3339> — read-only SQL
/// over the COLD tier: sealed archives thawed on demand (the Splunk
/// frozen→thawed half). Recent data lives in the hot `/api/query`; this reaches
/// history that retention has aged out of the hot table — so bounding
/// `retention_days` keeps the hot table (and compaction cost) fixed without
/// losing queryability. Pass `from`/`to` to bound the thaw; an unbounded cold
/// query over years of archives is refused (it would duplicate the tier to
/// scratch). `archives` in the response is how many overlapping archives were
/// thawed (0 = the range hit no cold data, distinct from a 0-row match).
pub(super) async fn query_cold(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let sql = p.get("sql").ok_or_else(|| bad("missing ?sql="))?;
    garmr_agent::reject_non_readonly(sql).map_err(bad)?;
    let from_us = p
        .get("from")
        .map(|s| crate::parse_rfc3339(s).map(|d| d.timestamp_micros()))
        .transpose()
        .map_err(bad)?;
    let to_us = p
        .get("to")
        .map(|s| crate::parse_rfc3339(s).map(|d| d.timestamp_micros()))
        .transpose()
        .map_err(bad)?;
    let cq = garmr_retention::ColdQuery::new(st.store.clone(), &st.cfg);
    // Cold queries thaw + decompress archives, so allow a longer wait than hot.
    let fut = cq.query(sql, from_us, to_us);
    let res = match tokio::time::timeout(
        std::time::Duration::from_secs(QUERY_TIMEOUT_SECS.saturating_mul(4)),
        fut,
    )
    .await
    {
        Ok(r) => r.map_err(oops)?,
        Err(_) => {
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                "cold query timed out — narrow it with from/to".to_string(),
            ))
        }
    };
    let (rows, truncated) = batches_to_json(&res.batches, MAX_QUERY_ROWS);
    Ok(Json(json!({
        "rows": rows,
        "truncated": truncated,
        "archives": res.archives,
    })))
}

/// GET /api/cold-query?sql=<SELECT…>&from=<t>&to=<t> — read-only SQL over the
/// cold tier (thaws the archives overlapping `[from, to)` first). `from`/`to`
/// are REQUIRED here, unlike the CLI: an unbounded thaw duplicates archives
/// onto scratch disk, and a shared daemon must not let one request do that
/// without naming a range. Bounds accept RFC3339 or a bare `YYYY-MM-DD` (which
/// covers the whole named day on either end).
pub(super) async fn cold_query(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let sql = p.get("sql").ok_or_else(|| bad("missing ?sql="))?;
    garmr_agent::reject_non_readonly(sql).map_err(bad)?;
    let from = p
        .get("from")
        .ok_or_else(|| bad("missing ?from= (cold queries must be bounded)"))?;
    let to = p
        .get("to")
        .ok_or_else(|| bad("missing ?to= (cold queries must be bounded)"))?;
    let from_us = crate::parse_time(from, crate::Bound::Start).map_err(bad)?;
    let to_us = crate::parse_time(to, crate::Bound::End).map_err(bad)?;

    let cq = garmr_retention::ColdQuery::new(st.store.clone(), &st.cfg);
    let fut = cq.query(sql, Some(from_us), Some(to_us));
    let res =
        match tokio::time::timeout(std::time::Duration::from_secs(COLD_QUERY_TIMEOUT_SECS), fut)
            .await
        {
            Ok(r) => r.map_err(oops)?,
            Err(_) => {
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    format!("cold query exceeded {COLD_QUERY_TIMEOUT_SECS}s"),
                ))
            }
        };
    let (rows, truncated) = batches_to_json(&res.batches, MAX_QUERY_ROWS);
    Ok(Json(
        json!({ "archives": res.archives, "rows": rows, "truncated": truncated }),
    ))
}

/// GET /api/tail?limit=40 — most recent events.
pub(super) async fn tail(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let limit = p
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(40u32)
        .min(MAX_QUERY_ROWS as u32);
    // Bound the tail to a recent window so the scan PRUNES to the newest data
    // files (event_ts row-group/file skipping) instead of decompressing the whole
    // table for a TopK — an unbounded `ORDER BY event_ts DESC LIMIT` was a
    // full-table scan that, polled on the console's 5 s sweep, pegged the box.
    // 24 h is far more than the newest `limit` events on a live feed; a genuinely
    // idle deployment simply shows its (few) most recent events.
    let sql = format!(
        "SELECT event_ts, host, service, severity, message FROM events \
         WHERE event_ts >= now() - INTERVAL '1 hour' \
         ORDER BY event_ts DESC LIMIT {limit}"
    );
    // Same bound as /api/query: a tail is a scan + TopK on a growing
    // table, and every reader must finish inside the compaction GC grace.
    let fut = st.store.events.sql(sql);
    let batches =
        match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), fut).await {
            Ok(r) => r.map_err(oops)?,
            Err(_) => {
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    format!("tail exceeded {QUERY_TIMEOUT_SECS}s"),
                ))
            }
        };
    let (rows, _) = batches_to_json(&batches, MAX_QUERY_ROWS);
    Ok(Json(json!({ "rows": rows })))
}

/// Shared timeout for the entity assemblers (several aggregate scans each).
const ENTITY_TIMEOUT_SECS: u64 = 60;

pub(super) async fn entity_page<F, Fut>(f: F) -> ApiResult
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = garmr_core::Result<serde_json::Value>>,
{
    match tokio::time::timeout(std::time::Duration::from_secs(ENTITY_TIMEOUT_SECS), f()).await {
        Ok(Ok(v)) => Ok(Json(v)),
        Ok(Err(e)) => Err(oops(e)),
        Err(_) => Err((
            StatusCode::REQUEST_TIMEOUT,
            format!("entity exceeded {ENTITY_TIMEOUT_SECS}s"),
        )),
    }
}

/// GET /api/entity/host/:name — the host page (volume, services, cases).
pub(super) async fn entity_host(State(st): State<ApiState>, Path(name): Path<String>) -> ApiResult {
    entity_page(|| async move { garmr_agent::entity::host_page(&st.store, &name).await }).await
}

/// GET /api/entity/ip/:name — the IP page (sightings, hosts, cases).
pub(super) async fn entity_ip(State(st): State<ApiState>, Path(name): Path<String>) -> ApiResult {
    // Validate here so a malformed address is the caller's 400, not a 500.
    if name.parse::<std::net::IpAddr>().is_err() {
        return Err(bad(format!("invalid IP: {name}")));
    }
    entity_page(|| async move { garmr_agent::entity::ip_page(&st.store, &name).await }).await
}

/// GET /api/entity/user/:name — the user page (activity, hosts, cases).
pub(super) async fn entity_user(State(st): State<ApiState>, Path(name): Path<String>) -> ApiResult {
    entity_page(|| async move { garmr_agent::entity::user_page(&st.store, &name).await }).await
}

/// GET /api/entity/staff/:name — the caseworker page: what a db_user looked up
/// (registerkontroll — "what did X look up?").
pub(super) async fn entity_staff(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> ApiResult {
    entity_page(|| async move { garmr_agent::entity::staff_page(&st.store, &name).await }).await
}

/// GET /api/entity/person/:name — the person page: who looked up this person
/// (registerkontroll — "who looked up Y?").
pub(super) async fn entity_person(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> ApiResult {
    entity_page(|| async move { garmr_agent::entity::person_page(&st.store, &name).await }).await
}
