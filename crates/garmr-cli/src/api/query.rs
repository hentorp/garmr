// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The read-query surface: SQL (`/api/query`), cold-tier query, full-text
//! search, live tail, and the per-entity pivot pages (host/ip/user).

use super::*;

/// Escalate a bulk read to a `data.export` record.
///
/// A query returning thousands of rows is not a lookup — it is an extraction,
/// and "who exported the mailbox table" is a different audit question from
/// "who searched". The threshold is MAX_QUERY_ROWS (the response cap): a
/// caller who hit the cap took as much as one request can carry, which is the
/// honest definition of bulk on this surface. Emitted IN ADDITION to the
/// data.query record, not instead — the export record carries the row count,
/// the query record carries the digest, and a reviewer may arrive from either
/// direction.
pub(super) fn record_export_if_bulk(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
    rows_returned: usize,
    what: &str,
) {
    if rows_returned < super::MAX_QUERY_ROWS {
        return;
    }
    let who = super::auth::attributed_principal(st, headers);
    let (user, role) = match &who {
        Some(p) => (p.user.as_str(), Some(format!("{:?}", p.role))),
        None => ("unauthenticated", None),
    };
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::EXPORT, what)
            .actor(garmr_audit::ActorType::Human, user, role.as_deref())
            .auth_method("api_session")
            .classification(garmr_audit::DataClassification::Confidential)
            .outcome(garmr_audit::Outcome::Success)
            .reason(match super::client_marker(headers) {
                Some(client) => format!(
                    "bulk read: {rows_returned} rows (at the response cap); client: {client}"
                ),
                None => format!("bulk read: {rows_returned} rows (at the response cap)"),
            }),
    );
}

/// Record a read of the event corpus in the tamper-evident ledger.
///
/// The watchers must be watched: an analyst who can search every event is a
/// surveillance capability, and "who looked up whom" is the first question in an
/// insider-misuse investigation of the SOC itself.
///
/// Three properties matter more than completeness here:
///
/// - **Digest, never the query text.** Storing the raw query would move the
///   sensitive content INTO the ledger, so the audit trail would become the
///   surveillance layer it exists to constrain — the exact failure the
///   sensitive-search threat model names. A digest still proves *that* a given
///   query ran when it is presented later, which is what an investigation needs.
/// - **Best-effort, not fail-closed.** A read changes nothing, so refusing to
///   answer because the ledger is unavailable would deny an analyst their tool
///   without protecting anything. State changes stay fail-closed
///   (`ApiState::record_admin`); this is deliberately the weaker contract.
/// - **The real principal**, not a constant. An audit record naming "api" for
///   every caller answers "a search happened" but not "who ran it", which is the
///   only question worth asking.
pub(super) fn record_read(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
    action: &str,
    q: &str,
    what: &str,
) {
    let who = super::auth::attributed_principal(st, headers);
    let (user, role) = match &who {
        Some(p) => (p.user.as_str(), Some(format!("{:?}", p.role))),
        // The open loopback/no-token stance has no identity to attribute. Say so
        // explicitly rather than inventing one — a record claiming a user that
        // was never authenticated is worse than one that admits it cannot tell.
        None => ("unauthenticated", None),
    };
    let mut rec = garmr_audit::AuditRecord::new(action, what)
        .actor(garmr_audit::ActorType::Human, user, role.as_deref())
        .auth_method("api_session")
        .classification(garmr_audit::DataClassification::Confidential)
        .input_digest(garmr_audit::digest_of(q.as_bytes()))
        .outcome(garmr_audit::Outcome::Success);
    // Advisory client marker (X-Garmr-Client): lets a reviewer separate reads
    // arriving through the MCP surface from direct API use. See
    // `super::client_marker` for why lying about it gains nothing.
    if let Some(client) = super::client_marker(headers) {
        rec = rec.reason(format!("client: {client}"));
    }
    crate::audit::record_best_effort(rec);
}

/// The caller's data scope, from the extension `require_auth` inserted.
///
/// Absent means UNRESTRICTED, and that is correct rather than lax: the auth
/// layer is only mounted when tokens are configured (`GARMR_API_TOKEN`), so on
/// the open-loopback posture there is no middleware and therefore no extension.
/// Defaulting to "deny everything" there would break every local `curl` on a
/// deployment that has deliberately not enabled auth. Every path that DOES
/// authenticate inserts a scope explicitly — including `Unrestricted` for env
/// tokens and passkey sessions — so a restricted credential can never arrive
/// here without its restriction.
pub(super) fn scope_or_unrestricted(
    ext: Option<axum::Extension<garmr_core::DataScope>>,
) -> garmr_core::DataScope {
    ext.map(|axum::Extension(s)| s)
        .unwrap_or(garmr_core::DataScope::Unrestricted)
}

/// Record that a read was answered under a source restriction.
///
/// Emitted in addition to the normal read record, not instead of it. Two
/// records rather than one flag because the question a reviewer asks later is
/// "was this answer complete?" — and an absent stamp on an old record must not
/// be readable as "this was unrestricted" when it might simply predate the
/// feature. A separate action is unambiguous either way.
pub(super) fn record_scope_constrained(
    st: &ApiState,
    headers: &axum::http::HeaderMap,
    scope: &garmr_core::DataScope,
    what: &str,
) {
    let Some(allowed) = scope.allowed() else {
        return;
    };
    let who = super::auth::attributed_principal(st, headers);
    let (user, role) = match &who {
        Some(p) => (p.user.as_str(), Some(format!("{:?}", p.role))),
        None => ("unauthenticated", None),
    };
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::QUERY, what)
            .actor(garmr_audit::ActorType::Human, user, role.as_deref())
            .auth_method("api_session")
            .classification(garmr_audit::DataClassification::Confidential)
            .outcome(garmr_audit::Outcome::Success)
            // The allow-list itself, not the query: the sources are configuration
            // an admin chose, so recording them tells a reviewer exactly how much
            // of the corpus this answer could have covered.
            .reason(format!(
                "answered under a source restriction: [{}]",
                allowed.join(", ")
            )),
    );
}

/// Apply the caller's data scope to a SQL string, or pass it through unchanged
/// when unrestricted.
///
/// Unrestricted callers get BYTE-IDENTICAL SQL — the rewrite is not run at all,
/// so today's behaviour, plans and performance are untouched for every existing
/// deployment.
fn scoped_sql(scope: &garmr_core::DataScope, sql: &str) -> Result<String, (StatusCode, String)> {
    match scope.allowed() {
        None => Ok(sql.to_string()),
        Some(allowed) => garmr_store::sql_guard::constrain_sources(sql, allowed)
            .map_err(|e| (StatusCode::FORBIDDEN, e)),
    }
}

/// Parse `/api/search`'s optional time-range parameters into `[from_us, to_us)`
/// bounds (epoch micros). `?hours=N` is relative to `now_us`; `?from=&to=` are
/// absolute epoch-MILLIS, the units `/map`'s window parameters use. Unlike
/// `/map`, nonsense here — an unparseable number, `hours=0`, a lone or reversed
/// bound, mixing the two forms — is an error, never a silent fall-through to an
/// unbounded search: an ignored range is exactly the bug this parameter fixes.
fn parse_search_range(
    p: &HashMap<String, String>,
    now_us: i64,
) -> Result<(Option<i64>, Option<i64>), String> {
    const US_PER_HOUR: i64 = 3_600_000_000;
    let (hours, from, to) = (p.get("hours"), p.get("from"), p.get("to"));
    if hours.is_some() && (from.is_some() || to.is_some()) {
        return Err("pass either ?hours= or ?from=&to=, not both".into());
    }
    if let Some(h) = hours {
        let h: i64 = h
            .parse()
            .map_err(|_| format!("unreadable ?hours={h} — expected a whole number"))?;
        if h < 1 {
            return Err("?hours= must be at least 1".into());
        }
        if h > 24 * 365 {
            return Err("?hours= beyond a year — use ?from=&to= for windows that far back".into());
        }
        return Ok((Some(now_us.saturating_sub(h * US_PER_HOUR)), None));
    }
    match (from, to) {
        (None, None) => Ok((None, None)),
        (Some(f), Some(t)) => {
            let ms = |name: &str, s: &str| -> Result<i64, String> {
                s.parse::<i64>()
                    .ok()
                    // Micros must not overflow either — refuse, don't wrap.
                    .and_then(|v| v.checked_mul(1000))
                    .ok_or_else(|| format!("unreadable ?{name}={s} — expected epoch millis"))
            };
            let (f, t) = (ms("from", f)?, ms("to", t)?);
            if f >= t {
                return Err("empty range: ?from= must be before ?to=".into());
            }
            Ok((Some(f), Some(t)))
        }
        _ => Err("a range needs both ?from= and ?to=".into()),
    }
}

/// GET /api/search?q=<query>&limit=20 — full-text search over messages,
/// optionally bounded to a time window (`?hours=N`, or `?from=&to=` in epoch
/// millis) so the console's global range governs search like every other view.
pub(super) async fn search(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    scope_ext: Option<axum::Extension<garmr_core::DataScope>>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let scope = scope_or_unrestricted(scope_ext);
    let q = p.get("q").ok_or_else(|| bad("missing ?q="))?.clone();
    record_read(
        &st,
        &headers,
        garmr_audit::action::SEARCH_SENSITIVE,
        &q,
        "event_search",
    );
    // Clamp: a huge ?limit flows into Tantivy TopDocs and would attempt a
    // multi-GB allocation (process abort).
    let limit = p
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20usize)
        .min(MAX_SEARCH_LIMIT);
    let (from_us, to_us) =
        parse_search_range(&p, chrono::Utc::now().timestamp_micros()).map_err(bad)?;
    // An index from before ts_micros was FAST cannot range-filter. Surface the
    // migration instruction here with a real status — the generic error path
    // (`oops`) deliberately hides server error text from clients.
    if (from_us.is_some() || to_us.is_some()) && !st.store.search.supports_ts_range() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "this deployment's full-text index predates time-range filtering — run \
             `garmr reindex` (with `serve` stopped) to rebuild it, or search without a range"
                .to_string(),
        ));
    }
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
    // Owned before the closure so the scope crosses into spawn_blocking.
    let allowed: Option<Vec<String>> = scope.allowed().map(|s| s.to_vec());
    let search_fut = async move {
        let permit = permits.acquire_owned().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("search limiter closed: {e}"),
            )
        })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            match allowed {
                // Unrestricted: the same call as before, so an existing
                // deployment's plan and results are untouched.
                None => store.search.search_in_range(&q, limit, from_us, to_us),
                Some(sources) => store.search.search_scoped_in_range(
                    &q,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    limit,
                    from_us,
                    to_us,
                    Some(&sources),
                ),
            }
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
    record_scope_constrained(&st, &headers, &scope, "event_search");
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
    headers: axum::http::HeaderMap,
    scope_ext: Option<axum::Extension<garmr_core::DataScope>>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let scope = scope_or_unrestricted(scope_ext);
    let sql = p.get("sql").ok_or_else(|| bad("missing ?sql="))?;
    // Audited BEFORE the read-only guard runs: a rejected statement is still an
    // attempt worth having in the ledger, and an attacker probing for a write
    // path is exactly who a later investigation wants to see.
    record_read(&st, &headers, garmr_audit::action::QUERY, sql, "event_sql");
    // Same AST-level read-only guard the agent's query tool uses.
    garmr_agent::reject_non_readonly(sql).map_err(bad)?;
    // Then the data scope. Order matters: the read-only guard rejects writes,
    // and only a query that is already known to be a read is worth rewriting.
    let sql = &scoped_sql(&scope, sql)?;
    record_scope_constrained(&st, &headers, &scope, "event_sql");
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
    record_export_if_bulk(&st, &headers, rows.len(), "event_sql");
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
    headers: axum::http::HeaderMap,
    scope_ext: Option<axum::Extension<garmr_core::DataScope>>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let scope = scope_or_unrestricted(scope_ext);
    let sql = p.get("sql").ok_or_else(|| bad("missing ?sql="))?;
    garmr_agent::reject_non_readonly(sql).map_err(bad)?;
    // The cold lane registers raw archives in a throwaway DataFusion session, so
    // it never passed through any hot-path guard — this rewrite has to happen
    // BEFORE `ColdQuery::new` or the scope is simply absent from the cold tier.
    // That gap was the bypass this milestone exists to close.
    let sql = &scoped_sql(&scope, sql)?;
    record_scope_constrained(&st, &headers, &scope, "event_sql_cold");
    record_read(
        &st,
        &headers,
        garmr_audit::action::QUERY,
        sql,
        "event_sql_cold",
    );
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
    record_export_if_bulk(&st, &headers, rows.len(), "event_sql_cold");
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
    headers: axum::http::HeaderMap,
    scope_ext: Option<axum::Extension<garmr_core::DataScope>>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let scope = scope_or_unrestricted(scope_ext);
    let sql = p.get("sql").ok_or_else(|| bad("missing ?sql="))?;
    garmr_agent::reject_non_readonly(sql).map_err(bad)?;
    // Same as `query_cold`: constrain before the archives are registered.
    let sql = &scoped_sql(&scope, sql)?;
    record_scope_constrained(&st, &headers, &scope, "event_sql_cold");
    record_read(
        &st,
        &headers,
        garmr_audit::action::QUERY,
        sql,
        "event_sql_cold",
    );
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
    record_export_if_bulk(&st, &headers, rows.len(), "event_sql_cold");
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

#[cfg(test)]
mod read_audit_tests {
    use garmr_audit::{action, digest_of, ActorType, AuditRecord, DataClassification};

    /// The record shape `record_read` builds. Asserted directly because the
    /// property that matters is what the record CANNOT contain, and that is
    /// visible in the serialized form.
    fn sample(q: &str) -> AuditRecord {
        AuditRecord::new(action::SEARCH_SENSITIVE, "event_search")
            .actor(ActorType::Human, "alice", Some("Analyst"))
            .auth_method("api_session")
            .classification(DataClassification::Confidential)
            .input_digest(digest_of(q.as_bytes()))
    }

    #[test]
    fn the_query_text_never_reaches_the_ledger() {
        // The sensitive-search threat model's own failure mode: if the audit
        // record carried the query, the ledger would become the surveillance
        // layer it exists to constrain. A digest still proves a given query ran
        // when it is presented later, which is what an investigation needs.
        let secret = "mailbox:ceo@example.com AND salary";
        let rendered = serde_json::to_string(&sample(secret)).unwrap();
        assert!(
            !rendered.contains("ceo@example.com") && !rendered.contains("salary"),
            "raw query text leaked into the audit record: {rendered}"
        );
        assert!(rendered.contains("alice"), "the actor must be recorded");
    }

    #[test]
    fn the_same_query_digests_identically_and_a_different_one_does_not() {
        // Presenting a query later and matching it against the ledger is the
        // whole point of storing a digest instead of nothing at all.
        let a = digest_of(b"host:pve failed password");
        let b = digest_of(b"host:pve failed password");
        let c = digest_of(b"host:njord failed password");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_US: i64 = 1_755_000_000_000_000;

    fn params(kv: &[(&str, &str)]) -> HashMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_range_params_leave_the_search_unbounded() {
        assert_eq!(parse_search_range(&params(&[]), NOW_US), Ok((None, None)));
        // Unrelated params (q, limit) don't trip the range parser.
        assert_eq!(
            parse_search_range(&params(&[("q", "pvefw"), ("limit", "20")]), NOW_US),
            Ok((None, None))
        );
    }

    #[test]
    fn hours_becomes_a_lower_bound_relative_to_now() {
        assert_eq!(
            parse_search_range(&params(&[("hours", "24")]), NOW_US),
            Ok((Some(NOW_US - 24 * 3_600_000_000), None))
        );
    }

    #[test]
    fn from_to_are_epoch_millis_converted_to_micros() {
        assert_eq!(
            parse_search_range(&params(&[("from", "1000"), ("to", "2000")]), NOW_US),
            Ok((Some(1_000_000), Some(2_000_000)))
        );
    }

    // Fail-closed: a range the server can't honor must be a 400, never a silent
    // fall-through to an unbounded search — that IS the bug the range fixes.
    #[test]
    fn nonsense_ranges_are_rejected_not_ignored() {
        for (kv, why) in [
            (vec![("hours", "abc")], "unparseable hours"),
            (vec![("hours", "0")], "zero hours"),
            (vec![("hours", "-5")], "negative hours"),
            (vec![("hours", "9000")], "hours beyond a year"),
            (
                vec![("hours", "24"), ("from", "1"), ("to", "2")],
                "mixed forms",
            ),
            (vec![("from", "1000")], "lone from"),
            (vec![("to", "2000")], "lone to"),
            (vec![("from", "x"), ("to", "2000")], "unparseable from"),
            (vec![("from", "1000"), ("to", "y")], "unparseable to"),
            (vec![("from", "2000"), ("to", "1000")], "reversed"),
            (vec![("from", "2000"), ("to", "2000")], "empty window"),
            (
                vec![
                    ("from", "9223372036854775807"),
                    ("to", "9223372036854775807"),
                ],
                "millis that overflow micros",
            ),
        ] {
            assert!(
                parse_search_range(&params(&kv), NOW_US).is_err(),
                "{why} must be rejected: {kv:?}"
            );
        }
    }

    #[test]
    fn range_errors_name_the_offending_parameter() {
        let e = parse_search_range(&params(&[("hours", "abc")]), NOW_US).unwrap_err();
        assert!(e.contains("hours"), "unhelpful: {e}");
        let e = parse_search_range(&params(&[("from", "x"), ("to", "1")]), NOW_US).unwrap_err();
        assert!(e.contains("from"), "unhelpful: {e}");
    }
}
