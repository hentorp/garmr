// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! POST /api/hsearch — the Phase 6 hybrid-search endpoint. Read-only and
//! follower-safe (spends no budget, writes nothing), so it is mounted in the
//! always-on read section. The body is the typed `HybridQuery` IR.
//!
//! The semantic clause (when the `semantic` feature is built AND a model is
//! configured) is embedded + scanned on the BLOCKING pool BEFORE the executor
//! runs, so the ~30ms BERT forward never stalls an async worker on a 1-2 vCPU
//! host; the precomputed hits are then handed to the executor through a tiny
//! `SemanticSearch` adapter. Without the feature/model the clause is honestly
//! reported unavailable.
//!
//! `filter.time` bounds every leg (see `garmr_query::Executor`), so the console's
//! global range governs Advanced search as it governs Simple search. A window on
//! a full-text index built before `ts_micros` was FAST cannot be served: that is
//! a 503 naming `garmr reindex`, mirroring `/api/search` — never a silently
//! unbounded search.

use garmr_query::{Executor, HybridQuery, SemanticHit, SemanticSearch};

use super::*;

/// A `SemanticSearch` impl over hits already computed off the async lane — the
/// executor's `search(nl, k)` just returns them (the query was already the right
/// one), so the CPU-heavy embed happens in `spawn_blocking`, not inline.
struct Precomputed(Vec<SemanticHit>);

impl SemanticSearch for Precomputed {
    fn search(&self, _nl: &str, k: usize) -> Vec<SemanticHit> {
        self.0.iter().take(k).cloned().collect()
    }
}

/// POST /api/hsearch — run a hybrid query, return the fused, provenance-carrying
/// result.
pub(super) async fn hsearch(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    scope_ext: Option<axum::Extension<garmr_core::DataScope>>,
    Json(q): Json<HybridQuery>,
) -> ApiResult {
    let scope = super::query::scope_or_unrestricted(scope_ext);
    // Audited here rather than inside `execute_hybrid`: that function is shared
    // with /api/reproduce and the agent's own tool path, which carry different
    // actors. Auditing the shared function would stamp every one of them as an
    // interactive human read.
    //
    // The digest is over the serialized query, so "who ran this exact hybrid
    // search" is answerable without the ledger holding the search terms.
    let digest_input = serde_json::to_string(&q).unwrap_or_default();
    super::query::record_read(
        &st,
        &headers,
        garmr_audit::action::QUERY,
        &digest_input,
        "event_hybrid",
    );
    super::query::record_scope_constrained(&st, &headers, &scope, "event_hybrid");
    Ok(Json(execute_hybrid(&st, q, &scope).await?))
}

/// Run a typed `HybridQuery` through the deterministic executor (semantic clause
/// embedded off the async lane first) and return the fused result as JSON. The
/// one place hybrid queries execute — shared by `/api/hsearch` and the LLM-free
/// `/api/reproduce`, so reproduction is byte-for-byte the same read path.
pub(super) async fn execute_hybrid(
    st: &ApiState,
    mut q: HybridQuery,
    scope: &garmr_core::DataScope,
) -> Result<Value, (StatusCode, String)> {
    // A source the caller asked for but may not read is a 403, never a quietly
    // narrowed result set. Silently dropping it would answer a question the
    // caller did not ask: they would read "no hits in infra" as evidence about
    // infra, when in fact infra was never searched.
    if !scope.covers_all(&q.filter.source) {
        return Err((
            StatusCode::FORBIDDEN,
            "this credential may not read every source named in filter.source".to_string(),
        ));
    }
    // Validate up front so a malformed query is the caller's 400, not a 500 —
    // the same convention as /api/query and the entity routes. (The executor
    // re-validates the clamped query harmlessly.)
    q.validate().map_err(bad)?;
    // An index from before ts_micros was FAST cannot bound the full-text leg.
    // Surface the migration instruction here with a real status — the generic
    // error path (`oops`) deliberately hides server error text from clients.
    if needs_ts_range_migration(&q, st.store.search.supports_ts_range()) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "this deployment's full-text index predates time-range filtering — run \
             `garmr reindex` (with `serve` stopped) to rebuild it, or search without a range"
                .to_string(),
        ));
    }
    let sem = semantic_hits(st, &q).await.map(Precomputed);
    let res = Executor::run_scoped(
        &st.store,
        &q,
        sem.as_ref().map(|a| a as &dyn SemanticSearch),
        scope.allowed(),
    )
    .await
    .map_err(hsearch_exec_err)?;
    serde_json::to_value(res).map_err(oops)
}

/// Would running `q` ask the full-text index for a time-bounded search it cannot
/// serve? Only the text leg pushes the window into Tantivy — a query with a
/// window but no text clause bounds its structured and semantic legs without the
/// index's help, and must keep working on a pre-upgrade deployment.
fn needs_ts_range_migration(q: &HybridQuery, supports_ts_range: bool) -> bool {
    q.text.is_some() && !q.filter.time.is_empty() && !supports_ts_range
}

/// GET /api/reproduce?query_id= — rerun a previously-planned `ask` query
/// **deterministically, with NO model call**: load the stored `HybridQuery` IR
/// and execute it through the exact same read path as `/api/hsearch`, under the
/// same authorization. This is how a past answer's retrieval is reproduced from
/// the audit trail (the query_id is returned by `/api/ask`). 404 if the plan was
/// never stored (or has been evicted).
pub(super) async fn reproduce(
    State(st): State<ApiState>,
    scope_ext: Option<axum::Extension<garmr_core::DataScope>>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    // The scope checked is the CURRENT caller's, not whoever planned the query.
    // A stored plan may name sources this caller may not read — replaying it
    // must then 403, or reproduce becomes a way to launder a wider credential's
    // reach through a saved plan id.
    let scope = super::query::scope_or_unrestricted(scope_ext);
    let id = p
        .get("query_id")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("missing ?query_id="))?;
    let bytes = st
        .store
        .state
        .get_query_plan(id)
        .map_err(oops)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("no stored query plan for {id:?}"),
            )
        })?;
    let q: HybridQuery = serde_json::from_slice(&bytes)
        .map_err(|e| bad(format!("stored plan is unparseable: {e}")))?;
    let mut v = execute_hybrid(&st, q, &scope).await?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("reproduced_query_id".into(), serde_json::json!(id));
        obj.insert("llm_used".into(), serde_json::json!(false));
    }
    Ok(Json(v))
}

/// Map an executor error to a status: a query timeout is a retryable 408 (as
/// /api/query and /api/tail return), everything else an opaque 500.
fn hsearch_exec_err(e: garmr_core::Error) -> (StatusCode, String) {
    if e.to_string().contains("timed out") {
        (
            StatusCode::REQUEST_TIMEOUT,
            "hybrid query timed out — narrow the filter or time window".to_string(),
        )
    } else {
        oops(e)
    }
}

/// Embed the semantic clause and scan the in-serve vector index off the async
/// lane. `None` when there is no semantic clause, no model, or the feature is off.
#[cfg(feature = "semantic")]
async fn semantic_hits(st: &ApiState, q: &HybridQuery) -> Option<Vec<SemanticHit>> {
    let clause = q.semantic.as_ref()?;
    let handle = st.semantic.as_ref()?;
    // `semantic_fetch_k` is the executor's own fetch width (wider when a window
    // is set, since the backend ranks by meaning and knows nothing of the
    // window) — read it here so the precomputed hits are never narrower than
    // what the executor is about to ask `Precomputed::search` for.
    let (embedder, index, query, k) = (
        handle.embedder.clone(),
        handle.index.clone(),
        clause.query.clone(),
        q.semantic_fetch_k(),
    );
    tokio::task::spawn_blocking(move || {
        let qv = embedder.embed(&query).ok()?;
        let idx = index.blocking_read();
        Some(
            idx.search(&qv, k)
                .into_iter()
                .map(|(score, r)| SemanticHit {
                    ts_micros: r.ts_micros,
                    host: r.host,
                    service: r.service,
                    source: r.source,
                    message: r.message,
                    score,
                })
                .collect::<Vec<_>>(),
        )
    })
    .await
    .ok()
    .flatten()
}

#[cfg(not(feature = "semantic"))]
async fn semantic_hits(_st: &ApiState, _q: &HybridQuery) -> Option<Vec<SemanticHit>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_query::{SemanticClause, TextClause};

    fn q(text: bool, hours: Option<f64>) -> HybridQuery {
        let mut q = HybridQuery {
            text: text.then(|| TextClause {
                query: "failed password".into(),
            }),
            ..Default::default()
        };
        q.filter.time.last_hours = hours;
        q
    }

    #[test]
    fn a_windowed_text_query_needs_a_migrated_index() {
        // The console's Advanced mode on a pre-upgrade deployment: refuse with
        // the migration instruction rather than search the wrong window.
        assert!(needs_ts_range_migration(&q(true, Some(24.0)), false));
        // A migrated index serves it.
        assert!(!needs_ts_range_migration(&q(true, Some(24.0)), true));
        // An absolute window counts the same as a relative one.
        let mut abs = q(true, None);
        abs.filter.time.from_micros = Some(1_754_179_200_000_000);
        abs.filter.time.to_micros = Some(1_754_265_600_000_000);
        assert!(needs_ts_range_migration(&abs, false));
    }

    #[test]
    fn queries_that_never_ask_tantivy_for_a_window_still_run() {
        // No window: the pre-upgrade index searches unbounded, as it always has.
        assert!(!needs_ts_range_migration(&q(true, None), false));
        // A window but no text clause: the structured and semantic legs bound
        // themselves without the full-text index, so this must not be refused.
        assert!(!needs_ts_range_migration(&q(false, Some(24.0)), false));
        let mut sem = q(false, Some(24.0));
        sem.semantic = Some(SemanticClause {
            query: "brute force".into(),
        });
        assert!(!needs_ts_range_migration(&sem, false));
    }

    #[test]
    fn the_precompute_fetches_what_the_executor_will_ask_for() {
        // `semantic_hits` precomputes `semantic_fetch_k()` hits and hands them
        // to `Precomputed`, whose `search(k)` the executor calls with that same
        // width — a narrower precompute would silently cap the semantic leg.
        let mut windowed = q(false, Some(24.0));
        windowed.semantic = Some(SemanticClause {
            query: "brute force".into(),
        });
        let mut unbounded = windowed.clone();
        unbounded.filter.time.last_hours = None;
        assert!(
            windowed.semantic_fetch_k() > unbounded.semantic_fetch_k(),
            "a windowed query must over-fetch before filtering to the window"
        );
        let hits = vec![
            SemanticHit {
                ts_micros: 1,
                host: "h".into(),
                service: "svc".into(),
                source: "journald".into(),
                message: "m".into(),
                score: 0.5,
            };
            windowed.semantic_fetch_k()
        ];
        assert_eq!(
            Precomputed(hits)
                .search("brute force", windowed.semantic_fetch_k())
                .len(),
            windowed.semantic_fetch_k(),
            "the adapter hands back every precomputed hit"
        );
    }
}
