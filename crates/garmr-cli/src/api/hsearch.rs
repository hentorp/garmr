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
pub(super) async fn hsearch(State(st): State<ApiState>, Json(q): Json<HybridQuery>) -> ApiResult {
    Ok(Json(execute_hybrid(&st, q).await?))
}

/// Run a typed `HybridQuery` through the deterministic executor (semantic clause
/// embedded off the async lane first) and return the fused result as JSON. The
/// one place hybrid queries execute — shared by `/api/hsearch` and the LLM-free
/// `/api/reproduce`, so reproduction is byte-for-byte the same read path.
pub(super) async fn execute_hybrid(
    st: &ApiState,
    mut q: HybridQuery,
) -> Result<Value, (StatusCode, String)> {
    // Validate up front so a malformed query is the caller's 400, not a 500 —
    // the same convention as /api/query and the entity routes. (The executor
    // re-validates the clamped query harmlessly.)
    q.validate().map_err(bad)?;
    let sem = semantic_hits(st, &q).await.map(Precomputed);
    let res = Executor::run(
        &st.store,
        &q,
        sem.as_ref().map(|a| a as &dyn SemanticSearch),
    )
    .await
    .map_err(hsearch_exec_err)?;
    serde_json::to_value(res).map_err(oops)
}

/// GET /api/reproduce?query_id= — rerun a previously-planned `ask` query
/// **deterministically, with NO model call**: load the stored `HybridQuery` IR
/// and execute it through the exact same read path as `/api/hsearch`, under the
/// same authorization. This is how a past answer's retrieval is reproduced from
/// the audit trail (the query_id is returned by `/api/ask`). 404 if the plan was
/// never stored (or has been evicted).
pub(super) async fn reproduce(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
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
    let mut v = execute_hybrid(&st, q).await?;
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
    let (embedder, index, query, k) = (
        handle.embedder.clone(),
        handle.index.clone(),
        clause.query.clone(),
        q.fusion.per_signal_k,
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
