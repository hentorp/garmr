// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Semantic search: the embedding model + in-serve vector index, its
//! background reindex loop, and the `/api/semantic` handler. Entirely behind
//! the `semantic` feature; absent from a lean build.

use super::*;

#[cfg(feature = "semantic")]
const SEMANTIC_MAX: usize = 100_000;
/// Reindex window (how far back distinct messages are embedded).
#[cfg(feature = "semantic")]
const SEMANTIC_WINDOW_HOURS: u64 = 168;

/// Index cap, config-driven via `GARMR_SEMANTIC_MAX` (default [`SEMANTIC_MAX`]).
#[cfg(feature = "semantic")]
fn semantic_max() -> usize {
    std::env::var("GARMR_SEMANTIC_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(SEMANTIC_MAX)
}

/// Reindex window hours, config-driven via `GARMR_SEMANTIC_WINDOW_HOURS`
/// (default [`SEMANTIC_WINDOW_HOURS`]).
#[cfg(feature = "semantic")]
fn semantic_window_hours() -> u64 {
    std::env::var("GARMR_SEMANTIC_WINDOW_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(SEMANTIC_WINDOW_HOURS)
}
/// How often the background task rebuilds the index off the read lane.
#[cfg(feature = "semantic")]
const SEMANTIC_REINDEX_SECS: u64 = 900;

/// A live [`garmr_query::SemanticSearch`] backend for the hybrid executor: embed
/// the query and scan the in-serve vector index. The executor runs on the async
/// lane and candle is CPU-blocking, so `search` uses `block_in_place` (valid on
/// serve's multi-thread runtime) to yield the worker while it embeds + scans —
/// the same off-lane discipline `/api/hsearch` gets via `spawn_blocking`. Used
/// by `ask` (natural-language search) so its semantic clause actually runs.
#[cfg(feature = "semantic")]
pub(super) struct LiveSemantic {
    embedder: std::sync::Arc<garmr_embed::Embedder>,
    index: std::sync::Arc<tokio::sync::RwLock<garmr_embed::VectorStore>>,
}

#[cfg(feature = "semantic")]
impl garmr_query::SemanticSearch for LiveSemantic {
    fn search(&self, nl: &str, k: usize) -> Vec<garmr_query::SemanticHit> {
        tokio::task::block_in_place(|| {
            let Ok(qv) = self.embedder.embed(nl) else {
                return Vec::new();
            };
            let idx = self.index.blocking_read();
            idx.search(&qv, k)
                .into_iter()
                .map(|(score, r)| garmr_query::SemanticHit {
                    ts_micros: r.ts_micros,
                    host: r.host,
                    service: r.service,
                    message: r.message,
                    score,
                })
                .collect()
        })
    }
}

/// The live semantic backend, if the daemon has a loaded model + index.
#[cfg(feature = "semantic")]
pub(super) fn live_semantic(st: &ApiState) -> Option<LiveSemantic> {
    let h = st.semantic.as_ref()?;
    Some(LiveSemantic {
        embedder: h.embedder.clone(),
        index: h.index.clone(),
    })
}

/// A shared semantic backend for the triage/hunt agent's `hybrid_search` tool
/// (Phase 11): a `LiveSemantic` view over the SAME handle the ask HTTP path uses,
/// so the embedding model is loaded exactly once. Type-erased so garmr-agent
/// stays free of the embedding toolchain.
#[cfg(feature = "semantic")]
pub(super) fn agent_semantic(
    h: &SemanticHandle,
) -> std::sync::Arc<dyn garmr_query::SemanticSearch> {
    std::sync::Arc::new(LiveSemantic {
        embedder: h.embedder.clone(),
        index: h.index.clone(),
    })
}

#[cfg(feature = "semantic")]
fn semantic_store_path(cfg: &Config) -> std::path::PathBuf {
    std::env::var_os("GARMR_SEMANTIC_STORE")
        .map(Into::into)
        .unwrap_or_else(|| {
            cfg.store
                .warehouse_dir
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("semantic-vectors.bin")
        })
}

/// Build the live semantic handle when the model dir is configured: load the
/// model, open the existing index file, and spawn a background rebuild task
/// (which queries the CONCURRENT read lane — never the ingest hot path). Returns
/// `None` (semantic search simply off) if the model can't be loaded.
#[cfg(feature = "semantic")]
pub(super) fn build_semantic(store: &Store, cfg: &Config) -> Option<SemanticHandle> {
    let dir = std::env::var_os("GARMR_EMBED_MODEL")?;
    // Phase 15 supply chain: VERIFY the model against an optional pin before
    // loading, so a swapped/tampered model can never load silently in an
    // air-gapped SOC. A digest MISMATCH disables semantic search (fail-closed —
    // better no semantic than a poisoned embedder), never loads the bad model.
    let pin = std::env::var("GARMR_EMBED_MODEL_DIGEST")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let (embedder, digest) = match garmr_embed::Embedder::load_verified(
        std::path::Path::new(&dir),
        pin.as_deref(),
    ) {
        Ok((e, d)) => (std::sync::Arc::new(e), d),
        Err(e) => {
            tracing::error!(error = %e, "semantic: model verify/load failed — semantic search DISABLED");
            return None;
        }
    };
    // Provenance: record the loaded model's digest to the audit ledger, and log
    // it so an operator can pin it. Best-effort (never blocks serving).
    if pin.is_some() {
        tracing::info!(digest = %digest, "semantic: embedding model verified against pin");
    } else {
        tracing::warn!(digest = %digest, "semantic: embedding model loaded UNPINNED — set GARMR_EMBED_MODEL_DIGEST to this digest to pin it");
    }
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::MODEL_REGISTER, "embedding_model")
            .actor(garmr_audit::ActorType::System, "serve", None)
            .object_id(digest.clone())
            .reason(if pin.is_some() {
                "embedding model loaded (pinned + verified)"
            } else {
                "embedding model loaded (unpinned)"
            }),
    );
    let path = semantic_store_path(cfg);
    let index = garmr_embed::VectorStore::open(&path, semantic_max(), &digest).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "semantic: index file unreadable — starting empty");
        garmr_embed::VectorStore::new(&path, semantic_max(), &digest)
    });
    tracing::info!(dir = ?dir, indexed = index.len(), "semantic search enabled");
    let handle = SemanticHandle {
        embedder,
        index: std::sync::Arc::new(tokio::sync::RwLock::new(index)),
    };
    tokio::spawn(semantic_reindex_loop(
        store.clone(),
        cfg.clone(),
        handle.clone(),
    ));
    Some(handle)
}

/// `AND source NOT IN ('a','b')` (empty when nothing is excluded). Sources are
/// operator config; single-quotes are escaped defensively all the same. Mirrors
/// the graph builder's clause so semantic search skips the same firehose.
#[cfg(feature = "semantic")]
fn exclude_clause(exclude: &[String]) -> String {
    if exclude.is_empty() {
        return String::new();
    }
    let list = exclude
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    format!(" AND source NOT IN ({list})")
}

/// Periodically rebuild the index from recent DISTINCT event messages, off the
/// concurrent read lane. Rebuild-and-swap (not incremental) — simple and
/// correct at home-lab scale; a failed cycle is logged and retried.
#[cfg(feature = "semantic")]
async fn semantic_reindex_loop(store: Store, cfg: Config, handle: SemanticHandle) {
    let path = semantic_store_path(&cfg);
    // Skip the same firehose sources full-text search excludes (e.g. the kunai
    // eBPF stream): their lines are near-unique per PID/arg, so they bloat the
    // embed set to the cap with rows worthless for semantic recall AND defeat
    // the reuse cache below. Static config — built once.
    let excl = exclude_clause(&cfg.store.fulltext_exclude_sources);
    loop {
        // Rebuild FIRST (so a fresh deploy's index is current from the start,
        // not stale-from-file or empty), then wait.
        match semantic_rebuild(&store, &path, &excl, &handle).await {
            Ok(n) => tracing::debug!(indexed = n, "semantic index rebuilt"),
            Err(e) => tracing::warn!(error = %e, "semantic reindex failed"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(SEMANTIC_REINDEX_SECS)).await;
    }
}

#[cfg(feature = "semantic")]
async fn semantic_rebuild(
    store: &Store,
    path: &std::path::Path,
    excl: &str,
    handle: &SemanticHandle,
) -> anyhow::Result<usize> {
    // ORDER BY the group's newest timestamp DESC before LIMIT so the cap keeps
    // the NEWEST distinct messages deterministically (a bare LIMIT with no ORDER
    // BY leaves which rows survive up to the scan order — the cap must be "newest
    // wins", not arbitrary).
    let (win, max) = (semantic_window_hours(), semantic_max());
    let sql = format!(
        "SELECT max(event_ts) AS ts, host, service, message FROM events \
         WHERE event_ts >= now() - INTERVAL '{win} hours' \
           AND log_type NOT IN ('anomaly', 'risk', 'baseline'){excl} \
         GROUP BY host, service, message ORDER BY ts DESC LIMIT {max}"
    );
    let batches = store.events.sql(sql).await?; // async, concurrent read lane
    let embedder = handle.embedder.clone();
    let path = path.to_path_buf();
    // Carry forward vectors we already have: a message's embedding depends only
    // on its text, so seed a message→vec cache from the current index and embed
    // ONLY messages missing from it. Turns each rebuild from "embed the whole
    // window" into "embed the delta" — and makes a restart's first rebuild
    // (which reads the persisted index) essentially free. Read guard is dropped
    // before the blocking task starts.
    let (cache, model_digest): (std::collections::HashMap<String, Vec<f32>>, String) = {
        let idx = handle.index.read().await;
        (
            idx.records()
                .map(|r| (r.message.clone(), r.vec.clone()))
                .collect(),
            idx.model_digest().to_string(),
        )
    };
    // Embedding is CPU-heavy (a BERT forward per message); run it — and the
    // flush — on the BLOCKING pool so it never stalls an async worker (garmr
    // deploys to 1-2 vCPU VMs where a pegged worker would starve ingest).
    let fresh = tokio::task::spawn_blocking(move || -> anyhow::Result<garmr_embed::VectorStore> {
        use skade::arrow_array::{Array, StringArray, TimestampMicrosecondArray};
        // 1. Extract the rows (order preserved: newest-first from the query).
        let mut rows: Vec<(i64, String, String, String)> = Vec::new();
        for b in &batches {
            let ts = b
                .column(0)
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>();
            let host = b.column(1).as_any().downcast_ref::<StringArray>();
            let svc = b.column(2).as_any().downcast_ref::<StringArray>();
            let msg = b.column(3).as_any().downcast_ref::<StringArray>();
            let (Some(ts), Some(host), Some(svc), Some(msg)) = (ts, host, svc, msg) else {
                continue;
            };
            for i in 0..b.num_rows() {
                if !msg.is_valid(i) {
                    continue;
                }
                rows.push((
                    if ts.is_valid(i) { ts.value(i) } else { 0 },
                    if host.is_valid(i) {
                        host.value(i).into()
                    } else {
                        String::new()
                    },
                    if svc.is_valid(i) {
                        svc.value(i).into()
                    } else {
                        String::new()
                    },
                    msg.value(i).to_string(),
                ));
            }
        }

        // 2. Embed the DELTA in BATCHES: distinct messages absent from the reuse
        //    cache go through one padded forward per chunk (a per-message forward
        //    would dominate a large (re)index). Messages already in the cache
        //    carry their vector forward for free.
        const EMBED_BATCH: usize = 64;
        let mut seen = std::collections::HashSet::new();
        let to_embed: Vec<String> = rows
            .iter()
            .map(|r| &r.3)
            .filter(|m| !cache.contains_key(*m) && seen.insert((*m).clone()))
            .cloned()
            .collect();
        let mut fresh_vecs: std::collections::HashMap<String, Vec<f32>> =
            std::collections::HashMap::with_capacity(to_embed.len());
        for chunk in to_embed.chunks(EMBED_BATCH) {
            let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
            // Prefer the batched forward; if a chunk errors (e.g. an OOM on a
            // pathological batch), degrade to the proven per-message path rather
            // than failing the whole rebuild.
            match embedder.embed_batch(&refs) {
                Ok(embs) => {
                    for (m, v) in chunk.iter().zip(embs) {
                        fresh_vecs.insert(m.clone(), v);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, n = chunk.len(), "semantic: batch embed failed — per-message fallback");
                    for m in chunk {
                        if let Ok(v) = embedder.embed(m) {
                            fresh_vecs.insert(m.clone(), v);
                        }
                    }
                }
            }
        }

        // 3. Assemble the fresh store (cache hit or freshly-embedded vector),
        //    stamped with the same model digest so a restart can trust the file.
        let mut fresh = garmr_embed::VectorStore::new(&path, semantic_max(), &model_digest);
        for (ts_micros, host, service, message) in rows {
            let Some(vec) = cache
                .get(&message)
                .cloned()
                .or_else(|| fresh_vecs.get(&message).cloned())
            else {
                continue; // unreachable: every message is cached or embedded
            };
            fresh.push(garmr_embed::Record {
                ts_micros,
                host,
                service,
                message,
                vec,
            });
        }
        fresh.flush().map_err(|e| anyhow::anyhow!("{e}"))?;
        // Warm the ANN graph HERE, off the query lock — the swap below then
        // hands queries an already-built index (no first-query build stall).
        fresh.warm();
        Ok(fresh)
    })
    .await??;
    let n = fresh.len();
    // Only swap in a NON-empty rebuild: during a quiet period (no events in the
    // window) don't clobber a good warm-start / prior index with an empty one.
    if n > 0 {
        *handle.index.write().await = fresh; // brief write guard, just the swap
    } else {
        tracing::debug!("semantic: no events in window — keeping existing index");
    }
    Ok(n)
}

/// GET /api/semantic?q=&limit= — nearest events by embedding cosine. 503 when
/// semantic search isn't enabled at runtime (no GARMR_EMBED_MODEL).
#[cfg(feature = "semantic")]
pub(super) async fn semantic(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let q = p.get("q").ok_or_else(|| bad("missing ?q="))?;
    let limit = p
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20usize)
        .min(200);
    let Some(sem) = &st.semantic else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "semantic search not configured".into(),
        ));
    };
    // Embedding + the HNSW scan (+ exact rerank) are CPU-bound; run them on the blocking
    // pool (blocking_read the index there) so they don't stall an async worker.
    let (embedder, index, q) = (sem.embedder.clone(), sem.index.clone(), q.clone());
    let (hits, indexed) = tokio::task::spawn_blocking(move || {
        let qv = embedder.embed(&q).map_err(oops)?;
        let idx = index.blocking_read();
        Ok::<_, (StatusCode, String)>((idx.search(&qv, limit), idx.len()))
    })
    .await
    .map_err(oops)??;
    let rows: Vec<Value> = hits
        .into_iter()
        .map(|(score, r)| {
            json!({
                "score": score,
                "ts_micros": r.ts_micros,
                "host": r.host,
                "service": r.service,
                "message": r.message,
            })
        })
        .collect();
    Ok(Json(json!({ "hits": rows, "indexed": indexed })))
}

/// GET /api/semantic/status — the semantic index freshness metric (DoD 15): record
/// count, cap/window, the stamped model digest, and the **index lag** (seconds
/// between now and the newest indexed event), so an operator can see whether
/// meaning-search is keeping up. Reports `enabled:false` when semantic is off.
#[cfg(feature = "semantic")]
pub(super) async fn semantic_status(State(st): State<ApiState>) -> ApiResult {
    let Some(sem) = &st.semantic else {
        return Ok(Json(json!({ "enabled": false })));
    };
    let index = sem.index.clone();
    let (records, newest_ts, digest) = tokio::task::spawn_blocking(move || {
        let idx = index.blocking_read();
        (idx.len(), idx.newest_ts(), idx.model_digest().to_string())
    })
    .await
    .map_err(oops)?;
    let now_us = chrono::Utc::now().timestamp_micros();
    let lag_secs = newest_ts.map(|t| (now_us - t).max(0) / 1_000_000);
    Ok(Json(json!({
        "enabled": true,
        "records": records,
        "cap": semantic_max(),
        "window_hours": semantic_window_hours(),
        "reindex_secs": SEMANTIC_REINDEX_SECS,
        "model_digest": digest,
        "newest_ts_micros": newest_ts,
        "lag_secs": lag_secs,
    })))
}