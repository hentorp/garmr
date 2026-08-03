// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The ingest servers: the native canonical HTTP endpoint, syslog UDP/TCP
//! listeners, and (opt-in) the Loki push endpoint.
//!
//! Every path decodes to a batch of [`Event`]s and forwards it on a channel —
//! `garmr serve` owns the receiver and fans each batch to the store and the
//! detector. Ingest never touches storage directly, so it stays testable and
//! the back-pressure of a full channel is the only coupling.
//!
//! The HTTP paths acknowledge **after persistence**: the success status is sent
//! only once the pipeline reports the batch durably appended, so a crash can't
//! silently drop batches that were already ACKed — the sender retries anything
//! unacknowledged, giving at-least-once delivery. Syslog is fire-and-forget by
//! nature (`ack: None`).
//!
//! The native endpoint (`/ingest/v1/events`) is the vendor-neutral primary path.
//! The Loki push endpoint is compiled only under the `loki-compat` feature, for
//! environments still fanning in through Grafana Alloy's `loki.write`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use garmr_core::{Error, Event, Result};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};

#[cfg(not(feature = "loki-compat"))]
use crate::native;
use crate::syslog;
#[cfg(feature = "loki-compat")]
use crate::{loki, native};

/// One ingested batch on its way to the pipeline. `ack` (when present) is
/// resolved after the batch is persisted — `Ok` maps to HTTP 204, `Err` to 500
/// so the shipper retries.
pub struct IngestBatch {
    pub events: Vec<Event>,
    pub ack: Option<oneshot::Sender<std::result::Result<(), String>>>,
    /// The AUTHENTICATED collector id that delivered this batch (Phase 12), or
    /// `None` when unauthenticated (default-off).
    pub collector_id: Option<String>,
}

impl IngestBatch {
    /// A batch with no delivery acknowledgement (syslog, tests).
    pub fn fire_and_forget(events: Vec<Event>) -> Self {
        Self {
            events,
            ack: None,
            collector_id: None,
        }
    }
}

/// The channel batches of ingested events are pushed onto.
pub type EventSink = mpsc::Sender<IngestBatch>;

/// A denied/anomalous ingest event to record (kept small so garmr-ingest needs
/// no garmr-audit dep; the CLI maps it onto the ledger).
pub struct IngestAudit {
    pub action: &'static str,
    pub collector: Option<String>,
    pub reason: String,
}

/// Observes a per-collector batch sequence AFTER the batch is durably persisted
/// (Phase 12 delivery observability). Implemented by the CLI against the state
/// store, so garmr-ingest stays store- and audit-agnostic. Only ever called with
/// an AUTHENTICATED collector id (FIX#4: no sequence tracking for unauthenticated
/// ingest, and the seq/epoch headers are ignored without a trusted collector).
pub trait IngestSeqObserver: Send + Sync {
    fn observe(&self, collector_id: &str, epoch: u64, seq: u64);
}

/// The audit callback + its rate limiters, so an attacker flooding bad-token POSTs
/// can't force one synchronous ledger append per request (FIX#5). Fires at most
/// once per window per class with an aggregated count.
///
/// Two DISTINCT denial classes are kept separate, each with its own limiter and
/// action, so a source-binding violation (a VALID collector asserting a forbidden
/// source — exactly the attack Phase 12 defends against) is never mislabeled as
/// "unauthenticated" and can neither be merged with nor suppressed by an
/// unauthenticated bad-token flood sharing one counter.
#[derive(Clone)]
pub struct IngestAuditor {
    sink: Arc<dyn Fn(IngestAudit) + Send + Sync>,
    auth: Arc<DenyLimiter>,
    source: Arc<DenyLimiter>,
    /// The most recent (collector_id, source) that a binding violation named — the
    /// representative example carried on the aggregated source-denied line.
    last_source: Arc<std::sync::Mutex<(String, String)>>,
}

struct DenyLimiter {
    window_secs: u64,
    last_flush: std::sync::atomic::AtomicU64,
    suppressed: std::sync::atomic::AtomicU64,
}

impl DenyLimiter {
    fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            last_flush: std::sync::atomic::AtomicU64::new(0),
            suppressed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Count this event; return `Some(aggregated_count)` on the call that crosses
    /// the window boundary (and should emit), `None` otherwise.
    fn bump(&self) -> Option<u64> {
        use std::sync::atomic::Ordering::Relaxed;
        self.suppressed.fetch_add(1, Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_flush.load(Relaxed);
        if now >= last + self.window_secs
            && self
                .last_flush
                .compare_exchange(last, now, Relaxed, Relaxed)
                .is_ok()
        {
            Some(self.suppressed.swap(0, Relaxed))
        } else {
            None
        }
    }
}

impl IngestAuditor {
    pub fn new(sink: Arc<dyn Fn(IngestAudit) + Send + Sync>) -> Self {
        Self {
            sink,
            auth: Arc::new(DenyLimiter::new(60)),
            source: Arc::new(DenyLimiter::new(60)),
            last_source: Arc::new(std::sync::Mutex::new((String::new(), String::new()))),
        }
    }

    /// A no-op auditor: accepts every record and drops it.
    ///
    /// Used by `tests/native_auth_e2e.rs`, which drives the real `run_ingest`
    /// server over a socket to prove the collector-auth contract and has no
    /// ledger to write to. Do not delete as dead code — the consumer lives in
    /// the public tree's test suite.
    pub fn noop() -> Self {
        Self::new(Arc::new(|_| {}))
    }

    /// An UNAUTHENTICATED / unrecognized-token rejection (no collector resolved).
    fn record_denied(&self, collector: Option<String>) {
        if let Some(count) = self.auth.bump() {
            (self.sink)(IngestAudit {
                action: "ingest.auth_denied",
                collector,
                reason: format!("{count} unauthenticated ingest request(s) in the last window"),
            });
        }
    }

    /// A SOURCE-BINDING violation: an AUTHENTICATED collector asserted a source
    /// outside its allowlist. Its own action + counter (never folded into the
    /// unauthenticated bucket); the reason names the collector and an example
    /// forbidden source (neither is a secret) but never the token.
    fn record_source_denied(&self, collector_id: &str, source: &str) {
        if let Ok(mut last) = self.last_source.lock() {
            *last = (collector_id.to_string(), source.to_string());
        }
        if let Some(count) = self.source.bump() {
            let (cid, src) = self
                .last_source
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            (self.sink)(IngestAudit {
                action: "ingest.source_denied",
                collector: Some(cid.clone()),
                reason: format!(
                    "{count} forbidden-source assertion(s) in the last window \
                     (e.g. collector '{cid}' attempted source '{src}')"
                ),
            });
        }
    }
}

#[derive(Clone)]
struct IngestState {
    sink: EventSink,
    default_environment: Arc<String>,
    registry: Arc<garmr_core::CollectorRegistry>,
    auditor: IngestAuditor,
    seq: Option<Arc<dyn IngestSeqObserver>>,
}

/// Extract a `Bearer <token>` from the Authorization header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim())
}

/// Parse the Phase-12 sequence headers into `(epoch, seq)`. Returns `None` unless
/// `X-Garmr-Seq` is a valid `u64`; `X-Garmr-Epoch` defaults to 0 when absent
/// (a collector that never restarts uses a single epoch).
fn seq_headers(headers: &HeaderMap) -> Option<(u64, u64)> {
    let seq = headers
        .get("x-garmr-seq")?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    let epoch = headers
        .get("x-garmr-epoch")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    Some((epoch, seq))
}

/// Run the native canonical ingest receiver until the process ends.
///
/// Serves `POST /ingest/v1/events` — a JSON array of canonical events, or, when
/// the request is `application/x-ndjson`, newline-delimited JSON. Acknowledges
/// only after the batch is durably persisted (`200` with `{"accepted": n}`),
/// returning `5xx` so the sender retries. This is garmr's vendor-neutral primary
/// ingest path; no Loki, protobuf, or snappy is involved.
///
/// When `registry` is non-empty (Phase 12 binding on), every POST must present a
/// valid `Bearer` collector token; the authenticated collector id is stamped on
/// the batch and a collector may only assert its bound `source`s. An EMPTY
/// registry is default-off — byte-identical to before.
pub async fn run_ingest(
    bind: &str,
    sink: EventSink,
    default_environment: String,
    registry: Arc<garmr_core::CollectorRegistry>,
    auditor: IngestAuditor,
    seq: Option<Arc<dyn IngestSeqObserver>>,
) -> Result<()> {
    let state = IngestState {
        sink,
        default_environment: Arc::new(default_environment),
        registry,
        auditor,
        seq,
    };
    let app = Router::new()
        // Cap the native ingest body at MAX_BODY_BYTES (overrides axum's ~2 MiB
        // default) so an oversized payload is rejected at the transport layer,
        // before it is buffered/parsed. `decode_events` re-checks the same bound
        // as a transport-independent backstop.
        .route(
            "/ingest/v1/events",
            post(ingest_events).layer(DefaultBodyLimit::max(native::MAX_BODY_BYTES)),
        )
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/ready", get(|| async { "ready" }))
        .with_state(state);
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| Error::Ingest(e.to_string()))?;
    tracing::info!(%bind, "native ingest receiver listening (/ingest/v1/events)");
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Ingest(e.to_string()))
}

async fn ingest_events(State(st): State<IngestState>, headers: HeaderMap, body: Bytes) -> Response {
    // FIX#5: authenticate BEFORE decoding — an unauthenticated request is rejected
    // without parsing (no parser-error leak) and its audit is rate-limited.
    let collector = if st.registry.is_empty() {
        None // default-off: today's unauthenticated path, byte-identical.
    } else {
        match bearer(&headers).and_then(|t| st.registry.resolve(t).cloned()) {
            Some(c) => Some(c),
            None => {
                st.auditor.record_denied(None);
                return (
                    StatusCode::UNAUTHORIZED,
                    "collector authentication required",
                )
                    .into_response();
            }
        }
    };

    let ndjson = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("ndjson"))
        .unwrap_or(false);

    let events = match native::decode_events(&body, ndjson, &st.default_environment) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "rejected native ingest");
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };
    if events.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    // Source binding: a collector may only assert its bound `source`s. A forbidden
    // source fails the whole batch closed (a forged source never lands).
    let collector_id = if let Some(c) = &collector {
        if let Some(bad) = events.iter().find(|e| !c.may_assert(&e.source)) {
            st.auditor.record_source_denied(&c.id, &bad.source);
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "collector '{}' may not assert source '{}'",
                    c.id, bad.source
                ),
            )
                .into_response();
        }
        Some(c.id.clone())
    } else {
        None
    };

    // Phase 12 sequence mark: only for an AUTHENTICATED collector (FIX#4) that
    // presents `X-Garmr-Seq`. Observed AFTER durable persistence below, so a
    // NACK+retry reads as a Replay, never a false Gap.
    let seq_mark = collector_id
        .as_ref()
        .and_then(|cid| seq_headers(&headers).map(|(epoch, seq)| (cid.clone(), epoch, seq)));

    // ACK after persistence: wait for the pipeline to report the batch durably
    // appended before returning 200. Any failure (pipeline gone, append error)
    // returns 5xx so the sender retries — at-least-once delivery.
    let accepted = events.len();
    let (ack, done) = oneshot::channel();
    if st
        .sink
        .send(IngestBatch {
            events,
            ack: Some(ack),
            collector_id,
        })
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let persisted = done.await;
    if let Ok(Ok(())) = &persisted {
        // Durable: record the sequence observation (gap/replay detection).
        if let (Some(obs), Some((cid, epoch, seq))) = (&st.seq, &seq_mark) {
            obs.observe(cid, *epoch, *seq);
        }
    }
    match persisted {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(serde_json::json!({ "accepted": accepted })),
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "native ingest not persisted");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The channel batches of ingested events are pushed onto.
#[cfg(feature = "loki-compat")]
#[derive(Clone)]
struct LokiState {
    sink: EventSink,
    default_environment: Arc<String>,
}

/// Run the Loki push receiver until the process ends. Compiled only under the
/// `loki-compat` feature — Loki is not part of the default build.
#[cfg(feature = "loki-compat")]
pub async fn run_loki(bind: &str, sink: EventSink, default_environment: String) -> Result<()> {
    let state = LokiState {
        sink,
        default_environment: Arc::new(default_environment),
    };
    let app = Router::new()
        .route("/loki/api/v1/push", post(push))
        .route("/ready", get(|| async { "ready" }))
        .with_state(state);
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| Error::Ingest(e.to_string()))?;
    tracing::info!(%bind, "loki push receiver listening");
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Ingest(e.to_string()))
}

#[cfg(feature = "loki-compat")]
async fn push(State(st): State<LokiState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let is_json = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("json"))
        .unwrap_or(false);

    let decoded = if is_json {
        loki::decode_json(&body, &st.default_environment)
    } else {
        loki::decode_protobuf(&body, &st.default_environment)
    };

    match decoded {
        Ok(events) if events.is_empty() => StatusCode::NO_CONTENT,
        Ok(events) => {
            // ACK after persistence: wait for the pipeline to report the batch
            // durably appended before returning 204. Any failure (pipeline
            // gone, append error) returns 5xx so the shipper retries — the
            // at-least-once contract of the Loki push protocol.
            let (ack, done) = oneshot::channel();
            if st
                .sink
                .send(IngestBatch {
                    events,
                    ack: Some(ack),
                    // Phase 12 auth is on the native endpoint; the legacy loki path
                    // is unattributed.
                    collector_id: None,
                })
                .await
                .is_err()
            {
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            match done.await {
                Ok(Ok(())) => StatusCode::NO_CONTENT,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "loki push not persisted");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                Err(_) => StatusCode::SERVICE_UNAVAILABLE,
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "rejected loki push");
            StatusCode::BAD_REQUEST
        }
    }
}

/// Run a syslog UDP listener.
pub async fn run_syslog_udp(
    bind: &str,
    sink: EventSink,
    default_environment: String,
) -> Result<()> {
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| Error::Ingest(e.to_string()))?;
    tracing::info!(%bind, "syslog UDP listener bound");
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, _peer): (usize, SocketAddr) = sock
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::Ingest(e.to_string()))?;
        let text = String::from_utf8_lossy(&buf[..n]);
        let events: Vec<Event> = text
            .lines()
            .map(|l| syslog::parse_line(l, &default_environment))
            .collect();
        if !events.is_empty()
            && sink
                .send(IngestBatch::fire_and_forget(events))
                .await
                .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// Run a syslog TCP listener (newline-delimited, RFC6587 octet-counting not
/// handled — line framing covers the common case).
pub async fn run_syslog_tcp(
    bind: &str,
    sink: EventSink,
    default_environment: String,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| Error::Ingest(e.to_string()))?;
    tracing::info!(%bind, "syslog TCP listener bound");
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|e| Error::Ingest(e.to_string()))?;
        let sink = sink.clone();
        let env = default_environment.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let ev = syslog::parse_line(&line, &env);
                if sink
                    .send(IngestBatch::fire_and_forget(vec![ev]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
}
