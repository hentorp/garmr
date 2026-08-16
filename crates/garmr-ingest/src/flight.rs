// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Arrow-Flight columnar ingest receiver (opt-in `flight` feature).
//!
//! A tonic gRPC [`FlightService`] whose `do_put` decodes the incoming Arrow-IPC
//! `FlightData` stream into `RecordBatch`es and swallows them straight into the
//! lakehouse via [`EventsHandle::append_batch`](garmr_store::EventsHandle) — **no
//! JSON parse, no owned `Event`**. The sender (`flightbeat`) ships the 9 v1
//! payload columns (`schema::wire_schema`); the receiver computes the v2
//! provenance server-side and dedups on `event_id`, so a Flight-delivered event
//! and the same event via NDJSON share one identity. This is the transport in
//! front of the columnar swallow the bench arms measured at ~2.6× the JSON path.
//!
//! Only `do_put` is implemented; the other `FlightService` methods return
//! `unimplemented` — garm is a **sink** (log shippers push to it), not a Flight
//! query engine.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Once};
use std::time::Duration;

use arrow_array::{Array, RecordBatch};
use arrow_flight::decode::FlightRecordBatchStream;
use arrow_flight::error::FlightError;
use arrow_flight::flight_service_server::{FlightService, FlightServiceServer};
use arrow_flight::{
    Action, ActionType, Criteria, Empty, FlightData, FlightDescriptor, FlightInfo,
    HandshakeRequest, HandshakeResponse, PollInfo, PutResult, SchemaResult, Ticket,
};
use futures::{Stream, StreamExt, TryStreamExt};
use garmr_core::SharedCollectors;
use garmr_store::EventsHandle;
use tonic::{Request, Response, Status, Streaming};

/// Enrich a decoded wire batch: for every row whose `fields` column is NULL or
/// empty (`{}`), derive the high-value fields from the `message` and fill them in
/// — the columnar analogue of the native path's "sender ships a raw line ⇒
/// [`fields::extract`](crate::fields::extract) derives src_ip/user/port". Rows
/// that already carry structured `fields` pass through untouched (the columnar
/// swallow stays alloc-free for structured senders). Because extraction and its
/// canonical `BTreeMap` serialization are identical to the native path, a raw line
/// via Flight and the same line via NDJSON get the SAME `event_id` — detection
/// fires on Flight-ingested raw logs exactly as it does on native ones.
///
/// Columns 7 (`message`) and 8 (`fields`) are the v1 wire positions; a batch whose
/// shape doesn't match is returned unchanged (the swallow then rejects it loudly).
fn enrich_empty_fields(batch: RecordBatch) -> RecordBatch {
    use arrow_array::StringArray;

    let n = batch.num_rows();
    if batch.num_columns() <= 8 {
        return batch;
    }
    let (Some(msg), Some(fields)) = (
        batch.column(7).as_any().downcast_ref::<StringArray>(),
        batch.column(8).as_any().downcast_ref::<StringArray>(),
    ) else {
        return batch;
    };

    let mut any = false;
    let enriched: StringArray = (0..n)
        .map(|i| {
            let f = if fields.is_null(i) {
                ""
            } else {
                fields.value(i)
            };
            if f.is_empty() || f == "{}" {
                any = true;
                let derived = crate::fields::extract(msg.value(i));
                Some(serde_json::to_string(&derived).unwrap_or_else(|_| "{}".to_string()))
            } else {
                Some(f.to_string())
            }
        })
        .collect();
    if !any {
        return batch; // every row already had structured fields — no work, no realloc
    }

    let mut cols = batch.columns().to_vec();
    cols[8] = std::sync::Arc::new(enriched);
    RecordBatch::try_new(batch.schema(), cols).unwrap_or(batch)
}

/// Legacy gRPC metadata key carrying a collector identity. It is never trusted:
/// authenticated identity is derived exclusively from the bearer token.
pub const COLLECTOR_HEADER: &str = "garmr-collector-id";

// ---- Resource limits for the do_put receiver (Arrow Flight is EXPERIMENTAL) ----
//
// A `do_put` stream is an untrusted, unbounded push from a network peer: it can
// send arbitrarily wide `RecordBatch`es and arbitrarily many of them. Without
// caps a single stream can OOM the receiver or pin it in the swallow loop
// forever. These caps bound one batch's width, a stream's batch count, and a
// stream's cumulative rows. Each has an env-var override so an operator can tune
// (or a test can shrink) the limit without touching shared config structs.

/// Maximum rows in a single decoded `RecordBatch`. A batch wider than this is
/// rejected before any enrich/append work is done. Override: `GARMR_FLIGHT_MAX_ROWS_PER_BATCH`.
pub const MAX_FLIGHT_ROWS_PER_BATCH: usize = 1_000_000;

/// Maximum number of `RecordBatch`es accepted from a single `do_put` stream
/// before it is aborted. Override: `GARMR_FLIGHT_MAX_BATCHES_PER_STREAM`.
pub const MAX_FLIGHT_BATCHES_PER_STREAM: usize = 10_000;

/// Maximum cumulative rows accepted from a single `do_put` stream before it is
/// aborted. Override: `GARMR_FLIGHT_MAX_ROWS_PER_STREAM`.
pub const MAX_FLIGHT_ROWS_PER_STREAM: usize = 50_000_000;

/// How long the receiver waits for the next `FlightData` frame before aborting a
/// stalled stream. A finite bound keeps a wedged/slow peer from pinning the
/// swallow task indefinitely; on expiry `do_put` returns `deadline_exceeded`
/// (the stream ends — no deadlock). Override: `GARMR_FLIGHT_BATCH_RECV_TIMEOUT_SECS`.
pub const FLIGHT_BATCH_RECV_TIMEOUT: Duration = Duration::from_secs(60);

/// Read a `usize` limit from `key`, falling back to `default` when the var is
/// unset or unparseable. Overrides are read per-stream (cheap) so an operator
/// change takes effect on the next connection without a restart.
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn max_rows_per_batch() -> usize {
    env_usize("GARMR_FLIGHT_MAX_ROWS_PER_BATCH", MAX_FLIGHT_ROWS_PER_BATCH)
}

fn max_batches_per_stream() -> usize {
    env_usize(
        "GARMR_FLIGHT_MAX_BATCHES_PER_STREAM",
        MAX_FLIGHT_BATCHES_PER_STREAM,
    )
}

fn max_rows_per_stream() -> usize {
    env_usize(
        "GARMR_FLIGHT_MAX_ROWS_PER_STREAM",
        MAX_FLIGHT_ROWS_PER_STREAM,
    )
}

fn batch_recv_timeout() -> Duration {
    match std::env::var("GARMR_FLIGHT_BATCH_RECV_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(secs) => Duration::from_secs(secs),
        None => FLIGHT_BATCH_RECV_TIMEOUT,
    }
}

/// Enforce the per-batch and per-stream caps for one decoded batch. `batches_seen`
/// and `rows_seen` are the running totals *including* the batch under test. An
/// oversized single batch or an over-budget stream is rejected with
/// `resource_exhausted`; the caller aborts the stream on `Err`. Pure and
/// synchronous so the policy is unit-testable without a socket or store.
fn check_flight_limits(
    batch_rows: usize,
    batches_seen: usize,
    rows_seen: usize,
    max_rows_batch: usize,
    max_batches: usize,
    max_rows_stream: usize,
) -> Result<(), Status> {
    if batch_rows > max_rows_batch {
        return Err(Status::resource_exhausted(format!(
            "flight batch has {batch_rows} rows, exceeds per-batch cap {max_rows_batch}"
        )));
    }
    if batches_seen > max_batches {
        return Err(Status::resource_exhausted(format!(
            "flight stream exceeded per-stream batch cap {max_batches}"
        )));
    }
    if rows_seen > max_rows_stream {
        return Err(Status::resource_exhausted(format!(
            "flight stream exceeded per-stream row cap {max_rows_stream}"
        )));
    }
    Ok(())
}

/// Emit the "Arrow Flight ingest is EXPERIMENTAL" banner exactly once per process,
/// no matter how many receivers start or streams arrive. Guarded by a [`Once`] so
/// the loud warning does not repeat per-connection.
fn warn_experimental_once() {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            "Arrow Flight ingest is EXPERIMENTAL and unauthenticated-by-default; \
             keep it DISABLED unless you have explicitly enabled and firewalled it. \
             do_put enforces per-batch ({} rows), per-stream ({} batches / {} rows) \
             and receive-timeout ({:?}) limits.",
            MAX_FLIGHT_ROWS_PER_BATCH,
            MAX_FLIGHT_BATCHES_PER_STREAM,
            MAX_FLIGHT_ROWS_PER_STREAM,
            FLIGHT_BATCH_RECV_TIMEOUT,
        );
    });
}

/// The Flight ingest service: swallows `DoPut` streams into the events store.
#[derive(Clone)]
pub struct FlightIngest {
    events: EventsHandle,
    collectors: Arc<SharedCollectors>,
}

impl FlightIngest {
    pub fn new(events: EventsHandle, collectors: Arc<SharedCollectors>) -> Self {
        Self { events, collectors }
    }

    /// Build the tonic service ready to `.add_service(..)` onto a server.
    pub fn into_server(self) -> FlightServiceServer<Self> {
        FlightServiceServer::new(self)
    }
}

/// A boxed server-streaming response — the shape every `FlightService` stream
/// associated type takes here.
type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// Run the Flight ingest receiver on `addr` until the server stops.
pub async fn serve(
    events: EventsHandle,
    collectors: Arc<SharedCollectors>,
    addr: SocketAddr,
) -> Result<(), tonic::transport::Error> {
    warn_experimental_once();
    tonic::transport::Server::builder()
        .add_service(FlightIngest::new(events, collectors).into_server())
        .serve(addr)
        .await
}

#[tonic::async_trait]
impl FlightService for FlightIngest {
    type HandshakeStream = BoxStream<HandshakeResponse>;
    type ListFlightsStream = BoxStream<FlightInfo>;
    type DoGetStream = BoxStream<FlightData>;
    type DoPutStream = BoxStream<PutResult>;
    type DoExchangeStream = BoxStream<FlightData>;
    type DoActionStream = BoxStream<arrow_flight::Result>;
    type ListActionsStream = BoxStream<ActionType>;

    /// The one method garm implements: swallow a pushed Arrow stream. Decodes the
    /// `FlightData` (schema message + record batches) into `RecordBatch`es and
    /// appends each via the columnar swallow. Responds with one `PutResult` whose
    /// `app_metadata` is the total rows stored (post-dedup), as ASCII.
    async fn do_put(
        &self,
        request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoPutStream>, Status> {
        // Match native ingest's default-off semantics. A self-declared collector
        // header is never an authentication credential: with a configured
        // registry require a bearer token, and with an empty registry store the
        // batch as unverified.
        let presented = if self.collectors.enabled() {
            let token = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::to_string);
            let registry = self.collectors.get();
            match token
                .as_deref()
                .and_then(|token| registry.resolve(token))
                .is_some()
            {
                true => token,
                false => return Err(Status::unauthenticated("collector authentication required")),
            }
        } else {
            None
        };

        // Loud, one-time reminder that this transport is experimental — fires even
        // when the service is wired up directly (not via `serve`).
        warn_experimental_once();

        // Resolve caps once per stream (env overrides are read here, cheaply).
        let max_rows_batch = max_rows_per_batch();
        let max_batches = max_batches_per_stream();
        let max_rows_stream = max_rows_per_stream();
        let recv_timeout = batch_recv_timeout();

        // tonic yields `Result<FlightData, Status>`; the decoder wants
        // `Result<FlightData, FlightError>`.
        let inbound = request.into_inner().map_err(FlightError::from);
        let mut batches = FlightRecordBatchStream::new_from_flight_data(inbound);

        let mut total = 0usize;
        let mut batches_seen = 0usize;
        let mut rows_seen = 0usize;
        loop {
            // Bound the wait for each frame so a stalled peer cannot pin the
            // swallow task forever. Timeout ends the stream (returns), no deadlock.
            let next = tokio::time::timeout(recv_timeout, batches.next())
                .await
                .map_err(|_| {
                    Status::deadline_exceeded("flight stream stalled waiting for next batch")
                })?;
            let Some(batch) = next else { break };
            let batch =
                batch.map_err(|e| Status::invalid_argument(format!("flight decode: {e}")))?;

            // Enforce resource limits BEFORE any enrich/append work: reject an
            // oversized single batch, abort the stream once cumulative batches or
            // rows exceed the per-stream caps.
            batches_seen += 1;
            rows_seen += batch.num_rows();
            check_flight_limits(
                batch.num_rows(),
                batches_seen,
                rows_seen,
                max_rows_batch,
                max_batches,
                max_rows_stream,
            )?;

            // RE-AUTHORIZE PER BATCH. A do_put stream is a single request that may
            // carry millions of rows over a long life, so resolving once at the
            // head would let a revoked, rotated, or newly-expired credential keep
            // writing until the client chose to hang up — "hot revoke" that is not
            // hot on the one transport built for volume. Re-resolving against the
            // current registry handle bounds that exposure to a single batch. The
            // cost is a handle clone plus a constant-time token scan per BATCH
            // (not per row), which is noise next to enrich + append.
            let collector =
                match &presented {
                    None => None,
                    Some(token) => {
                        let registry = self.collectors.get();
                        match registry.resolve(token) {
                            Some(c) => Some(c.clone()),
                            None => return Err(Status::unauthenticated(
                                "collector credential is no longer valid (revoked, rotated, or \
                                 expired) — reconnect with the current token",
                            )),
                        }
                    }
                };

            // Derive fields from the raw message for rows shipped without them, so
            // detection fires on raw Flight lines exactly as on native ingest.
            let batch = enrich_empty_fields(batch);
            if let Some(collector) = &collector {
                let sources = batch
                    .columns()
                    .get(3)
                    .ok_or_else(|| {
                        Status::invalid_argument("flight batch is missing source column")
                    })?
                    .as_any()
                    .downcast_ref::<arrow_array::StringArray>()
                    .ok_or_else(|| Status::invalid_argument("flight source column must be utf8"))?;
                if let Some(source) = (0..sources.len())
                    .map(|i| sources.value(i))
                    .find(|source| !collector.may_assert(source))
                {
                    return Err(Status::permission_denied(format!(
                        "collector '{}' may not assert source '{}'",
                        collector.id, source
                    )));
                }
            }
            total += self
                .events
                .append_batch(batch, collector.as_ref().map(|c| c.id.clone()))
                .await
                .map_err(|e| Status::internal(format!("append_batch: {e}")))?;
        }

        let ack = PutResult {
            app_metadata: total.to_string().into_bytes().into(),
        };
        let out = futures::stream::once(async move { Ok(ack) });
        Ok(Response::new(Box::pin(out)))
    }

    // ---- garm is a sink, not a Flight query engine: the rest are unimplemented ----

    async fn handshake(
        &self,
        _request: Request<Streaming<HandshakeRequest>>,
    ) -> Result<Response<Self::HandshakeStream>, Status> {
        Err(Status::unimplemented(
            "garm Flight ingest: handshake not supported",
        ))
    }

    async fn list_flights(
        &self,
        _request: Request<Criteria>,
    ) -> Result<Response<Self::ListFlightsStream>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn get_flight_info(
        &self,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn poll_flight_info(
        &self,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<PollInfo>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn get_schema(
        &self,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<SchemaResult>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn do_get(
        &self,
        _request: Request<Ticket>,
    ) -> Result<Response<Self::DoGetStream>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn do_exchange(
        &self,
        _request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoExchangeStream>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn do_action(
        &self,
        _request: Request<Action>,
    ) -> Result<Response<Self::DoActionStream>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }

    async fn list_actions(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::ListActionsStream>, Status> {
        Err(Status::unimplemented("garm Flight ingest is do_put only"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        check_flight_limits, enrich_empty_fields, MAX_FLIGHT_BATCHES_PER_STREAM,
        MAX_FLIGHT_ROWS_PER_BATCH, MAX_FLIGHT_ROWS_PER_STREAM,
    };
    use arrow_array::{Array, RecordBatch};
    use arrow_flight::decode::FlightRecordBatchStream;
    use arrow_flight::encode::FlightDataEncoderBuilder;
    use chrono::Utc;
    use garmr_core::Event;
    use garmr_store::schema::{build_events_batch, build_events_batch_from_wire, build_wire_batch};

    fn ev(i: usize) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("src_ip".to_string(), format!("10.2.0.{i}"));
        Event {
            ts: Utc::now(),
            host: format!("host-{i}").into(),
            service: "sshd".into(),
            source: "flightbeat".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: format!("flight line {i}"),
            fields,
        }
    }

    fn event_id_col(b: &RecordBatch) -> Vec<String> {
        use arrow_array::StringArray;
        let i = b.schema().index_of("event_id").unwrap();
        let a = b.column(i).as_any().downcast_ref::<StringArray>().unwrap();
        (0..a.len()).map(|r| a.value(r).to_string()).collect()
    }

    /// A wire batch must survive Arrow-Flight IPC encode→decode intact, so that the
    /// receiver's columnar swallow of the DECODED batch produces the SAME
    /// `event_id`s as the native path over the original events. This exercises the
    /// exact codec `do_put` runs (`FlightDataEncoderBuilder` on the sender,
    /// `FlightRecordBatchStream` on the receiver) with no server/socket, isolating
    /// wire-format fidelity. Red if the Flight codec ever perturbs the payload
    /// columns (type, order, value) enough to change the recomputed id.
    #[tokio::test]
    async fn wire_batch_survives_flight_ipc_roundtrip_preserving_event_id() {
        use futures::TryStreamExt;

        let events: Vec<Event> = (0..5).map(ev).collect();
        let wire = build_wire_batch(&events).unwrap();

        // Sender side: encode the wire batch to a Flight DoPut stream.
        let encoded: Vec<_> = FlightDataEncoderBuilder::new()
            .build(futures::stream::iter(vec![Ok(wire.clone())]))
            .try_collect()
            .await
            .expect("encode flight data");

        // Receiver side: decode exactly as `do_put` does.
        let decoded: Vec<RecordBatch> = FlightRecordBatchStream::new_from_flight_data(
            futures::stream::iter(encoded.into_iter().map(Ok)),
        )
        .try_collect()
        .await
        .expect("decode flight data");

        let total: usize = decoded.iter().map(|b| b.num_rows()).sum();
        assert_eq!(total, events.len(), "all rows survived the IPC round-trip");

        // Swallow each decoded batch; its event_id column must equal the native
        // build over the original events — full fidelity + cross-path identity.
        let native = build_events_batch(&events).unwrap();
        let want = event_id_col(&native);
        let mut got = Vec::new();
        for b in &decoded {
            let swallowed = build_events_batch_from_wire(b, Some("edge-01")).unwrap();
            got.extend(event_id_col(&swallowed));
        }
        assert_eq!(
            got, want,
            "Flight-decoded swallow event_ids match the native path"
        );
    }

    /// A raw line shipped over Flight WITHOUT fields must be enriched on the
    /// receiver exactly as the native path enriches it — same extracted fields,
    /// same `event_id` — so detection fires on raw Flight logs. Builds a wire batch
    /// with empty `fields` (a raw-line shipper) + messages carrying an IP/user,
    /// enriches it, and asserts the swallowed provenance matches a native build
    /// over events whose fields were `fields::extract`ed from the same messages.
    #[test]
    fn raw_flight_lines_are_field_enriched_to_match_native() {
        use arrow_array::StringArray;

        let msgs = [
            "Failed password for root from 10.0.0.9 port 22 ssh2",
            "Accepted password for alice from 192.168.1.5 port 51000 ssh2",
        ];
        // Raw-line shipper: events with EMPTY fields → wire `fields` = "{}".
        let raw: Vec<Event> = msgs
            .iter()
            .map(|m| Event {
                ts: Utc::now(),
                host: "pve".into(),
                service: "sshd".into(),
                source: "flightbeat".into(),
                environment: "test".into(),
                severity: "info".into(),
                log_type: "system".into(),
                message: (*m).into(),
                fields: BTreeMap::new(),
            })
            .collect();
        let wire = build_wire_batch(&raw).unwrap();

        // Enrich, then swallow.
        let enriched = enrich_empty_fields(wire);
        let fields_col = {
            let i = enriched.schema().index_of("fields").unwrap();
            enriched
                .column(i)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .clone()
        };
        assert!(
            fields_col.value(0).contains("10.0.0.9"),
            "src_ip extracted on the receiver"
        );
        assert!(
            fields_col.value(1).contains("alice"),
            "user extracted on the receiver"
        );
        let swallowed = build_events_batch_from_wire(&enriched, None).unwrap();

        // Native path over the SAME lines: fields derived by the same extractor.
        let native_events: Vec<Event> = raw
            .iter()
            .map(|e| {
                let mut e = e.clone();
                e.fields = crate::fields::extract(&e.message);
                e
            })
            .collect();
        let native = build_events_batch(&native_events).unwrap();

        assert_eq!(
            event_id_col(&swallowed),
            event_id_col(&native),
            "enriched raw Flight line gets the same event_id as the native path"
        );
    }

    /// A real wire batch whose row count exceeds the per-batch cap must be
    /// rejected by the exact guard `do_put` runs, while a batch within the cap
    /// passes. Building a >1M-row batch is impractical, so this drives the guard
    /// with a small cap over a real 5-row `RecordBatch` — the same
    /// `check_flight_limits` call the receiver makes, over a genuinely decoded
    /// batch's `num_rows()`. Red if the per-batch enforcement is dropped or its
    /// comparison inverted.
    #[test]
    fn flight_do_put_rejects_oversized_batch_and_accepts_normal() {
        let events: Vec<Event> = (0..5).map(ev).collect();
        let wire = build_wire_batch(&events).unwrap();
        assert_eq!(wire.num_rows(), 5);

        // 5 rows over a per-batch cap of 2 → resource_exhausted, no store touched.
        let rejected = check_flight_limits(
            wire.num_rows(),
            1,
            wire.num_rows(),
            2,                             // tiny per-batch cap
            MAX_FLIGHT_BATCHES_PER_STREAM, // generous per-stream caps
            MAX_FLIGHT_ROWS_PER_STREAM,
        );
        let err = rejected.expect_err("oversized batch must be rejected");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(
            err.message().contains("per-batch cap"),
            "message names the per-batch cap: {}",
            err.message()
        );

        // The same batch under the real production cap is accepted.
        check_flight_limits(
            wire.num_rows(),
            1,
            wire.num_rows(),
            MAX_FLIGHT_ROWS_PER_BATCH,
            MAX_FLIGHT_BATCHES_PER_STREAM,
            MAX_FLIGHT_ROWS_PER_STREAM,
        )
        .expect("a normal 5-row batch is within all caps");
    }

    /// The per-stream caps abort a stream that stays within the per-batch cap but
    /// accumulates too many batches or too many cumulative rows.
    #[test]
    fn flight_do_put_aborts_stream_over_cumulative_caps() {
        // Batch count cap: batch #(cap+1) trips it, batch #cap does not.
        check_flight_limits(
            1,
            MAX_FLIGHT_BATCHES_PER_STREAM,
            10,
            1000,
            MAX_FLIGHT_BATCHES_PER_STREAM,
            MAX_FLIGHT_ROWS_PER_STREAM,
        )
        .expect("the final in-budget batch is accepted");
        let over_batches = check_flight_limits(
            1,
            MAX_FLIGHT_BATCHES_PER_STREAM + 1,
            10,
            1000,
            MAX_FLIGHT_BATCHES_PER_STREAM,
            MAX_FLIGHT_ROWS_PER_STREAM,
        )
        .expect_err("one batch past the per-stream batch cap aborts the stream");
        assert_eq!(over_batches.code(), tonic::Code::ResourceExhausted);
        assert!(over_batches.message().contains("per-stream batch cap"));

        // Cumulative-row cap: a per-batch-legal batch pushes the running total over.
        let over_rows = check_flight_limits(
            10,
            2,
            MAX_FLIGHT_ROWS_PER_STREAM + 5,
            MAX_FLIGHT_ROWS_PER_BATCH,
            MAX_FLIGHT_BATCHES_PER_STREAM,
            MAX_FLIGHT_ROWS_PER_STREAM,
        )
        .expect_err("crossing the cumulative row cap aborts the stream");
        assert_eq!(over_rows.code(), tonic::Code::ResourceExhausted);
        assert!(over_rows.message().contains("per-stream row cap"));
    }
}
