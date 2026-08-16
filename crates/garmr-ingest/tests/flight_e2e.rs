// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Live end-to-end test of the Arrow-Flight ingest path over a real TCP socket:
//! a `FlightClient` `do_put`s a wire batch to the `flight::serve` receiver, which
//! swallows it into a real (tempdir) store. Proves the one seam the in-process
//! round-trip test can't: the actual tonic transport (client channel ↔
//! `FlightServiceServer`), plus collector attribution and that the rows land
//! queryable. Only built with `--features flight`.
#![cfg(feature = "flight")]

use std::sync::Arc;

use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow_flight::encode::FlightDataEncoderBuilder;
use arrow_flight::error::FlightError;
use arrow_flight::FlightClient;
use futures::TryStreamExt;
use garmr_core::Config;
use garmr_ingest::flight::FlightIngest;
use garmr_store::Store;

/// Build the 9-column v1 wire batch a sender ships (same shape as
/// `garmr_store::schema::wire_schema`), with distinct hosts/messages.
fn wire_batch(n: usize) -> RecordBatch {
    let schema = garmr_store::schema::wire_schema();
    let now = 1_700_000_500_000_000i64;
    let rep = |s: &str| StringArray::from(vec![s; n]);
    let hosts: Vec<String> = (0..n).map(|i| format!("host-{i}")).collect();
    let msgs: Vec<String> = (0..n).map(|i| format!("flight e2e line {i}")).collect();
    let cols: Vec<ArrayRef> = vec![
        Arc::new(TimestampMicrosecondArray::from(vec![now; n])),
        Arc::new(StringArray::from(
            hosts.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        )),
        Arc::new(rep("sshd")),
        Arc::new(rep("flightbeat")),
        Arc::new(rep("test")),
        Arc::new(rep("info")),
        Arc::new(rep("system")),
        Arc::new(StringArray::from(
            msgs.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        )),
        Arc::new(rep("{}")),
    ];
    RecordBatch::try_new(Arc::new(schema), cols).expect("wire batch")
}

async fn count(store: &Store, sql: &str) -> i64 {
    let rows = store.events.sql(sql).await.unwrap();
    rows[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap()
        .value(0)
}

#[tokio::test]
async fn flight_do_put_cannot_spoof_collector_identity() {
    // 1) A real store in a tempdir (config from the shipped example, redirected).
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../garmr.example.toml");
    let mut cfg = Config::load(&example).expect("load garmr.example.toml");
    let tmp = tempfile::tempdir().unwrap();
    cfg.store.warehouse_dir = tmp.path().join("wh");
    cfg.store.state_db = tmp.path().join("state.redb");
    cfg.store.search_dir = tmp.path().join("search");
    cfg.store.compact_snapshot_threshold = 0; // no compaction churn in the test
    let store = Store::open_writable(&cfg).await.expect("open store");

    // 2) Serve the receiver on an ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let events = store.events.clone();
    // The receiver takes the swappable handle (hot rotate/revoke), not a fixed
    // registry — an empty one here, so the test's spoofing attempt is judged by
    // the same gate production uses.
    let collectors = garmr_core::SharedCollectors::new(garmr_core::CollectorRegistry::new());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(FlightIngest::new(events, collectors).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // 3) Client: connect and DoPut a wire batch with a collector header.
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .expect("connect to receiver");
    let mut client = FlightClient::new(channel);
    client.add_header("garmr-collector-id", "e2e-01").unwrap();

    let batch = wire_batch(4);
    let schema = batch.schema();
    let stream = FlightDataEncoderBuilder::new()
        .with_schema(schema)
        .build(futures::stream::iter(vec![Ok::<_, FlightError>(batch)]));
    let acks: Vec<_> = client
        .do_put(stream)
        .await
        .expect("do_put")
        .try_collect()
        .await
        .unwrap();

    // The receiver acks the stored-row count in app_metadata.
    let acked: i64 = acks
        .iter()
        .filter_map(|r| std::str::from_utf8(&r.app_metadata).ok())
        .filter_map(|s| s.trim().parse().ok())
        .last()
        .unwrap_or(0);
    assert_eq!(acked, 4, "receiver acked 4 stored rows");

    // 4) The events are queryable, but an unverified client cannot stamp trusted
    // collector attribution merely by supplying the legacy metadata header.
    assert_eq!(count(&store, "SELECT count(*) AS n FROM events").await, 4);
    assert_eq!(
        count(
            &store,
            "SELECT count(*) AS n FROM events \
             WHERE source_trust='unverified' AND collector_id IS NULL"
        )
        .await,
        4,
        "self-declared collector metadata is not trusted"
    );
}

/// Revoking a collector must bound how much longer it can write, even mid-stream.
///
/// A `do_put` stream is ONE request that may carry millions of rows over a long
/// life. Resolving the credential once at the head — as this receiver used to —
/// means "hot revoke" is not hot on the one transport built for volume: a
/// revoked shipper keeps writing until it chooses to hang up. The receiver
/// re-resolves per batch, so this test sends one batch, revokes, and asserts the
/// next batch on the SAME stream is refused.
#[tokio::test]
async fn revoking_a_collector_stops_an_already_open_flight_stream() {
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../garmr.example.toml");
    let mut cfg = Config::load(&example).expect("load garmr.example.toml");
    let tmp = tempfile::tempdir().unwrap();
    cfg.store.warehouse_dir = tmp.path().join("wh");
    cfg.store.state_db = tmp.path().join("state.redb");
    cfg.store.search_dir = tmp.path().join("search");
    cfg.store.compact_snapshot_threshold = 0;
    let store = Store::open_writable(&cfg).await.expect("open store");

    // A registry holding one plaintext credential, behind the swappable handle.
    let mut reg = garmr_core::CollectorRegistry::new();
    reg.add_json(r#"[{"id":"e2e-rev","token":"s3cret-token"}]"#)
        .expect("seed the registry");
    let collectors = garmr_core::SharedCollectors::new(reg);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let events = store.events.clone();
    let serving = collectors.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(FlightIngest::new(events, serving).into_server())
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .expect("connect to receiver");
    let mut client = FlightClient::new(channel);
    client
        .add_header("authorization", "Bearer s3cret-token")
        .unwrap();

    // Batch 1 goes out; then the operator revokes (an empty registry is the
    // "this credential no longer exists" end state of `garmr collectors revoke`)
    // while the stream is still open; then batch 2 goes out on the SAME stream.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<RecordBatch, FlightError>>();
    let batch = wire_batch(4);
    let schema = batch.schema();
    tx.send(Ok(batch)).unwrap();
    let revoked = collectors.clone();
    let sender = tokio::spawn(async move {
        // Give the receiver time to swallow batch 1 before revoking, so the
        // refusal below is unambiguously the re-check and not a race.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        revoked.swap(garmr_core::CollectorRegistry::new());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        tx.send(Ok(wire_batch(4))).unwrap();
        drop(tx);
    });

    let stream = FlightDataEncoderBuilder::new()
        .with_schema(schema)
        .build(tokio_stream::wrappers::UnboundedReceiverStream::new(rx));
    let result: Result<Vec<_>, _> = match client.do_put(stream).await {
        Ok(s) => s.try_collect().await,
        Err(e) => Err(e),
    };
    sender.await.unwrap();

    let err = result.expect_err("the stream must be refused after revocation");
    let msg = format!("{err}");
    assert!(
        msg.contains("no longer valid")
            || msg.contains("Unauthenticated")
            || msg.contains("unauthenticated"),
        "the refusal names the credential state: {msg}"
    );
    // The pre-revocation batch was legitimately stored; only the post-revocation
    // one is refused. Revocation bounds the exposure, it does not rewrite history.
    assert_eq!(
        count(&store, "SELECT count(*) AS n FROM events").await,
        4,
        "batch 1 (authorized) landed; batch 2 (revoked) did not"
    );
}
