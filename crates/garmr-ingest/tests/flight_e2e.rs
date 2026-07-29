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
    let collectors = Arc::new(garmr_core::CollectorRegistry::new());
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