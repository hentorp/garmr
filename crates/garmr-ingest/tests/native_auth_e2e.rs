// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end proof of the native ingest endpoint's *authentication* contract.
//!
//! `native.rs` unit-tests the decoder's size/count limits, but the controls that
//! `docs/security/known-limitations.md` promises live in the axum handler and had
//! no wire-level coverage: bearer-token collector auth, authentication happening
//! **before** decoding, whole-batch rejection on a forbidden source, and the
//! server — not the client — stamping the trusted collector id.
//!
//! These drive the real `run_ingest` server over a real TCP socket with raw
//! HTTP/1.1, so the axum routing, the `DefaultBodyLimit` layer, and the handler
//! are all exercised exactly as a shipper would hit them. No HTTP client crate is
//! needed, which keeps garmr-ingest's dev-dependency surface at tokio.

use std::sync::Arc;

use garmr_core::CollectorRegistry;
use garmr_ingest::{IngestAuditor, IngestBatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// What a delivered batch looks like to the test: the events plus the collector
/// id the SERVER stamped on them.
type Delivered = (Vec<garmr_core::Event>, Option<String>);

/// Start `run_ingest` on an ephemeral loopback port, together with a stand-in
/// pipeline that ACKs every batch as durably persisted.
///
/// The ACK matters: the handler holds the HTTP response until the pipeline
/// confirms persistence (that is the at-least-once contract), so a test harness
/// that never ACKs would hang every successful request. The stand-in forwards
/// what it received so assertions can be made on the batch.
async fn start(registry: CollectorRegistry) -> (String, mpsc::Receiver<Delivered>) {
    // Bind first to learn a free port, then drop it so the server can take it.
    // A loopback ephemeral port is not realistically re-taken in between.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let (tx, mut raw_rx) = mpsc::channel::<IngestBatch>(16);
    let (seen_tx, seen_rx) = mpsc::channel::<Delivered>(16);
    tokio::spawn(async move {
        while let Some(batch) = raw_rx.recv().await {
            let IngestBatch {
                events,
                ack,
                collector_id,
            } = batch;
            let _ = seen_tx.send((events, collector_id)).await;
            if let Some(ack) = ack {
                let _ = ack.send(Ok(()));
            }
        }
    });

    let bind = addr.to_string();
    let serve_bind = bind.clone();
    tokio::spawn(async move {
        let _ = garmr_ingest::run_ingest(
            &serve_bind,
            tx,
            "test".to_string(),
            Arc::new(registry),
            IngestAuditor::noop(),
            None,
        )
        .await;
    });

    // Wait for the listener to accept connections.
    for _ in 0..200 {
        if TcpStream::connect(&bind).await.is_ok() {
            return (bind, seen_rx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("ingest server never came up on {bind}");
}

/// POST `body` to `/ingest/v1/events` and return `(status_code, body_text)`.
async fn post(addr: &str, auth: Option<&str>, body: &str) -> (u16, String) {
    let mut req = format!(
        "POST /ingest/v1/events HTTP/1.1\r\nHost: {addr}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(token) = auth {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);

    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(req.as_bytes()).await.expect("write request");
    s.flush().await.unwrap();

    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();

    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in response: {text:?}"));
    (status, text)
}

fn registry(json: &str) -> CollectorRegistry {
    let mut r = CollectorRegistry::new();
    r.add_json(json).expect("valid collector json");
    r
}

/// With collectors configured, a POST carrying no bearer token is rejected 401 —
/// and, critically, the batch never reaches the pipeline.
#[tokio::test]
async fn unauthenticated_post_is_rejected_when_collectors_are_configured() {
    let reg = registry(r#"[{"id":"pg-01","token":"s3cret","sources":["postgres-csvlog"]}]"#);
    let (addr, mut rx) = start(reg).await;

    let (status, _) = post(
        &addr,
        None,
        r#"[{"message":"hello","source":"postgres-csvlog"}]"#,
    )
    .await;
    assert_eq!(status, 401, "no bearer token must be 401");

    let (status, _) = post(
        &addr,
        Some("wrong-token"),
        r#"[{"message":"hello","source":"postgres-csvlog"}]"#,
    )
    .await;
    assert_eq!(status, 401, "an unknown token must be 401");

    assert!(
        rx.try_recv().is_err(),
        "no batch may reach the pipeline from an unauthenticated request"
    );
}

/// Authentication runs BEFORE decoding: a request with a syntactically broken
/// body and no credential must still be 401, never 400. A 400 would prove the
/// parser ran first and would leak parser detail to an unauthenticated caller.
#[tokio::test]
async fn authentication_precedes_decoding() {
    let reg = registry(r#"[{"id":"pg-01","token":"s3cret"}]"#);
    let (addr, _rx) = start(reg).await;

    let (status, body) = post(&addr, None, "{ this is not json at all ").await;
    assert_eq!(
        status, 401,
        "an unauthenticated request must be refused before the body is parsed \
         (got {status}, body: {body})"
    );
    assert!(
        !body.contains("json decode"),
        "no parser error may leak to an unauthenticated caller: {body}"
    );
}

/// A collector may only assert the sources bound to it, and one forbidden source
/// fails the WHOLE batch — the legitimate events in the same request must not be
/// ingested either.
#[tokio::test]
async fn forbidden_source_rejects_the_entire_batch() {
    let reg = registry(r#"[{"id":"pg-01","token":"s3cret","sources":["postgres-csvlog"]}]"#);
    let (addr, mut rx) = start(reg).await;

    let body = r#"[
        {"message":"legitimate","source":"postgres-csvlog"},
        {"message":"forged","source":"journald"},
        {"message":"also legitimate","source":"postgres-csvlog"}
    ]"#;
    let (status, text) = post(&addr, Some("s3cret"), body).await;
    assert_eq!(status, 403, "a forbidden source must be 403");
    assert!(
        text.contains("may not assert source"),
        "the response names the violation: {text}"
    );
    assert!(
        rx.try_recv().is_err(),
        "the whole batch is rejected — not even the allowed events land"
    );
}

/// The collector identity written with a batch is derived from the resolved token
/// on the SERVER. A client cannot assert its own identity: the id stamped on the
/// batch is the registry's, regardless of what the payload claims.
#[tokio::test]
async fn collector_identity_is_server_stamped_not_client_asserted() {
    let reg = registry(
        r#"[{"id":"pg-01","token":"s3cret","sources":["postgres-csvlog"]},
             {"id":"other-99","token":"other-token"}]"#,
    );
    let (addr, mut rx) = start(reg).await;

    // The payload has no way to name a collector, and the `source` it does assert
    // is bound to pg-01 — so authenticating as pg-01 must stamp exactly "pg-01".
    let (status, text) = post(
        &addr,
        Some("s3cret"),
        r#"[{"message":"audit row","source":"postgres-csvlog"}]"#,
    )
    .await;
    assert_eq!(status, 200, "an authorized post is accepted: {text}");
    assert!(
        text.contains("\"accepted\":1"),
        "the response reports the accepted count: {text}"
    );

    let (events, collector_id) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("a batch reaches the pipeline")
        .expect("channel open");
    assert_eq!(
        collector_id.as_deref(),
        Some("pg-01"),
        "the server stamps the authenticated collector id"
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source, "postgres-csvlog");
}

/// Default-off parity: with an EMPTY registry the endpoint is the historical
/// unauthenticated path — a tokenless POST is accepted and the batch carries no
/// collector attribution. This is the documented development posture, and the
/// test exists so a change to it is deliberate rather than accidental.
#[tokio::test]
async fn empty_registry_keeps_the_unauthenticated_development_path() {
    let (addr, mut rx) = start(CollectorRegistry::new()).await;

    let (status, text) = post(&addr, None, r#"[{"message":"dev line"}]"#).await;
    assert_eq!(
        status, 200,
        "with no collectors configured a tokenless post is accepted: {text}"
    );

    let (events, collector_id) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("a batch reaches the pipeline")
        .expect("channel open");
    assert_eq!(events.len(), 1);
    assert_eq!(
        collector_id, None,
        "an unauthenticated batch carries no collector attribution"
    );
}

/// The decoder's limits are enforced over the WIRE, not just in the unit test:
/// an over-long single message is refused with 400 and never reaches the pipeline.
#[tokio::test]
async fn oversized_message_is_refused_over_the_wire() {
    let reg = registry(r#"[{"id":"pg-01","token":"s3cret"}]"#);
    let (addr, mut rx) = start(reg).await;

    let big = "m".repeat(garmr_ingest::native::MAX_MESSAGE_BYTES + 1);
    let body = format!(r#"[{{"message":"{big}"}}]"#);
    let (status, text) = post(&addr, Some("s3cret"), &body).await;
    assert_eq!(status, 400, "an over-limit message is a 400: {text}");
    assert!(
        text.contains("message too large"),
        "the response names the limit: {text}"
    );
    assert!(
        rx.try_recv().is_err(),
        "an over-limit batch never reaches the pipeline"
    );
}
