//! `HttpLineageSink` (feature `lineage-http`) — map a `LineageEvent` to an
//! OpenLineage `RunEvent` and POST it. Two assertions in one test: the RunEvent
//! JSON body is shaped correctly (direct `run_event` mapping, no network), and a
//! real `emit` POSTs that body to a one-shot local HTTP server which captures it.

#![cfg(feature = "lineage-http")]

use std::io::{Read, Write};
use std::net::TcpListener;

use anyhow::Result;
use skade::lineage::HttpLineageSink;
use skade::{DatasetRef, LineageEvent, LineageSink, SystemRef};

#[tokio::test]
async fn http_lineage_sink_maps_runevent() -> Result<()> {
    // A cross-system transform hop: silver -> gold, by a named run, with a cursor.
    let event = LineageEvent::new(
        skade::LineageOperation::Append,
        DatasetRef::skade("main.gold", Some(77)),
    )
    .with_actor("nornir/etl-run-3")
    .with_input(DatasetRef::in_system(
        "main.silver",
        Some(76),
        SystemRef::new("spark", "app-42"),
    ))
    .with_commit_seq(9001);

    let sink =
        HttpLineageSink::new("http://127.0.0.1:0/api/v1/lineage").with_job_namespace("lakehouse");

    // ── 1. mapping assertions (no network) ────────────────────────────────
    let re = sink.run_event(&event);
    assert_eq!(re["eventType"], "COMPLETE");
    assert_eq!(re["job"]["namespace"], "lakehouse");
    assert_eq!(re["job"]["name"], "nornir/etl-run-3");
    // Output dataset (in-warehouse → job namespace), versioned by snapshot id.
    assert_eq!(re["outputs"][0]["name"], "main.gold");
    assert_eq!(re["outputs"][0]["namespace"], "lakehouse");
    assert_eq!(
        re["outputs"][0]["facets"]["version"]["datasetVersion"],
        "77"
    );
    // Input dataset lives in the foreign system → its instance is the namespace.
    assert_eq!(re["inputs"][0]["name"], "main.silver");
    assert_eq!(re["inputs"][0]["namespace"], "app-42");
    // Commit cursor rides as a run facet; runId is UUID-shaped (5 dash groups).
    assert_eq!(re["run"]["facets"]["skade_commit"]["commitSeq"], 9001);
    let run_id = re["run"]["runId"].as_str().unwrap();
    assert_eq!(run_id.split('-').count(), 5, "runId is UUID-shaped");
    assert_eq!(run_id.len(), 36);
    // eventTime is RFC-3339 UTC.
    assert!(re["eventTime"].as_str().unwrap().ends_with('Z'));

    // Same event id → same run id (deterministic).
    assert_eq!(sink.run_event(&event)["run"]["runId"], run_id);

    // ── 2. real POST to a one-shot local server ───────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let server = std::thread::spawn(move || -> std::io::Result<String> {
        let (mut stream, _) = listener.accept()?;
        // Accumulate until the whole request (headers + JSON body) has arrived —
        // a small localhost payload may still split across reads.
        let mut acc: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n]);
            // The body ends with the RunEvent's closing brace once fully read; the
            // cursor facet is the last-written field, so stop once it's present.
            if acc.windows(9).any(|w| w == b"commitSeq") {
                break;
            }
        }
        // Respond 200 so ureq is happy.
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        stream.flush()?;
        Ok(String::from_utf8_lossy(&acc).to_string())
    });

    let post_sink = HttpLineageSink::new(format!("http://127.0.0.1:{port}/api/v1/lineage"))
        .with_job_namespace("lakehouse");
    post_sink.emit(&event).await.expect("emit POST succeeds");

    let request = server.join().expect("server thread")?;
    assert!(
        request.starts_with("POST /api/v1/lineage"),
        "POST line: {request}"
    );
    // The captured request body carries the RunEvent JSON.
    assert!(
        request.contains("\"eventType\":\"COMPLETE\""),
        "body has eventType"
    );
    assert!(request.contains("\"main.gold\""), "body names the output");
    assert!(
        request.contains("\"commitSeq\":9001"),
        "body carries the cursor"
    );
    Ok(())
}
