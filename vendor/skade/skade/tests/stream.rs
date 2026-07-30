//! Streaming CDC consume (`feature = "stream"`) — the push `ChangeStream` over
//! skade-katalog's commit broadcast, its poll fallback, and exactly-once cursor
//! resume. A temp-dir warehouse, real appends, a live stream draining windows.
#![cfg(feature = "stream")]

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use skade::arrow_array::{Array, Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::change_type;
use skade::{ChangeStream, ConsumerCursor};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

fn batch(ids: &[i64]) -> Result<RecordBatch> {
    let names: Vec<String> = ids.iter().map(|i| format!("r{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(Int64Array::from(ids.to_vec())),
            Arc::new(StringArray::from(names)),
        ],
    )?)
}

/// The sorted ids across a changelog window (skipping widened-null rows).
fn ids(cl: &skade::ChangelogBatch) -> Vec<i64> {
    let mut out = Vec::new();
    for b in &cl.rows {
        let col = b
            .column_by_name("id")
            .unwrap()
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        for i in 0..col.len() {
            if col.is_valid(i) {
                out.push(col.value(i));
            }
        }
    }
    out.sort();
    out
}

/// Every insert (delete) rows carry an INSERT (…) tag string.
fn tags(cl: &skade::ChangelogBatch) -> Vec<String> {
    let mut out = Vec::new();
    for b in &cl.rows {
        let c = b
            .column_by_name(change_type::COLUMN)
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        for i in 0..c.len() {
            out.push(c.value(i).to_string());
        }
    }
    out
}

/// A commit to the table wakes the stream: each `append` yields exactly one
/// changelog window carrying that commit's rows, in commit order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn table_changes_yields_window_per_commit() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    // Subscribe at "now" (empty table), then commit twice.
    let mut s = t.changes(None).await?;
    t.append(&[batch(&[1, 2, 3])?]).await?;
    t.append(&[batch(&[4, 5])?]).await?;

    let w1 = timeout(T, s.next()).await?.expect("a first window")?;
    assert_eq!(ids(&w1), vec![1, 2, 3], "window 1 = first commit's rows");
    assert!(tags(&w1).iter().all(|t| t == "INSERT"));

    let w2 = timeout(T, s.next()).await?.expect("a second window")?;
    assert_eq!(ids(&w2), vec![4, 5], "window 2 = second commit's rows");

    #[cfg(feature = "testmatrix")]
    skade::functional_status(
        "skade/stream",
        "table_changes_yields_window_per_commit",
        true,
        "2 appends → 2 push windows {1,2,3} then {4,5}",
    );
    Ok(())
}

/// The poll fallback yields the same windows with no broadcast at all — a pure
/// timer poll of the table's current snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_stream_poll_fallback_without_broadcast() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    // Poll-only: never touches subscribe_commits.
    let mut s = t.changes_polling(None, Duration::from_millis(15)).await?;
    t.append(&[batch(&[1, 2, 3])?]).await?;

    let w = timeout(T, s.next()).await?.expect("a polled window")?;
    assert_eq!(ids(&w), vec![1, 2, 3], "poll detected the commit");

    // A second commit is picked up on the next poll tick too.
    t.append(&[batch(&[9])?]).await?;
    let w2 = timeout(T, s.next())
        .await?
        .expect("a second polled window")?;
    assert_eq!(ids(&w2), vec![9]);

    #[cfg(feature = "testmatrix")]
    skade::functional_status(
        "skade/stream",
        "change_stream_poll_fallback_without_broadcast",
        true,
        "poll path yields windows with no broadcast",
    );
    Ok(())
}

/// Many commits landing right after subscribe are each delivered exactly once,
/// in forward order, with NO row re-emitted. This guards the commit_seq gate:
/// before it, a stale/out-of-order broadcast event (a commit buffered ahead of
/// the subscribe-time cursor, or handed back behind a newer one) could open a
/// backwards `read_delta(from=newer, to=older)` window and re-emit the whole
/// history as duplicate INSERTs. Every appended id must appear exactly once
/// across the drained windows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rapid_commits_deliver_each_row_exactly_once() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    // Subscribe at "now" (empty table), then fire a burst of commits so several
    // events sit buffered in the broadcast ring at once.
    let mut s = t.changes(None).await?;
    let commits = 12;
    for i in 0..commits {
        t.append(&[batch(&[i as i64])?]).await?;
    }

    // Drain exactly `commits` windows and collect every delivered id.
    let mut seen: Vec<i64> = Vec::new();
    for _ in 0..commits {
        let w = timeout(T, s.next()).await?.expect("a window per commit")?;
        seen.extend(ids(&w));
    }
    seen.sort();
    let expect: Vec<i64> = (0..commits as i64).collect();
    assert_eq!(
        seen, expect,
        "each appended row delivered exactly once, forward-only, no re-emit"
    );

    #[cfg(feature = "testmatrix")]
    skade::functional_status(
        "skade/stream",
        "rapid_commits_deliver_each_row_exactly_once",
        true,
        "12-commit burst → 12 disjoint windows, no backwards re-emit (commit_seq gate)",
    );
    Ok(())
}

/// Restart from a persisted cursor delivers each row exactly once: the first
/// window's `to_snapshot` becomes the resume `from`, and the resumed stream's
/// first window covers only commits strictly after it — no re-delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_stream_resumes_exactly_once_after_restart() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    // Baseline commit A, then subscribe at "now" so A is NOT redelivered.
    t.append(&[batch(&[1, 2, 3])?]).await?;
    let mut s = t.changes(None).await?;

    // Commit B → one window; save the cursor after applying it.
    t.append(&[batch(&[4, 5])?]).await?;
    let wb = timeout(T, s.next()).await?.expect("window B")?;
    assert_eq!(ids(&wb), vec![4, 5]);
    let cursor = ConsumerCursor::after("main.events", &wb);
    assert!(cursor.snapshot_id.is_some());
    drop(s); // "restart"

    // Commit C happens while we're down.
    t.append(&[batch(&[6, 7])?]).await?;

    // Resume from the saved cursor: the catch-up window is ONLY C — B and A are
    // never re-delivered (exactly-once).
    let mut s2 = t.changes(cursor.snapshot_id).await?;
    let wc = timeout(T, s2.next()).await?.expect("resume window C")?;
    assert_eq!(
        ids(&wc),
        vec![6, 7],
        "resume delivers only rows after the cursor"
    );

    #[cfg(feature = "testmatrix")]
    skade::functional_status(
        "skade/stream",
        "change_stream_resumes_exactly_once_after_restart",
        true,
        "resume from cursor → only C {6,7}, no B/A re-delivery",
    );
    Ok(())
}
