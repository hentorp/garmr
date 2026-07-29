//! Streaming CDC consume — push, not poll (feature `stream`).
//!
//! Today a CDC consumer polls `commit_seq()` then `read_delta`. This module
//! inverts that to a **push**: [`Table::changes`] returns a live stream of
//! [`ChangelogBatch`] windows driven by skade-katalog's commit broadcast
//! ([`RedbCatalog::subscribe_commits`]) — a producer→consumer hop is
//! sub-millisecond locally (no Kafka, no network). A commit for this table wakes
//! the stream, which reads the changelog from the consumer's last cursor to the
//! freshly-committed snapshot and yields it.
//!
//! **Resilience.** The broadcast is a low-latency *hint*; if a subscriber lags
//! and the ring drops events (`RecvError::Lagged`), the stream catches up by
//! re-reading to the table's current snapshot (the durable catalog is the
//! truth), so no change is lost. [`Table::changes_polling`] is the same stream
//! with no broadcast at all — a pure timer poll, for a build/consumer that
//! doesn't want the push path.
//!
//! **Exactly-once resume.** A window's [`ChangelogBatch::to_snapshot`] is the
//! resume cursor. Persist it in a [`ConsumerCursor`]; restart with
//! `changes(cursor.snapshot_id)` and the first window covers exactly the rows
//! after that snapshot — `read_delta`'s strictly-after semantics mean no row is
//! delivered twice.

use std::time::Duration;

use futures::stream::{BoxStream, StreamExt};
use iceberg::Catalog as _;
use skade_katalog::RedbCatalog;
use tokio::sync::broadcast::error::RecvError;

use crate::error::Result;
use crate::read::{ChangelogBatch, read_changelog};
use crate::table::Table;

/// A durable, resumable CDC cursor for one table: the offset a consumer persists
/// so it can restart exactly where it left off. `snapshot_id` is the resume key
/// ([`ChangelogBatch::to_snapshot`] of the last applied window); `commit_seq`
/// mirrors the catalog's global cursor when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerCursor {
    /// `"namespace.table"` the cursor tracks.
    pub table: String,
    /// The last snapshot the consumer fully applied — pass as `from` on resume.
    pub snapshot_id: Option<i64>,
    /// The catalog `commit_seq` at that point, when known (0 otherwise).
    pub commit_seq: u64,
}

impl ConsumerCursor {
    /// The cursor after fully applying `batch`: advance to its `to_snapshot`.
    pub fn after(table: impl Into<String>, batch: &ChangelogBatch) -> Self {
        ConsumerCursor {
            table: table.into(),
            snapshot_id: Some(batch.to_snapshot),
            commit_seq: 0,
        }
    }
}

/// A live changelog stream for one table: each item is a CDC window from the
/// consumer's last cursor to a freshly-committed snapshot.
#[async_trait::async_trait]
pub trait ChangeStream {
    /// Yield CDC windows as the table advances. `from = None` starts at "now"
    /// (only future commits); `from = Some(s)` first emits the catch-up window
    /// `read_changelog(s, current)` and then tails live commits.
    async fn changes(
        &self,
        from: Option<i64>,
    ) -> Result<BoxStream<'static, Result<ChangelogBatch>>>;
}

/// Load the table's latest state and read the changelog window `(from, to]`.
async fn window(
    catalog: &RedbCatalog,
    ident: &iceberg::TableIdent,
    from: Option<i64>,
    to: i64,
) -> Result<ChangelogBatch> {
    let table = catalog.load_table(ident).await?;
    read_changelog(&table, from, to).await
}

/// The current snapshot id of the table's latest state.
async fn current_snapshot(
    catalog: &RedbCatalog,
    ident: &iceberg::TableIdent,
) -> Result<Option<i64>> {
    let table = catalog.load_table(ident).await?;
    Ok(table.metadata().current_snapshot().map(|s| s.snapshot_id()))
}

/// Push-stream driver state (owned, so the stream is `'static`).
struct PushState {
    catalog: std::sync::Arc<RedbCatalog>,
    ident: iceberg::TableIdent,
    table_key: String,
    /// The last snapshot yielded (the running cursor).
    last: Option<i64>,
    /// The monotonic global `commit_seq` up to which events are already
    /// accounted for. Freshness is keyed off this — NOT snapshot-id identity —
    /// so a stale/out-of-order broadcast event (a commit buffered before the
    /// subscribe-time cursor, or delivered behind a newer one) can never open a
    /// backwards changelog window that re-emits history. Only an event with
    /// `commit_seq > last_seq` is fresh.
    last_seq: u64,
    /// A catch-up window computed at subscribe time, yielded first.
    pending: Option<ChangelogBatch>,
    rx: tokio::sync::broadcast::Receiver<skade_katalog::CommitEvent>,
}

/// Poll-stream driver state.
struct PollState {
    catalog: std::sync::Arc<RedbCatalog>,
    ident: iceberg::TableIdent,
    last: Option<i64>,
    interval: tokio::time::Interval,
}

#[async_trait::async_trait]
impl ChangeStream for Table {
    async fn changes(
        &self,
        from: Option<i64>,
    ) -> Result<BoxStream<'static, Result<ChangelogBatch>>> {
        let catalog = self.catalog().clone();
        let ident = self.ident().clone();
        let table_key = catalog.commit_table_key(&ident);

        // Subscribe BEFORE reading current, so a commit racing the subscribe is
        // delivered on the channel rather than lost. `cursor` is the durable
        // global `commit_seq` at subscribe time: every event with
        // `commit_seq > cursor` is guaranteed to flow through `rx`, and every
        // event with `commit_seq <= cursor` is already reflected in `cur`
        // below — so gating live events on `> last_seq` (seeded from `cursor`)
        // both de-dups the subscribe-window race and enforces forward-only
        // progress even when the broadcast ring hands us buffered events out of
        // snapshot order.
        let (cursor, rx) = catalog.subscribe_commits().await?;
        let cur = current_snapshot(&catalog, &ident).await?;

        // Initialise the cursor + optional catch-up window.
        let (last, pending) = match from {
            Some(s) => {
                let pending = match cur {
                    Some(c) if c != s => Some(window(&catalog, &ident, Some(s), c).await?),
                    _ => None,
                };
                (cur.or(Some(s)), pending)
            }
            None => (cur, None),
        };

        let state = PushState {
            catalog,
            ident,
            table_key,
            last,
            last_seq: cursor,
            pending,
            rx,
        };

        let stream = futures::stream::unfold(state, |mut st| async move {
            loop {
                // Drain the subscribe-time catch-up window first.
                if let Some(w) = st.pending.take() {
                    return Some((Ok(w), st));
                }
                match st.rx.recv().await {
                    Ok(ev) => {
                        if ev.table_key.as_ref() != st.table_key {
                            continue; // another table's commit
                        }
                        // Forward-only: an event at or below the seq we've
                        // already accounted for is stale (buffered before the
                        // cursor, or delivered out of order behind a newer
                        // commit). Skipping it is what prevents a backwards
                        // `read_delta(from=newer, to=older)` re-emitting history.
                        if ev.commit_seq <= st.last_seq {
                            continue;
                        }
                        st.last_seq = ev.commit_seq; // this table's commit is fresh — advance
                        let sid = match ev.snapshot_id {
                            Some(s) if Some(s) != st.last => s,
                            _ => continue, // snapshot-less commit: seq advanced, no window
                        };
                        match window(&st.catalog, &st.ident, st.last, sid).await {
                            Ok(w) => {
                                st.last = Some(sid);
                                return Some((Ok(w), st));
                            }
                            Err(e) => return Some((Err(e), st)),
                        }
                    }
                    // Lagged: the durable catalog is the truth — catch up to the
                    // current snapshot in one window.
                    Err(RecvError::Lagged(_)) => {
                        // The ring dropped events: jump the seq cursor to the
                        // catalog's durable global `commit_seq` so the stale
                        // events still buffered behind us can't reopen a
                        // backwards window once we resume draining `rx`.
                        if let Ok(seq) = st.catalog.commit_seq().await {
                            st.last_seq = st.last_seq.max(seq);
                        }
                        match current_snapshot(&st.catalog, &st.ident).await {
                            Ok(Some(c)) if Some(c) != st.last => {
                                match window(&st.catalog, &st.ident, st.last, c).await {
                                    Ok(w) => {
                                        st.last = Some(c);
                                        return Some((Ok(w), st));
                                    }
                                    Err(e) => return Some((Err(e), st)),
                                }
                            }
                            Ok(_) => continue,
                            Err(e) => return Some((Err(e), st)),
                        }
                    }
                    Err(RecvError::Closed) => return None,
                }
            }
        });

        Ok(stream.boxed())
    }
}

impl Table {
    /// Poll-only changelog stream — the same [`ChangeStream`] semantics with **no
    /// broadcast** (a build/consumer that prefers polling, or where the producer
    /// runs in another process). Every `poll_interval` it re-reads the table's
    /// current snapshot and yields a window whenever it advanced. `from` behaves
    /// as in [`ChangeStream::changes`].
    pub async fn changes_polling(
        &self,
        from: Option<i64>,
        poll_interval: Duration,
    ) -> Result<BoxStream<'static, Result<ChangelogBatch>>> {
        let catalog = self.catalog().clone();
        let ident = self.ident().clone();

        let cur = current_snapshot(&catalog, &ident).await?;
        let (last, pending) = match from {
            Some(s) => {
                let pending = match cur {
                    Some(c) if c != s => Some(window(&catalog, &ident, Some(s), c).await?),
                    _ => None,
                };
                (cur.or(Some(s)), pending)
            }
            None => (cur, None),
        };

        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let state = PollState {
            catalog,
            ident,
            last,
            interval,
        };

        // Yield the catch-up window first (if any), then poll.
        let head = futures::stream::iter(pending.map(Ok));
        let tail = futures::stream::unfold(state, |mut st| async move {
            loop {
                st.interval.tick().await;
                match current_snapshot(&st.catalog, &st.ident).await {
                    Ok(Some(c)) if Some(c) != st.last => {
                        match window(&st.catalog, &st.ident, st.last, c).await {
                            Ok(w) => {
                                st.last = Some(c);
                                return Some((Ok(w), st));
                            }
                            Err(e) => return Some((Err(e), st)),
                        }
                    }
                    Ok(_) => continue, // no advance yet — keep polling
                    Err(e) => return Some((Err(e), st)),
                }
            }
        });

        Ok(head.chain(tail).boxed())
    }
}
