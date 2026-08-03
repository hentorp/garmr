// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-store` — the storage facade: two stores plus the full-text index
//! behind one handle.
//!
//! - [`events`]: the skade lakehouse (Apache Iceberg over an embedded catalog)
//!   holding the columnar event history, queried with DataFusion SQL.
//! - [`state`]: an embedded redb database holding agent state — cases,
//!   detection memory, the budget ledger, registries, the environment model,
//!   and the rest of the per-domain tables (see [`state`]).
//! - the Tantivy [`SearchIndex`] (from `garmr-search`): opened read-only by
//!   [`Store::open`], or with the exclusive writer lock by
//!   [`Store::open_writable`] — which is also the single choke point that
//!   refuses a writable open on a restored-but-unpromoted node (Phase 13).
//!
//! [`Store`] bundles a clonable handle to each so the rest of garmr takes one
//! dependency.

pub mod events;
pub mod lock;
pub mod schema;
pub mod sql_guard;
pub mod state;

use garmr_core::{Config, Result};

pub use events::EventsHandle;
pub use garmr_search::SearchIndex;
pub use lock::{restored_marker_path, try_acquire_exclusion, WriterExclusion};
pub use sql_guard::reject_non_readonly;
pub use state::StateStore;

/// The combined storage facade: columnar events (SQL), embedded agent state,
/// and a full-text index (Lucene-class free-text search).
#[derive(Clone)]
pub struct Store {
    pub events: EventsHandle,
    pub state: StateStore,
    pub search: SearchIndex,
}

impl Store {
    /// Open read-only for search (reader, no Tantivy writer lock) — safe to run
    /// while `garmr serve` holds the writer. Events and state open normally.
    pub async fn open(cfg: &Config) -> Result<Self> {
        let search = SearchIndex::open_reader(&cfg.store.search_dir)?;
        Self::open_with(cfg, search).await
    }

    /// Open writable: acquires the exclusive full-text writer lock. Used by the
    /// ingest pipeline (`serve`) and every one-shot writer command (`replay`,
    /// `eval`, `learn`, `reflect`, `bundle import/rollback`).
    ///
    /// THE single choke point for Phase-13 invariant #2: a node restored from a
    /// backup carries a `<state_db>.restored` marker and MUST stay a read-only
    /// follower until an audited `garmr backup promote` clears it. Refusing here —
    /// not only in `serve` — means no writer path (scheduled or manual) can mutate
    /// a restored-but-unpromoted node. Read-only [`Store::open`] is unaffected.
    pub async fn open_writable(cfg: &Config) -> Result<Self> {
        let marker = lock::restored_marker_path(&cfg.store.state_db);
        let restored_err = || {
            garmr_core::Error::store(format!(
                "this node was restored from a backup and has NOT been promoted (marker {}) — run \
                 `garmr backup promote` before any writable open",
                marker.display()
            ))
        };
        if marker.exists() {
            return Err(restored_err());
        }
        let search = SearchIndex::open_writer(&cfg.store.search_dir)?
            .with_exclude_sources(cfg.store.fulltext_exclude_sources.clone());
        let store = Self::open_with(cfg, search).await?;
        // TOCTOU: re-check AFTER the writer + redb locks are held. A `backup
        // restore` that lands the marker between the first check and lock
        // acquisition must not leave this process running as a writer on a node
        // that just became a follower — refuse and drop the store.
        if marker.exists() {
            return Err(restored_err());
        }
        Ok(store)
    }

    async fn open_with(cfg: &Config, search: SearchIndex) -> Result<Self> {
        let state = StateStore::open(&cfg.store.state_db)?;
        let events = events::spawn(cfg, state.clone()).await?;
        Ok(Self {
            events,
            state,
            search,
        })
    }
}
