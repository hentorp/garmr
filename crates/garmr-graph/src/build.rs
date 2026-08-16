// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The `store`-backed graph builder (feature `store`): [`build`] pulls case
//! edges from the state store, then enriches best-effort from the event lake —
//! a wide-window host pass (every monitored host appears as a node, tagged
//! with a device type via `garmr_core::resolve_asset_role`), a DISTINCT
//! `(host, src_ip, user)` co-occurrence scan for event edges, and a
//! staff↔person register-lookup overlay. Each lake scan is time-boxed
//! ([`EVENT_QUERY_TIMEOUT`]); on timeout/failure the graph degrades to
//! case-only (`set_degraded`) instead of holding up an interactive pivot —
//! the lookup overlay just drops out without degrading.
//!
//! [`GraphCache`] wraps the build in a stale-while-revalidate cache: a fresh
//! entry returns at once, a stale one returns immediately and kicks a
//! single-flight background rebuild, and only the first-ever build blocks —
//! warmed at startup so pivots and the topology map never wait on the
//! multi-second wide-window scan. Explicit `?from/&to` / `?hours` windows go
//! through [`GraphCache::get_window`], a bounded per-window cache whose builds
//! are serialized on one lock (issue #23). [`TimeWindow`] is the
//! relative/absolute `event_ts` span the scans cover.

use std::time::Duration;

use garmr_core::Result;
use garmr_store::Store;
use skade::arrow_array::{Array, StringArray};

use crate::Graph;

/// Best-effort timeout for the event-edge scan — it must not hold up an
/// interactive pivot; on timeout/error the graph degrades to case-only.
const EVENT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// The time span a graph build scans over `event_ts` — either relative to now,
/// or an absolute `[from, to)` range. `Range` bounds are RFC3339 strings the
/// caller generates from parsed integers, never raw user input, so inlining them
/// into SQL is injection-safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimeWindow {
    LastHours(u64),
    Range { from: String, to: String },
}

impl TimeWindow {
    /// A SQL predicate over `event_ts` (no leading `AND`/`WHERE`).
    fn predicate(&self) -> String {
        match self {
            TimeWindow::LastHours(h) => format!("event_ts >= now() - INTERVAL '{h} hours'"),
            TimeWindow::Range { from, to } => {
                format!("event_ts >= '{from}' AND event_ts < '{to}'")
            }
        }
    }
}

/// Build the entity graph: case edges (always) plus event-co-occurrence edges
/// from DISTINCT `(host, src_ip, user)` seen in the last `event_hours` (capped
/// at `cap` distinct combinations). The event scan is best-effort — if it is
/// slow or fails, the returned graph still has every case edge. `exclude`
/// names high-volume "firehose" sources (e.g. an eBPF endpoint stream) to skip
/// in the lake scans — every host still appears via its other events, and the
/// scan finishes well under the timeout instead of degrading to case-only.
pub async fn build(
    store: &Store,
    event_window: TimeWindow,
    host_window: TimeWindow,
    cap: usize,
    exclude: &[String],
) -> Result<Graph> {
    let cases = store.state.list_cases()?;
    let mut g = Graph::from_cases(&cases);
    let event_pred = event_window.predicate();
    let host_pred = host_window.predicate();

    // `AND source NOT IN ('a','b')` (empty when nothing is excluded). Sources are
    // operator config, but single-quotes are escaped defensively all the same.
    let excl = if exclude.is_empty() {
        String::new()
    } else {
        let list = exclude
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" AND source NOT IN ({list})")
    };

    // Cheap pass: every monitored host as a node, ALL sources (firehose too),
    // over a WIDE window (≥14d — decoupled from the edge-scan window) so a host
    // seen anytime within retention still appears even if it's been quiet for
    // days or emits only firehose telemetry. Reading just the low-cardinality
    // `host` column + DISTINCT is fast — unlike the fields-regexp edge scan
    // below. Best-effort; on failure the case/event hosts still stand.
    // Also pull each host's DOMINANT (source, log_type) so we can tag it with a
    // device type (server/router/vault/cluster/…): grouped + ordered so the
    // first row per host is its most-common source/log_type. Still cheap (low-
    // cardinality columns). Best-effort; on failure hosts still appear untyped.
    let host_sql = format!(
        "SELECT host, source, log_type, count(*) AS n FROM events \
         WHERE {host_pred} \
           AND log_type NOT IN ('anomaly', 'risk', 'baseline') AND host <> '' \
         GROUP BY host, source, log_type ORDER BY host, n DESC \
         LIMIT {cap}"
    );
    if let Ok(Ok(batches)) =
        tokio::time::timeout(EVENT_QUERY_TIMEOUT, store.events.sql(host_sql)).await
    {
        // Trusted host-role facts from the environment model (Phase 5). Empty when
        // the model is off/unused, so the heuristic fallback below reproduces the
        // previous hardcoded classification exactly. A poisoned Candidate role can
        // never win — only Trusted facts are read.
        let trusted_roles: std::collections::HashMap<String, String> = store
            .state
            .list_env_facts(None, chrono::Utc::now())
            .unwrap_or_default()
            .into_iter()
            .filter(|f| {
                f.entity.kind == garmr_core::EntityKind::Host
                    && f.state == garmr_core::FactState::Trusted
                    && f.attribute == "role"
            })
            .map(|f| (f.entity.id, f.value))
            .collect();
        // Keep only the first (dominant) row per host — the ORDER BY put it first.
        let mut seen: std::collections::BTreeSet<String> = Default::default();
        for b in &batches {
            let hosts = b.column(0).as_any().downcast_ref::<StringArray>();
            let sources = b.column(1).as_any().downcast_ref::<StringArray>();
            let ltypes = b.column(2).as_any().downcast_ref::<StringArray>();
            let (Some(hosts), Some(sources), Some(ltypes)) = (hosts, sources, ltypes) else {
                continue;
            };
            for i in 0..b.num_rows() {
                let host = val(hosts, i);
                if host.is_empty() || !seen.insert(host.clone()) {
                    continue;
                }
                let dt = garmr_core::resolve_asset_role(
                    trusted_roles.get(&host).map(String::as_str),
                    &host,
                    &val(sources, i),
                    &val(ltypes, i),
                )
                .role;
                g.ensure_node_typed(crate::KIND_HOST, &host, &dt);
            }
        }
    }

    // DataFusion's regexp_replace returns the WHOLE input on no-match, which
    // would turn a row missing (or with an EMPTY) src_ip/user into a bogus node
    // = the entire fields blob. NULLIF(replace, fields) collapses that to NULL
    // (a real capture is a strict substring, never == fields), and `val` maps
    // NULL → "" → skipped. The LIKE in WHERE is just a perf pre-filter.
    let sql = format!(
        "SELECT DISTINCT host, \
           NULLIF(regexp_replace(fields, '.*\"src_ip\":\"([^\"]+)\".*', '$1'), fields) AS src_ip, \
           NULLIF(regexp_replace(fields, '.*\"user\":\"([^\"]+)\".*', '$1'), fields) AS usr \
         FROM events \
         WHERE {event_pred} \
           AND log_type NOT IN ('anomaly', 'risk', 'baseline') AND host <> ''{excl} \
           AND (fields LIKE '%\"src_ip\":%' OR fields LIKE '%\"user\":%') \
         LIMIT {cap}"
    );

    match tokio::time::timeout(EVENT_QUERY_TIMEOUT, store.events.sql(sql)).await {
        Ok(Ok(batches)) => {
            let mut triples = Vec::new();
            for b in &batches {
                let host = b.column(0).as_any().downcast_ref::<StringArray>();
                let ip = b.column(1).as_any().downcast_ref::<StringArray>();
                let usr = b.column(2).as_any().downcast_ref::<StringArray>();
                let (Some(host), Some(ip), Some(usr)) = (host, ip, usr) else {
                    continue;
                };
                // Keep extraction local to the graph build. Windowed API requests
                // can build concurrently, so spawning a per-batch worker set here
                // would multiply native threads across requests.
                for i in 0..b.num_rows() {
                    triples.push((val(host, i), val(ip, i), val(usr, i)));
                }
            }
            g.add_event_edges(&triples);
        }
        // Warn (not debug): a degraded graph silently omits low-and-slow event
        // links, so an operator scanning logs should see when it happened.
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "graph: event-edge scan failed — graph is case-only this build");
            g.set_degraded(true);
        }
        Err(_) => {
            tracing::warn!("graph: event-edge scan timed out — graph is case-only this build");
            g.set_degraded(true);
        }
    }

    // Register lookups: staff↔person "looked-up" edges straight from the raw
    // audit lookups, so who-looked-up-whom is graphable even with no case. A
    // best-effort supplement — on failure the case + event edges still stand
    // (no degrade flag, since this only omits the audit overlay).
    // Source-agnostic: the actor+subject field-presence already restricts this
    // to access-audit rows regardless of producer (postgres-audit, an app audit,
    // any feed), matching how staff_page/person_page scope purely by field.
    let lookup_sql = format!(
        "SELECT DISTINCT \
           NULLIF(regexp_replace(fields, '.*\"db_user\":\"([^\"]+)\".*', '$1'), fields) AS db_user, \
           NULLIF(regexp_replace(fields, '.*\"target_person\":\"([^\"]+)\".*', '$1'), fields) AS target_person \
         FROM events \
         WHERE {event_pred}{excl} \
           AND fields LIKE '%\"db_user\":%' AND fields LIKE '%\"target_person\":%' \
         LIMIT {cap}"
    );
    match tokio::time::timeout(EVENT_QUERY_TIMEOUT, store.events.sql(lookup_sql)).await {
        Ok(Ok(batches)) => {
            let mut pairs = Vec::new();
            for b in &batches {
                let du = b.column(0).as_any().downcast_ref::<StringArray>();
                let tp = b.column(1).as_any().downcast_ref::<StringArray>();
                let (Some(du), Some(tp)) = (du, tp) else {
                    continue;
                };
                for i in 0..b.num_rows() {
                    pairs.push((val(du, i), val(tp, i)));
                }
            }
            g.add_lookup_edges(&pairs);
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "graph: lookup-edge scan failed — register-lookup overlay omitted this build")
        }
        Err(_) => {
            tracing::warn!(
                "graph: lookup-edge scan timed out — register-lookup overlay omitted this build"
            )
        }
    }
    Ok(g)
}

/// The cached build: `(built_at, graph)`, shared so a background refresh can
/// swap it in while readers hold the old `Arc`.
type GraphSlot =
    std::sync::Arc<tokio::sync::Mutex<Option<(std::time::Instant, std::sync::Arc<Graph>)>>>;

/// One windowed-cache entry: the `(event_window, host_window)` pair that keyed
/// the build, when it was built, and the shared graph.
type WindowEntry = (
    TimeWindow,
    TimeWindow,
    std::time::Instant,
    std::sync::Arc<Graph>,
);

/// How many distinct explicit windows [`GraphCache::get_window`] keeps. Small on
/// purpose: the map UI offers a handful of presets, so anything past this is an
/// abusive or one-off caller and can pay the rebuild.
const MAX_WINDOW_ENTRIES: usize = 8;

/// A time-bounded cache so rapid successive pivots (an agent pivots several
/// times per triage; a UI user clicks around) reuse one build instead of
/// re-running the event scan each time.
pub struct GraphCache {
    ttl: Duration,
    event_hours: u64,
    cap: usize,
    exclude_sources: Vec<String>,
    inner: GraphSlot,
    /// Single-flight guard for the background refresh — only one rebuild runs at
    /// a time (a rebuild over a wide window is seconds of full-table scan).
    refreshing: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Explicit-window cache (issue #23): TTL-bounded entries keyed by the two
    /// scan windows, capped at [`MAX_WINDOW_ENTRIES`].
    windowed: tokio::sync::Mutex<Vec<WindowEntry>>,
    /// Serializes explicit-window builds: held across the lake scan so distinct
    /// user-supplied windows queue instead of running expensive scans
    /// concurrently, and identical windows coalesce on the double-checked
    /// lookup in [`get_window`](Self::get_window).
    window_build: tokio::sync::Mutex<()>,
}

impl GraphCache {
    pub fn new(ttl_secs: u64, event_hours: u64, cap: usize, exclude_sources: Vec<String>) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            event_hours,
            cap,
            exclude_sources,
            inner: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            refreshing: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            windowed: tokio::sync::Mutex::new(Vec::new()),
            window_build: tokio::sync::Mutex::new(()),
        }
    }

    /// The cached graph, **stale-while-revalidate**: a FRESH entry returns at
    /// once; a STALE one returns immediately too and kicks a background rebuild
    /// (single-flight) so no request ever blocks on the multi-second wide-window
    /// scan; only an EMPTY cache (first-ever build) awaits the build. Combined
    /// with [`warm`](Self::warm) at startup, the map is effectively always warm.
    pub async fn get(&self, store: &Store) -> Result<std::sync::Arc<Graph>> {
        let snapshot = self.inner.lock().await.clone();
        match snapshot {
            Some((at, graph)) if at.elapsed() < self.ttl => Ok(graph),
            Some((_, graph)) => {
                self.spawn_refresh(store);
                Ok(graph)
            }
            None => {
                let fresh = std::sync::Arc::new(self.build_now(store).await?);
                *self.inner.lock().await = Some((std::time::Instant::now(), fresh.clone()));
                Ok(fresh)
            }
        }
    }

    /// Kick a background build on startup so the first `get` is already warm
    /// (never blocks a user's first map open on the cold build).
    pub fn warm(&self, store: &Store) {
        self.spawn_refresh(store);
    }

    /// A cached graph for an explicit time window (issue #23). Before this,
    /// every `?from=&to=` / `?hours=` request ran its own uncached lake scan, so
    /// a caller spamming distinct windows could pile up concurrent multi-second
    /// full-table scans. Now a hit returns the cached graph, a miss builds under
    /// a global build lock (one windowed scan at a time), and identical windows
    /// that queued behind the first builder pick up its result from the
    /// double-checked lookup instead of re-scanning. Unlike [`get`](Self::get)
    /// there is no stale-while-revalidate: the caller asked for a specific
    /// window, so a cold miss legitimately waits for its build.
    pub async fn get_window(
        &self,
        store: &Store,
        event_window: TimeWindow,
        host_window: TimeWindow,
    ) -> Result<std::sync::Arc<Graph>> {
        let lookup = |slots: &[WindowEntry]| {
            window_lookup(
                slots,
                self.ttl,
                &event_window,
                &host_window,
                std::time::Instant::now(),
            )
        };
        if let Some(g) = lookup(&self.windowed.lock().await) {
            return Ok(g);
        }
        let _build_permit = self.window_build.lock().await;
        if let Some(g) = lookup(&self.windowed.lock().await) {
            return Ok(g);
        }
        let g = std::sync::Arc::new(
            build(
                store,
                event_window.clone(),
                host_window.clone(),
                self.cap,
                &self.exclude_sources,
            )
            .await?,
        );
        window_insert(
            &mut *self.windowed.lock().await,
            self.ttl,
            MAX_WINDOW_ENTRIES,
            event_window,
            host_window,
            g.clone(),
            std::time::Instant::now(),
        );
        Ok(g)
    }

    async fn build_now(&self, store: &Store) -> Result<Graph> {
        // Host floor: hosts seen anytime in ≥14d appear as nodes even if quiet,
        // decoupled from the (shorter) edge-scan window.
        let host_hours = self.event_hours.max(336);
        build(
            store,
            TimeWindow::LastHours(self.event_hours),
            TimeWindow::LastHours(host_hours),
            self.cap,
            &self.exclude_sources,
        )
        .await
    }

    fn spawn_refresh(&self, store: &Store) {
        use std::sync::atomic::Ordering;
        if self.refreshing.swap(true, Ordering::SeqCst) {
            return; // a rebuild is already in flight
        }
        let inner = self.inner.clone();
        let refreshing = self.refreshing.clone();
        let store = store.clone();
        let (event_hours, cap, exclude) =
            (self.event_hours, self.cap, self.exclude_sources.clone());
        tokio::spawn(async move {
            let host_hours = event_hours.max(336);
            match build(
                &store,
                TimeWindow::LastHours(event_hours),
                TimeWindow::LastHours(host_hours),
                cap,
                &exclude,
            )
            .await
            {
                Ok(g) => {
                    *inner.lock().await = Some((std::time::Instant::now(), std::sync::Arc::new(g)))
                }
                Err(e) => tracing::warn!(error = %e, "graph cache background rebuild failed"),
            }
            refreshing.store(false, Ordering::SeqCst);
        });
    }
}

/// Find a live windowed-cache entry for the exact `(event, host)` window pair.
/// `now` is passed in (rather than read) so the TTL logic is unit-testable.
fn window_lookup(
    slots: &[WindowEntry],
    ttl: Duration,
    event_window: &TimeWindow,
    host_window: &TimeWindow,
    now: std::time::Instant,
) -> Option<std::sync::Arc<Graph>> {
    slots
        .iter()
        .find(|(ew, hw, built_at, _)| {
            ew == event_window && hw == host_window && now.duration_since(*built_at) < ttl
        })
        .map(|(_, _, _, g)| g.clone())
}

/// Insert a windowed-cache entry, keeping the vec bounded: expired entries and
/// any stale entry for the same key go first, then the oldest (front) entries
/// until `max` holds. Insertion order is age order, so FIFO eviction suffices —
/// entries expire on the TTL long before recency ordering would matter.
fn window_insert(
    slots: &mut Vec<WindowEntry>,
    ttl: Duration,
    max: usize,
    event_window: TimeWindow,
    host_window: TimeWindow,
    graph: std::sync::Arc<Graph>,
    now: std::time::Instant,
) {
    slots.retain(|(ew, hw, built_at, _)| {
        now.duration_since(*built_at) < ttl && !(ew == &event_window && hw == &host_window)
    });
    while slots.len() >= max {
        slots.remove(0);
    }
    slots.push((event_window, host_window, now, graph));
}

fn val(a: &StringArray, i: usize) -> String {
    if a.is_valid(i) {
        a.value(i).to_string()
    } else {
        String::new()
    }
}

// The host-role heuristic lives once in garmr_core::domain (heuristic_role);
// build() resolves a device type via garmr_core::resolve_asset_role, which
// prefers a Trusted environment-model role fact and falls back to that heuristic.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{window_insert, window_lookup, TimeWindow, WindowEntry};
    use crate::Graph;

    const TTL: Duration = Duration::from_secs(300);

    fn win(h: u64) -> TimeWindow {
        TimeWindow::LastHours(h)
    }

    fn entry(ev_h: u64, host_h: u64, built_at: Instant) -> WindowEntry {
        (win(ev_h), win(host_h), built_at, Arc::new(Graph::default()))
    }

    #[test]
    fn lookup_hits_only_the_exact_live_key() {
        let now = Instant::now();
        let slots = vec![entry(24, 336, now)];
        // Exact pair hits; either window differing misses.
        assert!(window_lookup(&slots, TTL, &win(24), &win(336), now).is_some());
        assert!(window_lookup(&slots, TTL, &win(48), &win(336), now).is_none());
        assert!(window_lookup(&slots, TTL, &win(24), &win(400), now).is_none());
        // Range windows key on their exact bounds.
        let range = TimeWindow::Range {
            from: "2026-08-01T00:00:00Z".into(),
            to: "2026-08-02T00:00:00Z".into(),
        };
        let slots = vec![(
            range.clone(),
            range.clone(),
            now,
            Arc::new(Graph::default()),
        )];
        assert!(window_lookup(&slots, TTL, &range, &range, now).is_some());
    }

    #[test]
    fn lookup_misses_an_expired_entry() {
        let now = Instant::now();
        let slots = vec![entry(24, 336, now)];
        assert!(window_lookup(&slots, TTL, &win(24), &win(336), now + TTL).is_none());
        // Just inside the TTL still hits.
        let almost = now + TTL - Duration::from_secs(1);
        assert!(window_lookup(&slots, TTL, &win(24), &win(336), almost).is_some());
    }

    #[test]
    fn insert_replaces_the_same_key_and_drops_expired_entries() {
        // `base` is the oldest instant used, so no Instant subtraction is needed.
        let base = Instant::now();
        let now = base + TTL;
        let mut slots = vec![entry(24, 336, now), entry(48, 336, base)];
        // Re-inserting the (24, 336) key replaces its entry; the expired
        // (48, 336) entry is dropped in the same pass.
        window_insert(
            &mut slots,
            TTL,
            8,
            win(24),
            win(336),
            Arc::new(Graph::default()),
            now,
        );
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, win(24));
    }

    #[test]
    fn insert_evicts_the_oldest_at_the_bound() {
        let now = Instant::now();
        let mut slots: Vec<WindowEntry> = (0..8)
            .map(|i| entry(i + 1, 336, now + Duration::from_secs(i)))
            .collect();
        window_insert(
            &mut slots,
            TTL,
            8,
            win(100),
            win(336),
            Arc::new(Graph::default()),
            now + Duration::from_secs(8),
        );
        assert_eq!(slots.len(), 8);
        // The oldest (event window 1h) went; the newest is the inserted key.
        assert!(!slots.iter().any(|(ew, ..)| ew == &win(1)));
        assert_eq!(slots.last().unwrap().0, win(100));
    }
}
