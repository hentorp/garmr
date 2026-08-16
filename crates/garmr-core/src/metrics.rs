// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! A minimal Prometheus-compatible metrics registry.
//!
//! Hand-rolled rather than pulled from a crate: the exposition format is small
//! and stable, and garmr ships as one static binary an operator installs in an
//! air-gapped environment — every dependency here is one more thing to vendor,
//! audit and explain in the SBOM.
//!
//! What it does NOT do, deliberately: no exemplars, no native histograms, no
//! push gateway, no exporter-side aggregation. It emits the text exposition
//! format ([version 0.0.4]) that every Prometheus, VictoriaMetrics, Grafana
//! Alloy and OpenTelemetry collector can scrape.
//!
//! # Cardinality is a security boundary
//!
//! Label values that come from the network — a source name a shipper chose, a
//! collector id, a query string — can blow up the series count and take the
//! scraper down with the exporter. Every label family here is therefore
//! **bounded**: [`Family::with_limit`] admits at most `limit` distinct label
//! sets and counts the rest into an `_overflow` series, so an abusive producer
//! costs one extra series instead of unbounded memory. Never call
//! [`Family::unbounded`] with a value an untrusted party controls.
//!
//! [version 0.0.4]: https://prometheus.io/docs/instrumenting/exposition_formats/

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Metric kind, as emitted in the `# TYPE` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

/// A monotonic counter or a point-in-time gauge, addressed by label set.
///
/// Counters are `f64`-rendered but stored as `u64` (integral increments only),
/// which is what every garmr counter actually needs and keeps the atomics
/// lock-free. Gauges store a bit-cast `f64` so they can carry ratios and ages.
#[derive(Debug)]
pub struct Family {
    name: &'static str,
    help: &'static str,
    kind: Kind,
    /// `None` = unbounded (only for label sets garmr itself controls).
    limit: Option<usize>,
    series: Mutex<BTreeMap<Vec<(String, String)>, AtomicU64>>,
    /// Increments that did not fit under `limit`, rendered as `<name>_overflow`.
    overflow: AtomicU64,
}

impl Family {
    /// A family whose label sets come from garmr's own code (fixed strings), so
    /// the series count is bounded by construction.
    pub fn unbounded(name: &'static str, help: &'static str, kind: Kind) -> Self {
        Self {
            name,
            help,
            kind,
            limit: None,
            series: Mutex::new(BTreeMap::new()),
            overflow: AtomicU64::new(0),
        }
    }

    /// A family whose label values may come from outside (source names,
    /// collector ids). Admits at most `limit` distinct label sets; everything
    /// beyond that is counted into `<name>_overflow` and dropped.
    pub fn with_limit(name: &'static str, help: &'static str, kind: Kind, limit: usize) -> Self {
        Self {
            name,
            help,
            kind,
            limit: Some(limit),
            series: Mutex::new(BTreeMap::new()),
            overflow: AtomicU64::new(0),
        }
    }

    fn key(labels: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut k: Vec<(String, String)> = labels
            .iter()
            .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
            .collect();
        // Sorted so the same logical label set always hashes to one series,
        // whatever order a call site passes them in.
        k.sort();
        k
    }

    /// Add `n` to the series for `labels`. Over the cardinality limit the
    /// increment lands in the overflow series instead.
    pub fn add(&self, labels: &[(&str, &str)], n: u64) {
        let key = Self::key(labels);
        let mut series = self.series.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = series.get(&key) {
            v.fetch_add(n, Ordering::Relaxed);
            return;
        }
        if self.limit.is_some_and(|l| series.len() >= l) {
            self.overflow.fetch_add(n, Ordering::Relaxed);
            return;
        }
        series.insert(key, AtomicU64::new(n));
    }

    /// Increment by one.
    pub fn inc(&self, labels: &[(&str, &str)]) {
        self.add(labels, 1);
    }

    /// Set a gauge. Stores the `f64` bit pattern, so a gauge must never be read
    /// with counter semantics (the renderer keys off [`Kind`]).
    pub fn set(&self, labels: &[(&str, &str)], v: f64) {
        let key = Self::key(labels);
        let mut series = self.series.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = series.get(&key) {
            slot.store(v.to_bits(), Ordering::Relaxed);
            return;
        }
        if self.limit.is_some_and(|l| series.len() >= l) {
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        series.insert(key, AtomicU64::new(v.to_bits()));
    }

    /// Drop every series in this family. Used by scrape-time gauge refresh so a
    /// label set that has disappeared upstream (a decommissioned collector)
    /// stops being reported as a stale value forever.
    pub fn clear(&self) {
        self.series
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    fn render(&self, out: &mut String) {
        use std::fmt::Write as _;
        let series = self.series.lock().unwrap_or_else(|e| e.into_inner());
        let overflow = self.overflow.load(Ordering::Relaxed);
        if series.is_empty() && overflow == 0 {
            return;
        }
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} {}", self.name, self.kind.as_str());
        for (labels, value) in series.iter() {
            let raw = value.load(Ordering::Relaxed);
            let v = match self.kind {
                Kind::Gauge => f64::from_bits(raw),
                _ => raw as f64,
            };
            let _ = writeln!(out, "{}{} {}", self.name, render_labels(labels), fmt_f64(v));
        }
        if overflow > 0 {
            let _ = writeln!(
                out,
                "# HELP {}_overflow Increments dropped because the label-cardinality limit was reached.",
                self.name
            );
            let _ = writeln!(out, "# TYPE {}_overflow counter", self.name);
            let _ = writeln!(out, "{}_overflow {}", self.name, overflow);
        }
    }
}

/// A cumulative histogram with fixed buckets, rendered as `_bucket`/`_sum`/
/// `_count` triplets. One label set per histogram — garmr's timing sites are
/// per-endpoint, and a labelled histogram multiplies series by bucket count.
#[derive(Debug)]
pub struct Histogram {
    name: &'static str,
    help: &'static str,
    bounds: &'static [f64],
    /// One counter per bucket (non-cumulative; the renderer accumulates).
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    /// Sum of observations, as bit-cast `f64` under a mutex-free CAS loop.
    sum_bits: AtomicU64,
}

/// Default second-scale bounds for API latency: sub-millisecond through the
/// 30 s query timeout, so a timeout lands in the last finite bucket rather than
/// only in `+Inf`.
pub const LATENCY_BOUNDS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

impl Histogram {
    pub fn new(name: &'static str, help: &'static str, bounds: &'static [f64]) -> Self {
        Self {
            name,
            help,
            bounds,
            buckets: (0..bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_bits: AtomicU64::new(0f64.to_bits()),
        }
    }

    /// Record one observation (seconds, for the latency bounds).
    pub fn observe(&self, v: f64) {
        // Bounds are ascending, so the first bucket whose bound is >= v is the
        // one this observation belongs to; values past the last bound are
        // represented only in +Inf (rendered from `count`).
        if let Some(i) = self.bounds.iter().position(|b| v <= *b) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut cur = self.sum_bits.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(cur) + v).to_bits();
            match self.sum_bits.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    fn render(&self, out: &mut String) {
        use std::fmt::Write as _;
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return;
        }
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} histogram", self.name);
        let mut cumulative = 0u64;
        for (i, bound) in self.bounds.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{}_bucket{{le=\"{}\"}} {}",
                self.name,
                fmt_f64(*bound),
                cumulative
            );
        }
        let _ = writeln!(out, "{}_bucket{{le=\"+Inf\"}} {}", self.name, count);
        let _ = writeln!(
            out,
            "{}_sum {}",
            self.name,
            fmt_f64(f64::from_bits(self.sum_bits.load(Ordering::Relaxed)))
        );
        let _ = writeln!(out, "{}_count {}", self.name, count);
    }
}

/// Escape a label value per the exposition format: backslash, double quote and
/// newline. Without this a source name containing a quote produces a payload
/// the scraper rejects — and source names come from shippers.
fn escape(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            _ => s.push(c),
        }
    }
    s
}

fn render_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

/// Render a float the way the exposition format wants it: integers without a
/// decimal point, non-finite values as the literal Prometheus spellings.
fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    if v == v.trunc() && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    format!("{v}")
}

/// The process-wide metric set. Fields are public so call sites read as
/// `metrics::registry().ingest_events_total.inc(&[("source", s)])`.
#[derive(Debug)]
pub struct Registry {
    /// Build/version info as a labelled always-1 gauge (the standard idiom).
    pub build_info: Family,
    /// Which HA side this process is — a follower scrape must not be misread as
    /// a writer with dead ingest.
    pub ha_role: Family,
    /// Confirmed-lost sequence numbers per collector (scrape-time gauge).
    pub ingest_seq_gaps: Family,
    /// Outstanding (lost or in-flight) seqs per collector.
    pub ingest_seq_outstanding: Family,
    /// Replayed sequence numbers per collector.
    pub ingest_seq_replays: Family,
    /// Seconds since a collector's sequence state was last updated — the
    /// gone-dark signal.
    pub ingest_seq_age_seconds: Family,
    /// HTTP responses by path class and status class.
    pub http_responses_total: Family,
    /// API request latency.
    pub http_request_seconds: Histogram,
    /// Events received per ingest path (before dedup) — the raw offered load.
    pub ingest_received_total: Family,
    /// Events durably committed per ingest path (after dedup). received minus
    /// committed is dedup drops plus failures, each counted separately below.
    pub ingest_committed_total: Family,
    /// Batches NACKed (5xx / error status) per ingest path — what senders will
    /// retry. A rising rate here with flat commit is the store failing.
    pub ingest_nacked_total: Family,
    /// Duplicate events dropped by the at-least-once dedup, per ingest path.
    /// Routine at low volume (retries exist); a surge means a sender is
    /// re-shipping history.
    pub ingest_dedup_dropped_total: Family,
    /// Commit latency of the durable append (enqueue-to-ack).
    pub ingest_commit_seconds: Histogram,
    /// Depth of the pipeline channel at observation points. Sampled, not
    /// tracked per message: the channel's own len() at ingest time is the
    /// honest congestion signal and costs nothing.
    pub pipeline_channel_depth: Family,
    /// Sequence marks dropped because the observer queue was full — the
    /// silent-discard the gap analysis called out, now visible.
    pub ingest_seq_marks_dropped_total: Family,
    /// Compaction outcomes (label outcome=ok|failed).
    pub compaction_runs_total: Family,
    /// Full-text index failures (the indexer is best-effort off the ingest
    /// ack path, so its failures are otherwise invisible).
    pub fulltext_index_failures_total: Family,
    /// Seconds since a source last delivered an event (refreshed by a
    /// background task, NEVER on the scrape path — the refresh runs a
    /// warehouse query, and a scrape that contends with the single-permit
    /// read lane turns monitoring into an outage amplifier).
    pub source_staleness_seconds: Family,
    /// Per-source ingest lag: ingest_time minus event_ts, i.e. how far behind
    /// the pipeline is on that source's events.
    pub source_ingest_lag_seconds: Family,
    /// Events per source over the refresh window (a gauge, not a counter —
    /// the window slides).
    pub source_events_window: Family,
}

impl Registry {
    fn new() -> Self {
        // Collector ids are configured server-side, but the cap is cheap
        // insurance against a misconfiguration fanning out the series count.
        const COLLECTOR_CAP: usize = 256;
        Self {
            build_info: Family::unbounded(
                "garmr_build_info",
                "Build information; always 1, carrying version as a label.",
                Kind::Gauge,
            ),
            ha_role: Family::unbounded(
                "garmr_ha_role",
                "This node's HA role; always 1, carrying the role as a label.",
                Kind::Gauge,
            ),
            ingest_seq_gaps: Family::with_limit(
                "garmr_ingest_seq_gaps",
                "Confirmed-lost ingest sequence numbers per collector.",
                Kind::Gauge,
                COLLECTOR_CAP,
            ),
            ingest_seq_outstanding: Family::with_limit(
                "garmr_ingest_seq_outstanding",
                "Ingest sequence numbers below the high-water mark not yet seen (lost or in flight).",
                Kind::Gauge,
                COLLECTOR_CAP,
            ),
            ingest_seq_replays: Family::with_limit(
                "garmr_ingest_seq_replays",
                "Replayed ingest sequence numbers per collector.",
                Kind::Gauge,
                COLLECTOR_CAP,
            ),
            ingest_seq_age_seconds: Family::with_limit(
                "garmr_ingest_seq_age_seconds",
                "Seconds since this collector's sequence state last advanced.",
                Kind::Gauge,
                COLLECTOR_CAP,
            ),
            http_responses_total: Family::with_limit(
                "garmr_http_responses_total",
                "HTTP responses by route class and status class.",
                Kind::Counter,
                512,
            ),
            http_request_seconds: Histogram::new(
                "garmr_http_request_seconds",
                "API request latency in seconds.",
                LATENCY_BOUNDS,
            ),
            // The ingest path label is one of a FIXED set garmr itself names
            // (native, ndjson, loki, syslog, flight) — bounded by construction,
            // but capped anyway: a cap that is never hit costs nothing, and one
            // that is hit is a bug report.
            ingest_received_total: Family::with_limit(
                "garmr_ingest_received_total",
                "Events received per ingest path, before dedup.",
                Kind::Counter,
                16,
            ),
            ingest_committed_total: Family::with_limit(
                "garmr_ingest_committed_total",
                "Events durably committed per ingest path, after dedup.",
                Kind::Counter,
                16,
            ),
            ingest_nacked_total: Family::with_limit(
                "garmr_ingest_nacked_total",
                "Batches NACKed (sender will retry) per ingest path.",
                Kind::Counter,
                16,
            ),
            ingest_dedup_dropped_total: Family::with_limit(
                "garmr_ingest_dedup_dropped_total",
                "Duplicate events dropped by at-least-once dedup, per ingest path.",
                Kind::Counter,
                16,
            ),
            ingest_commit_seconds: Histogram::new(
                "garmr_ingest_commit_seconds",
                "Durable-append commit latency in seconds.",
                LATENCY_BOUNDS,
            ),
            pipeline_channel_depth: Family::with_limit(
                "garmr_pipeline_channel_depth",
                "Sampled depth of the pipeline channel at observation points.",
                Kind::Gauge,
                8,
            ),
            ingest_seq_marks_dropped_total: Family::with_limit(
                "garmr_ingest_seq_marks_dropped_total",
                "Sequence marks dropped because the observer queue was full.",
                Kind::Counter,
                4,
            ),
            compaction_runs_total: Family::with_limit(
                "garmr_compaction_runs_total",
                "Compaction runs by outcome.",
                Kind::Counter,
                4,
            ),
            fulltext_index_failures_total: Family::with_limit(
                "garmr_fulltext_index_failures_total",
                "Full-text indexing failures (best-effort path).",
                Kind::Counter,
                4,
            ),
            // Source names are SHIPPER-INFLUENCED (a collector asserts its
            // source), so the cardinality cap is load-bearing here, not
            // insurance: an abusive shipper minting source names costs one
            // overflow series, never scraper memory.
            source_staleness_seconds: Family::with_limit(
                "garmr_source_staleness_seconds",
                "Seconds since this source last delivered an event.",
                Kind::Gauge,
                256,
            ),
            source_ingest_lag_seconds: Family::with_limit(
                "garmr_source_ingest_lag_seconds",
                "Ingest lag (ingest_time - event_ts) for this source's newest events.",
                Kind::Gauge,
                256,
            ),
            source_events_window: Family::with_limit(
                "garmr_source_events_window",
                "Events from this source in the refresh window.",
                Kind::Gauge,
                256,
            ),
        }
    }

    /// The full exposition payload.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        self.build_info.render(&mut out);
        self.ha_role.render(&mut out);
        self.ingest_seq_gaps.render(&mut out);
        self.ingest_seq_outstanding.render(&mut out);
        self.ingest_seq_replays.render(&mut out);
        self.ingest_seq_age_seconds.render(&mut out);
        self.http_responses_total.render(&mut out);
        self.http_request_seconds.render(&mut out);
        self.ingest_received_total.render(&mut out);
        self.ingest_committed_total.render(&mut out);
        self.ingest_nacked_total.render(&mut out);
        self.ingest_dedup_dropped_total.render(&mut out);
        self.ingest_commit_seconds.render(&mut out);
        self.pipeline_channel_depth.render(&mut out);
        self.ingest_seq_marks_dropped_total.render(&mut out);
        self.compaction_runs_total.render(&mut out);
        self.fulltext_index_failures_total.render(&mut out);
        self.source_staleness_seconds.render(&mut out);
        self.source_ingest_lag_seconds.render(&mut out);
        self.source_events_window.render(&mut out);
        out
    }
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// The process-wide registry, created on first use.
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_renders_with_sorted_labels_and_type_lines() {
        let f = Family::unbounded("garmr_test_total", "A test counter.", Kind::Counter);
        f.inc(&[("b", "2"), ("a", "1")]);
        f.add(&[("a", "1"), ("b", "2")], 4);
        let mut s = String::new();
        f.render(&mut s);
        assert!(s.contains("# TYPE garmr_test_total counter"), "{s}");
        // Same logical label set regardless of call-site order → one series at 5.
        assert!(s.contains("garmr_test_total{a=\"1\",b=\"2\"} 5"), "{s}");
        assert_eq!(s.matches("garmr_test_total{").count(), 1, "{s}");
    }

    #[test]
    fn an_empty_family_renders_nothing() {
        // A HELP/TYPE header with no series is legal but noisy; more importantly
        // it would make an unused metric look like a reported zero.
        let f = Family::unbounded("garmr_unused", "Never touched.", Kind::Counter);
        let mut s = String::new();
        f.render(&mut s);
        assert!(s.is_empty());
    }

    #[test]
    fn cardinality_limit_diverts_to_overflow_instead_of_growing() {
        let f = Family::with_limit("garmr_capped", "Bounded.", Kind::Counter, 2);
        for i in 0..10 {
            f.inc(&[("source", &format!("s{i}"))]);
        }
        let mut s = String::new();
        f.render(&mut s);
        // Two admitted series, the other eight increments in one overflow series.
        assert_eq!(s.matches("garmr_capped{").count(), 2, "{s}");
        assert!(s.contains("garmr_capped_overflow 8"), "{s}");
    }

    #[test]
    fn label_values_are_escaped() {
        let f = Family::unbounded("garmr_esc", "Escaping.", Kind::Counter);
        // A shipper-chosen source name containing a quote and a backslash would
        // otherwise emit a payload the scraper rejects outright.
        f.inc(&[("source", "we\"ird\\path")]);
        let mut s = String::new();
        f.render(&mut s);
        assert!(s.contains(r#"source="we\"ird\\path""#), "{s}");
    }

    #[test]
    fn gauge_round_trips_a_fractional_value() {
        let f = Family::unbounded("garmr_ratio", "A ratio.", Kind::Gauge);
        f.set(&[], 0.25);
        let mut s = String::new();
        f.render(&mut s);
        assert!(s.contains("garmr_ratio 0.25"), "{s}");
        // Setting again replaces rather than accumulating.
        f.set(&[], 0.5);
        let mut s2 = String::new();
        f.render(&mut s2);
        assert!(s2.contains("garmr_ratio 0.5"), "{s2}");
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_carry_sum_and_count() {
        let h = Histogram::new("garmr_lat_seconds", "Latency.", LATENCY_BOUNDS);
        h.observe(0.003); // falls in le=0.005
        h.observe(0.2); // falls in le=0.25
        h.observe(60.0); // past the last bound → only +Inf
        let mut s = String::new();
        h.render(&mut s);
        assert!(
            s.contains("garmr_lat_seconds_bucket{le=\"0.005\"} 1"),
            "{s}"
        );
        // Cumulative: the 0.25 bucket includes the 0.003 observation too.
        assert!(s.contains("garmr_lat_seconds_bucket{le=\"0.25\"} 2"), "{s}");
        assert!(s.contains("garmr_lat_seconds_bucket{le=\"+Inf\"} 3"), "{s}");
        assert!(s.contains("garmr_lat_seconds_count 3"), "{s}");
        assert!(s.contains("garmr_lat_seconds_sum 60.203"), "{s}");
    }

    #[test]
    fn exposition_grammar_holds_for_the_whole_registry() {
        let r = Registry::new();
        r.build_info.set(&[("version", "0.1.0")], 1.0);
        r.ha_role.set(&[("role", "writer")], 1.0);
        r.ingest_seq_gaps.set(&[("collector", "pve")], 0.0);
        r.http_responses_total
            .inc(&[("route", "/api/query"), ("status", "2xx")]);
        r.http_request_seconds.observe(0.01);
        let out = r.render();

        // Every metric line must be `name[{labels}] value`, every value parseable,
        // and each family must be preceded by its TYPE line. A hand-rolled
        // exposition that is subtly wrong makes dashboards lie silently.
        let mut typed: Vec<&str> = Vec::new();
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                typed.push(rest.split(' ').next().unwrap());
                continue;
            }
            if line.starts_with("# HELP ") {
                continue;
            }
            assert!(!line.is_empty(), "no blank lines in the payload");
            let (series, value) = line.rsplit_once(' ').expect("metric line has a value");
            assert!(
                value.parse::<f64>().is_ok() || value == "+Inf" || value == "NaN",
                "unparseable value in {line:?}"
            );
            let base = series.split('{').next().unwrap();
            let family = base
                .trim_end_matches("_bucket")
                .trim_end_matches("_sum")
                .trim_end_matches("_count");
            assert!(
                typed.iter().any(|t| *t == base || *t == family),
                "{base} emitted without a preceding TYPE line"
            );
            if let Some(labels) = series.split_once('{') {
                assert!(
                    labels.1.ends_with('}'),
                    "unterminated label set in {line:?}"
                );
            }
        }
        assert!(
            out.contains("garmr_build_info{version=\"0.1.0\"} 1"),
            "{out}"
        );
        assert!(out.contains("garmr_ha_role{role=\"writer\"} 1"), "{out}");
    }
}
