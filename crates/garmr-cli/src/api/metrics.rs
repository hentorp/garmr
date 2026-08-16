// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /metrics` (Prometheus exposition) and `GET /ready` (readiness probe).
//!
//! Two endpoints with deliberately different auth stances:
//!
//! - **`/metrics` is authenticated.** A scrape names every configured collector,
//!   the HA role, and the shape of the estate — a posture leak that also tells an
//!   attacker which source to impersonate or silence. Prometheus carries a bearer
//!   token per scrape job (`authorization` in `scrape_configs`), so this costs
//!   the operator one config line and closes a real disclosure.
//! - **`/ready` is public**, like `/health`. A load balancer or Kubernetes
//!   probe cannot hold a credential, and the response is a single bit plus a
//!   fixed reason string — nothing an unauthenticated caller can mine.
//!
//! `/health` (existing) is liveness: the process answers. `/ready` is readiness:
//! the store is actually queryable. A restored-but-unpromoted node, or one whose
//! state store will not open, is alive but must not receive traffic.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garmr_core::metrics::{self, registry};

use super::ApiState;

/// Content type for the Prometheus text exposition format, version 0.0.4.
const EXPOSITION_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// GET /metrics — the exposition payload.
///
/// Point-in-time gauges are refreshed here rather than being written on the hot
/// path: the values come from state the store already maintains, so a scrape is
/// a read of existing structures, and no ingest-path work is spent maintaining a
/// metric nobody may ever scrape.
pub(super) async fn metrics(State(st): State<ApiState>) -> Response {
    refresh_scrape_time_gauges(&st);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, EXPOSITION_CONTENT_TYPE)],
        registry().render(),
    )
        .into_response()
}

/// Refresh the gauges that are derived from persisted state at scrape time.
///
/// Every per-collector family is cleared first: a collector that has been
/// decommissioned must stop being reported, otherwise its last value is
/// exported forever and a "gone dark" alert on it can never clear (or, worse,
/// never fires because the stale sample looks healthy).
fn refresh_scrape_time_gauges(st: &ApiState) {
    let r = registry();

    r.build_info.clear();
    r.build_info
        .set(&[("version", env!("CARGO_PKG_VERSION"))], 1.0);

    // A follower serves reads only. Without this label a follower's scrape —
    // zero ingest, zero detections — reads exactly like a writer that has died.
    r.ha_role.clear();
    let role = if st.read_only { "follower" } else { "writer" };
    r.ha_role.set(&[("role", role)], 1.0);

    let health = match st.store.state.ingest_seq_health() {
        Ok(h) => h,
        Err(e) => {
            // Surfacing partial metrics beats failing the scrape: the rest of the
            // payload is still true, and a silent gap in one family is visible in
            // Prometheus as a stale series rather than a dead target.
            tracing::warn!(error = %e, "metrics: ingest sequence health unavailable this scrape");
            return;
        }
    };
    r.ingest_seq_gaps.clear();
    r.ingest_seq_outstanding.clear();
    r.ingest_seq_replays.clear();
    r.ingest_seq_age_seconds.clear();
    let now_us = chrono::Utc::now().timestamp_micros();
    for h in &health {
        let labels = [("collector", h.collector_id.as_str())];
        r.ingest_seq_gaps.set(&labels, h.gaps as f64);
        r.ingest_seq_outstanding.set(&labels, h.outstanding as f64);
        r.ingest_seq_replays.set(&labels, h.replays as f64);
        // Age, not the raw timestamp: an alert wants "silent for 10 minutes",
        // and a bare epoch would force every rule to do the subtraction.
        let age_s = (now_us.saturating_sub(h.updated_us)) as f64 / 1_000_000.0;
        r.ingest_seq_age_seconds.set(&labels, age_s.max(0.0));
    }
}

/// GET /ready — readiness. 200 when this node can serve reads, 503 otherwise.
///
/// The probe is deliberately cheap and bounded: it touches the state store,
/// which is the dependency whose absence makes every read fail. It does NOT run
/// a warehouse query — a readiness probe that scans the lake would take the node
/// out of rotation exactly when it is busiest, which is the classic way a probe
/// turns a slowdown into an outage.
pub(super) async fn ready(State(st): State<ApiState>) -> Response {
    match st.store.state.ingest_seq_health() {
        Ok(_) => (StatusCode::OK, "ready\n").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe failed: state store unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready: state store\n").into_response()
        }
    }
}

/// Middleware: time every request and record it against its ROUTE TEMPLATE.
///
/// The label comes from axum's [`MatchedPath`] — `/api/cases/:id`, never the
/// concrete `/api/cases/9f3c…`. That distinction is the whole cardinality
/// story: a per-id label would let any caller mint unbounded series by varying
/// the path, which is a denial-of-service against the scraper as much as
/// against garmr.
///
/// An unmatched request (a 404 against no route) is recorded as `"unmatched"`
/// for the same reason — the requested path is attacker-chosen text.
pub(super) async fn track_layer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use axum::extract::MatchedPath;
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let started = std::time::Instant::now();
    let res = next.run(req).await;
    record_response(&route, res.status().as_u16(), started.elapsed());
    res
}

/// Record one API response for the HTTP families.
///
/// `route` must be a ROUTE TEMPLATE (`/api/cases/:id`), never a concrete path:
/// a per-id label is unbounded cardinality driven by the caller. Status is
/// bucketed to its class for the same reason.
fn record_response(route: &str, status: u16, elapsed: std::time::Duration) {
    let class = match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    let r = registry();
    r.http_responses_total
        .inc(&[("route", route), ("status", class)]);
    r.http_request_seconds.observe(elapsed.as_secs_f64());
    let _ = metrics::LATENCY_BOUNDS;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_bucket_into_classes() {
        // Cardinality: 5 classes, not 60-odd codes, and never a per-request id.
        for (code, want) in [
            (200u16, "2xx"),
            (204, "2xx"),
            (301, "3xx"),
            (401, "4xx"),
            (404, "4xx"),
            (500, "5xx"),
            (503, "5xx"),
        ] {
            record_response("/api/test", code, std::time::Duration::from_millis(1));
            let out = registry().render();
            assert!(
                out.contains(&format!("status=\"{want}\"")),
                "code {code} should render as {want}: {out}"
            );
        }
    }

    #[test]
    fn the_exposition_content_type_is_the_004_text_format() {
        // Prometheus negotiates on this exact string; a wrong charset or version
        // makes some scrapers fall back to protobuf and fail the target.
        assert_eq!(
            EXPOSITION_CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }

    #[test]
    fn the_shipped_alert_rules_reference_only_real_metrics() {
        // The drift guard for docs/operations/garmr-alerts.rules.yml: an alert
        // whose metric was renamed silently never fires — the worst kind of
        // monitoring, present and useless. Touch every family, render, and
        // assert every metric name the rules reference exists in the payload.
        let r = registry();
        r.build_info.set(&[("version", "t")], 1.0);
        r.ha_role.set(&[("role", "writer")], 1.0);
        r.ingest_seq_gaps.set(&[("collector", "c")], 0.0);
        r.ingest_seq_outstanding.set(&[("collector", "c")], 0.0);
        r.ingest_seq_replays.set(&[("collector", "c")], 0.0);
        r.ingest_seq_age_seconds.set(&[("collector", "c")], 0.0);
        r.http_responses_total
            .inc(&[("route", "/t"), ("status", "2xx")]);
        r.http_request_seconds.observe(0.01);
        r.ingest_received_total.inc(&[("path", "native")]);
        r.ingest_committed_total.inc(&[("path", "native")]);
        r.ingest_nacked_total.inc(&[("path", "native")]);
        r.ingest_dedup_dropped_total.inc(&[("path", "store")]);
        r.ingest_commit_seconds.observe(0.01);
        r.pipeline_channel_depth.set(&[("channel", "ingest")], 1.0);
        r.ingest_seq_marks_dropped_total
            .inc(&[("observer", "ingest")]);
        r.compaction_runs_total.inc(&[("outcome", "ok")]);
        r.fulltext_index_failures_total.inc(&[("stage", "live")]);
        r.source_staleness_seconds.set(&[("source", "s")], 1.0);
        r.source_ingest_lag_seconds.set(&[("source", "s")], 1.0);
        r.source_events_window.set(&[("source", "s")], 1.0);
        let payload = r.render();

        let rules = include_str!("../../../../docs/operations/garmr-alerts.rules.yml");
        let mut missing = Vec::new();
        for cap in rules.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if !cap.starts_with("garmr_") {
                continue;
            }
            // Histogram series render as _bucket/_sum/_count of the base name.
            let base = cap
                .trim_end_matches("_bucket")
                .trim_end_matches("_sum")
                .trim_end_matches("_count");
            if !payload.contains(base) {
                missing.push(cap.to_string());
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "alert rules reference metrics the registry does not export: {missing:?}"
        );

        // And the dashboard's queries too — same failure mode, same guard.
        let dash = include_str!("../../../../docs/operations/grafana-garmr.json");
        let mut missing = Vec::new();
        for cap in dash.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if !cap.starts_with("garmr_") {
                continue;
            }
            let base = cap
                .trim_end_matches("_bucket")
                .trim_end_matches("_sum")
                .trim_end_matches("_count");
            if !payload.contains(base) {
                missing.push(cap.to_string());
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "dashboard queries reference metrics the registry does not export: {missing:?}"
        );
    }
}
