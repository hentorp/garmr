// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The read-only query API on `serve`.
//!
//! The embedded store is single-process, so you can't point a second CLI at it
//! while the daemon runs. Instead the daemon exposes a small localhost HTTP API
//! over its own in-process store — this is how you query garmr *while* it
//! ingests (the same model as Splunk/Elastic: query the service, not the raw
//! index files). A browser, `curl`, a future facett UI, or a CLI-over-HTTP all
//! consume it. Everything here is strictly read-only.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use garmr_core::Config;
use garmr_store::Store;
use serde_json::{json, Value};
use skade::arrow_array::RecordBatch;
use skade::arrow_cast::display::array_value_to_string;

type ApiResult = std::result::Result<Json<Value>, (StatusCode, String)>;

/// Hard caps so a single request can't OOM or wedge the daemon.
const MAX_SEARCH_LIMIT: usize = 1000;
/// Cap synchronous Tantivy scorers so timed-out searches cannot accumulate in
/// Tokio's blocking pool. Permits are held by the blocking closure itself.
const MAX_CONCURRENT_SEARCHES: usize = 2;
const MAX_QUERY_ROWS: usize = 5000;
const QUERY_TIMEOUT_SECS: u64 = 30;
/// Cold queries thaw + decompress archives before scanning — allow longer.
const COLD_QUERY_TIMEOUT_SECS: u64 = 120;

mod admin;
mod appaudit;
mod applications;
mod auth;
mod behavioral;
mod capabilities;
mod config;
// pub(crate) so the offline `garmr recover` command can reuse CredentialStore.
pub(crate) mod credentials;
mod env;
mod explain;
mod feedback;
mod hsearch;
mod llm;
mod passkey;
mod policies;
mod query;
mod registry;
mod resources;
mod secrets;
mod security;
#[cfg(feature = "semantic")]
mod semantic;
mod serve;
mod setup;
mod shadow;
mod users;
mod views;

use auth::check_admin;
pub use serve::{check_bind_auth, serve};

/// Shared state for the handlers: the in-process store plus the config (the
/// cold-query route needs `retention.cold_dir`), the bearer token that
/// authenticates the admin surface (when enabled), and a Matrix handle so
/// silence changes are announced on the alerts room — a stolen admin token
/// must not be a *silent* notification kill-switch.
#[derive(Clone)]
struct ApiState {
    store: Store,
    search_permits: std::sync::Arc<tokio::sync::Semaphore>,
    cfg: Config,
    /// RBAC token→principal registry (bearer/basic secret → named principal with
    /// an ordered role). Resolves the read-surface gate and the admin check.
    auth: std::sync::Arc<garmr_core::AuthRegistry>,
    /// Scoped machine API credentials (issued/rotated/revoked at runtime),
    /// consulted after the static env-token registry misses.
    creds: credentials::CredentialStore,
    matrix: Option<std::sync::Arc<garmr_agent::Matrix>>,
    /// Time-bounded entity-graph cache shared across pivots.
    graph_cache: std::sync::Arc<garmr_graph::GraphCache>,
    /// Passkey (WebAuthn) login state, present when `GARMR_WEBAUTHN_RP_ID` is
    /// set; `None` keeps the surface token-only as before.
    webauthn: Option<std::sync::Arc<passkey::Webauthn>>,
    /// Tamper-evident audit ledger; `None` when `audit.enabled=false`.
    audit: Option<std::sync::Arc<garmr_audit::AuditLedger>>,
    /// The live application-audit plane (Phase 7/8), shared with the pipeline so
    /// the admin surface promotes/suspects the SAME in-memory baselines the
    /// detectors query. `None` when `detect.app_audit_enabled=false`.
    app_audit: Option<std::sync::Arc<crate::appaudit::AppAudit>>,
    /// This node's HA role: `true` = a read-only follower (writes/LLM/admin
    /// unmounted); `false` = the writer/leader. Surfaced by `/api/ha/status`.
    read_only: bool,
    /// Live semantic-search state (model + vector index), present when the
    /// `semantic` feature is built and GARMR_EMBED_MODEL is set.
    #[cfg(feature = "semantic")]
    semantic: Option<SemanticHandle>,
}

impl ApiState {
    /// Record a protected administrative decision to the audit ledger,
    /// **fail-closed**: when auditing is on and the durable write fails, this
    /// returns a 500 that the handler propagates with `?`, so the state change is
    /// not acknowledged without a durable audit record (the outbox invariant). A
    /// no-op (returns `Ok`) when auditing is disabled.
    fn record_admin(
        &self,
        who: &garmr_core::Principal,
        action: &str,
        object_type: &str,
        object_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<Option<String>, (StatusCode, String)> {
        self.record_change("admin_session", who, action, object_type, object_id, reason)
    }

    /// Fail-closed audit of an analyst-tier decision/feedback write. Same
    /// contract as [`record_admin`] but tagged as a writer session; returns the
    /// audit id so the appended record can reference it.
    fn record_decision(
        &self,
        who: &garmr_core::Principal,
        action: &str,
        object_type: &str,
        object_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<Option<String>, (StatusCode, String)> {
        self.record_change(
            "writer_session",
            who,
            action,
            object_type,
            object_id,
            reason,
        )
    }

    /// Shared fail-closed audit write for a protected change. Returns the audit
    /// id (`None` when auditing is disabled); on a durable-write failure returns
    /// a 500 so the caller aborts before the state change is acknowledged.
    fn record_change(
        &self,
        auth_method: &str,
        who: &garmr_core::Principal,
        action: &str,
        object_type: &str,
        object_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<Option<String>, (StatusCode, String)> {
        let Some(ledger) = &self.audit else {
            return Ok(None);
        };
        let mut rec = garmr_audit::AuditRecord::new(action, object_type)
            .actor(
                garmr_audit::ActorType::Human,
                who.user.clone(),
                Some(&format!("{:?}", who.role)),
            )
            .auth_method(auth_method)
            .outcome(garmr_audit::Outcome::Success)
            .policy(garmr_audit::PolicyDecision::Allowed);
        if let Some(id) = object_id {
            rec = rec.object_id(id);
        }
        if let Some(r) = reason {
            rec = rec.reason(r);
        }
        ledger.append(rec).map(|receipt| Some(receipt.audit_id)).map_err(|e| {
            tracing::error!(error = %e, action, "audit append failed — refusing action (fail closed)");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit ledger unavailable".to_string(),
            )
        })
    }

    /// Record a REFUSED environment promotion best-effort (a blocked attempt is
    /// evidence, not a silent no-op; the refusal itself already protects the
    /// invariant, so a dropped audit line here does not change the outcome).
    fn record_env_denied(&self, who: &garmr_core::Principal, fact_id: &str, blocks: &str) {
        let Some(ledger) = &self.audit else {
            return;
        };
        let rec =
            garmr_audit::AuditRecord::new(garmr_audit::action::ENV_PROMOTE_DENIED, "env_fact")
                .actor(
                    garmr_audit::ActorType::Human,
                    who.user.clone(),
                    Some(&format!("{:?}", who.role)),
                )
                .auth_method("admin_session")
                .outcome(garmr_audit::Outcome::Denied)
                .policy(garmr_audit::PolicyDecision::Denied)
                .object_id(fact_id)
                .reason(blocks);
        if let Err(e) = ledger.append(rec) {
            tracing::warn!(error = %e, "audit append for a denied env promotion dropped (best-effort)");
        }
    }
}

/// Shared handle to the embedding model + the in-serve vector index (kept fresh
/// by a background rebuild task off the concurrent read lane).
#[cfg(feature = "semantic")]
#[derive(Clone)]
struct SemanticHandle {
    embedder: std::sync::Arc<garmr_embed::Embedder>,
    index: std::sync::Arc<tokio::sync::RwLock<garmr_embed::VectorStore>>,
}

fn bad(msg: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_string())
}
/// Classify an admin-action error: caller mistakes (unknown/ambiguous id,
/// already decided) surface as 400 with their message; everything else —
/// filesystem, store — is a server fault and goes through the opaque 500.
fn admin_err(e: garmr_core::Error) -> (StatusCode, String) {
    let msg = e.to_string();
    if msg.contains("match")
        || msg.contains("already")
        || msg.contains("empty")
        || msg.contains("multiple")
    {
        bad(msg)
    } else {
        oops(e)
    }
}
/// Log the real error server-side; return an opaque message so an
/// unauthenticated client can't enumerate schema/paths from error text.
fn oops(msg: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::warn!(error = %msg, "query API error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
}

/// Render Arrow record batches to JSON row objects (every cell stringified —
/// good enough for a query/inspection surface; typed columns are a follow-up).
/// Caps at `max_rows` so a `SELECT *` over a 90-day lakehouse can't materialise
/// the whole corpus into one response (OOM). Returns `(rows, truncated)`.
fn batches_to_json(batches: &[RecordBatch], max_rows: usize) -> (Vec<Value>, bool) {
    let mut out = Vec::new();
    for b in batches {
        let names: Vec<String> = b
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        for row in 0..b.num_rows() {
            if out.len() >= max_rows {
                return (out, true);
            }
            let mut obj = serde_json::Map::new();
            for (col, name) in names.iter().enumerate() {
                let v = array_value_to_string(b.column(col), row).unwrap_or_default();
                obj.insert(name.clone(), Value::String(v));
            }
            out.push(Value::Object(obj));
        }
    }
    (out, false)
}

/// Default page size for the list endpoints — high enough that today's consoles
/// (which filter client-side) still see the whole set, but bounded so a list
/// response can never be unbounded as case / finding / registry volume grows.
/// Callers page explicitly with `?limit=&offset=`.
const DEFAULT_PAGE_LIMIT: usize = 1000;
const MAX_PAGE_LIMIT: usize = 5000;

/// Parsed `?limit=&offset=` bounds for a list endpoint (see [`Page::envelope`]).
pub(super) struct Page {
    limit: usize,
    offset: usize,
}

impl Page {
    /// Read `?limit=` (clamped to `[1, MAX_PAGE_LIMIT]`, default
    /// `DEFAULT_PAGE_LIMIT`) and `?offset=` (default 0) from the query map.
    fn from_query(p: &HashMap<String, String>) -> Self {
        let limit = p
            .get("limit")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT);
        let offset = p
            .get("offset")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        Page { limit, offset }
    }

    /// Slice `items` to this page under `key`, plus a stable pagination envelope
    /// (`total` / `returned` / `limit` / `offset` / `has_more`). The array stays
    /// under `key` so existing consumers keep reading it unchanged; a paginating
    /// client reads `total` / `has_more` to know there is more. An `offset` past
    /// the end yields an empty page (never a panic).
    fn envelope<T: serde::Serialize>(&self, key: &str, items: Vec<T>) -> Value {
        let total = items.len();
        let start = self.offset.min(total);
        let end = self.offset.saturating_add(self.limit).min(total);
        let page = &items[start..end];
        json!({
            key: page,
            "total": total,
            "returned": page.len(),
            "limit": self.limit,
            "offset": self.offset,
            "has_more": end < total,
        })
    }
}

#[cfg(test)]
mod page_tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn default_page_returns_everything_up_to_the_cap() {
        let items: Vec<i32> = (0..10).collect();
        let v = Page::from_query(&q(&[])).envelope("items", items);
        assert_eq!(v["total"], 10);
        assert_eq!(v["returned"], 10);
        assert_eq!(v["has_more"], false);
        assert_eq!(v["items"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn limit_and_offset_slice_and_flag_more() {
        let items: Vec<i32> = (0..10).collect();
        let v = Page::from_query(&q(&[("limit", "3"), ("offset", "2")])).envelope("items", items);
        assert_eq!(v["total"], 10);
        assert_eq!(v["returned"], 3);
        assert_eq!(v["offset"], 2);
        assert_eq!(v["has_more"], true);
        assert_eq!(v["items"], serde_json::json!([2, 3, 4]));
    }

    #[test]
    fn offset_past_the_end_is_an_empty_page_not_a_panic() {
        let items: Vec<i32> = (0..3).collect();
        let v = Page::from_query(&q(&[("offset", "99")])).envelope("items", items);
        assert_eq!(v["total"], 3);
        assert_eq!(v["returned"], 0);
        assert_eq!(v["has_more"], false);
        assert_eq!(v["items"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn limit_is_clamped_to_the_hard_cap() {
        let v = Page::from_query(&q(&[("limit", "999999")]));
        assert_eq!(v.limit, MAX_PAGE_LIMIT);
        // A garbage limit falls back to the default, not zero.
        let v = Page::from_query(&q(&[("limit", "abc")]));
        assert_eq!(v.limit, DEFAULT_PAGE_LIMIT);
    }
}
