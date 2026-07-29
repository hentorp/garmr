// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The read-only tool surface the agent may call.
//!
//! Every tool here is read-only — the worst outcome of a prompt injection in a
//! log line is an unwanted *read*, never an action (the Hermes safety stance).
//! `submit_verdict` is the terminal tool: the loop intercepts it rather than
//! dispatching it here.
//!
//! This module is the [`ToolBox`] executor (dispatch + the per-tool handlers).
//! The rest is split into siblings: [`schemas`] (the tool catalog offered to the
//! model), [`guard`] (the SQL read-only AST check + LIKE escaping), and
//! [`render`] (Arrow-batch → text rendering + case summaries). The three
//! peel-off items keep their old crate paths via the re-exports below.

use std::collections::HashMap;
use std::sync::Arc;

use garmr_store::Store;
use serde_json::Value;
use skade::arrow_array::RecordBatch;

use crate::baseline;

mod guard;
mod render;
mod schemas;

pub use guard::reject_non_readonly;
pub use render::format_batches;
pub use schemas::tool_schemas;

use guard::like_escape;
use render::summarize_case;

const MAX_ROWS: usize = 50;

/// Executes read-only tools against the store. Never panics — tool errors are
/// returned as text so the model can recover and finish its verdict.
/// Render a hybrid-search result for the agent: one line per event tagged with
/// which signals matched (`[S]`tructured / `[F]`ull-text / `[V]` semantic).
fn render_hybrid(res: &garmr_query::HybridResult) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if matches!(
        res.semantic_status,
        garmr_query::SemanticStatus::RequestedButUnavailable
    ) {
        out.push_str(
            "(note: semantic clause requested but no semantic model is available — \
             ranked on structured + full-text only)\n",
        );
    }
    if res.items.is_empty() {
        out.push_str("(no matches)\n");
    }
    for it in &res.items {
        let tags: String = it.provenance.iter().map(|p| p.signal.tag()).collect();
        let when = chrono::DateTime::from_timestamp_micros(it.ts_micros)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        let msg: String = it.message.chars().take(200).collect();
        let _ = writeln!(
            out,
            "[{tags}] {when} {}/{} {} — {msg}",
            it.host, it.service, it.severity
        );
    }
    if res.truncated {
        out.push_str("[… more results truncated]\n");
    }
    out
}

pub struct ToolBox {
    store: Store,
    rules: Arc<HashMap<String, String>>,
    enricher: Arc<garmr_enrich::Enricher>,
    /// The shared semantic backend for `hybrid_search` (Phase 11). Bound once by
    /// the daemon with the SAME embedder + index the ask HTTP path uses, so the
    /// model loads once (a 1-2 vCPU box can't afford a second 128 MB load). Unset
    /// in every one-shot caller and until the model finishes loading — a semantic
    /// clause is then honestly reported unavailable, never silently dropped. Set
    /// through `&self` so it survives the `Arc` the agent is wrapped in.
    sem: std::sync::OnceLock<Arc<dyn garmr_query::SemanticSearch>>,
}

impl ToolBox {
    pub fn new(
        store: Store,
        rules: Arc<HashMap<String, String>>,
        enricher: Arc<garmr_enrich::Enricher>,
    ) -> Self {
        Self {
            store,
            rules,
            enricher,
            sem: std::sync::OnceLock::new(),
        }
    }

    /// The shared IP enricher — so a serve loop can hot-refresh its IOC set.
    pub fn enricher(&self) -> Arc<garmr_enrich::Enricher> {
        self.enricher.clone()
    }

    /// Bind the shared semantic backend so `hybrid_search` runs its semantic
    /// clause. Serve-only, idempotent (first set wins); one-shot callers leave it
    /// unset. Takes `&self` so it works through the `Arc` the agent holds.
    pub fn set_semantic(&self, sem: Arc<dyn garmr_query::SemanticSearch>) {
        let _ = self.sem.set(sem);
    }

    /// The bound shared semantic backend, if any — so a hunt (which builds its own
    /// ToolBox) can be handed the SAME embedder the triage agent uses.
    pub fn semantic(&self) -> Option<Arc<dyn garmr_query::SemanticSearch>> {
        self.sem.get().cloned()
    }

    /// Dispatch a non-terminal tool call. `submit_verdict` is handled by the
    /// loop, not here. Returns `(output, is_error)` so the agent can flag the
    /// tool_result correctly instead of making the model infer failure from a
    /// text prefix.
    pub async fn dispatch(&self, name: &str, input: &Value) -> (String, bool) {
        let r = match name {
            "query_events" => self.query_events(input).await,
            "search_events" => self.search_events(input).await,
            "hybrid_search" => self.hybrid_search(input).await,
            "get_host_baseline" => self.get_host_baseline(input).await,
            "ip_reputation" => self.ip_reputation(input).await,
            "domain_reputation" => self.domain_reputation(input).await,
            "get_rule" => Ok(self.get_rule(input)),
            "search_cases" => self.search_cases(input),
            "pivot_entity" => self.pivot_entity(input).await,
            other => Err(format!("unknown tool: {other}")),
        };
        match r {
            Ok(out) => (out, false),
            Err(e) => (format!("ERROR: {e}"), true),
        }
    }

    /// All agent SQL is time-bounded: an LLM-issued query must not hold a triage
    /// for minutes, and every reader must finish inside the compaction GC grace
    /// window (default 300s) or it may lose its files mid-stream.
    async fn bounded_sql(&self, sql: &str) -> std::result::Result<Vec<RecordBatch>, String> {
        const TOOL_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        match tokio::time::timeout(TOOL_QUERY_TIMEOUT, self.store.events.sql(sql)).await {
            Ok(r) => r.map_err(|e| e.to_string()),
            Err(_) => Err(format!(
                "the query took >{}s and was aborted",
                TOOL_QUERY_TIMEOUT.as_secs()
            )),
        }
    }

    async fn query_events(&self, input: &Value) -> std::result::Result<String, String> {
        let sql = input
            .get("sql")
            .and_then(Value::as_str)
            .ok_or("missing sql")?;
        reject_non_readonly(sql)?;
        let batches = self.bounded_sql(sql).await?;
        Ok(format_batches(&batches))
    }

    async fn search_events(&self, input: &Value) -> std::result::Result<String, String> {
        let text = input
            .get("text")
            .and_then(Value::as_str)
            .ok_or("missing text")?;
        let hours = input.get("hours").and_then(Value::as_f64).unwrap_or(24.0);
        // Escape LIKE metacharacters so the search is a literal substring — a
        // bare `%`/`_` in the query must match itself, not "anything".
        let needle = like_escape(text);
        let sql = format!(
            "SELECT event_ts, host, service, message FROM events \
             WHERE message ILIKE '%{needle}%' ESCAPE '\\' \
             AND event_ts >= now() - INTERVAL '{hours} hours' \
             ORDER BY event_ts DESC LIMIT {MAX_ROWS}"
        );
        let batches = self.bounded_sql(&sql).await?;
        Ok(format_batches(&batches))
    }

    /// Hybrid retrieval: parse the typed Query IR and run the safe executor
    /// (structured + full-text + semantic, fused with provenance). The daemon
    /// binds a shared semantic backend at startup; when it hasn't (a one-shot
    /// caller, or before the model finishes loading), a semantic clause is
    /// honestly reported unavailable rather than dropped.
    async fn hybrid_search(&self, input: &Value) -> std::result::Result<String, String> {
        let q: garmr_query::HybridQuery = serde_json::from_value(input.clone())
            .map_err(|e| format!("invalid hybrid query: {e}"))?;
        let sem = self.sem.get().map(|s| s.as_ref());
        let res = garmr_query::Executor::run(&self.store, &q, sem)
            .await
            .map_err(|e| e.to_string())?;
        Ok(render_hybrid(&res))
    }

    async fn get_host_baseline(&self, input: &Value) -> std::result::Result<String, String> {
        let host = input
            .get("host")
            .and_then(Value::as_str)
            .ok_or("missing host")?;
        // Same bound as bounded_sql — the baseline is three aggregate scans.
        match tokio::time::timeout(
            std::time::Duration::from_secs(60),
            baseline::describe(&self.store, host),
        )
        .await
        {
            Ok(r) => r.map_err(|e| e.to_string()),
            Err(_) => Err("the baseline queries took >60s and were aborted".into()),
        }
    }

    /// Link-analysis pivot over the entity graph (host↔ip↔user↔case): everything
    /// connected to an entity within `depth` hops, via adjudicated cases AND raw
    /// event co-occurrence (each hit tagged case/event). Read-only, in-memory.
    async fn pivot_entity(&self, input: &Value) -> std::result::Result<String, String> {
        let kind = input
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("missing kind (host|ip|user|case)")?;
        let name = input
            .get("name")
            .and_then(Value::as_str)
            .ok_or("missing name")?;
        let depth = input
            .get("depth")
            .and_then(Value::as_u64)
            .unwrap_or(2)
            .clamp(1, 6) as usize;
        let graph = garmr_graph::build(
            &self.store,
            garmr_graph::TimeWindow::LastHours(168),
            garmr_graph::TimeWindow::LastHours(336),
            50_000,
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        let start = garmr_graph::node_id(kind, name);
        if !graph.contains(&start) {
            return Ok(format!("No entity {start} in the graph."));
        }
        let reached = graph.pivot(&start, depth);
        if reached.is_empty() {
            return Ok(format!(
                "{start} exists but is isolated (no linked entities)."
            ));
        }
        let mut by_kind: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
        for h in &reached {
            let (n, hop, via) = (h.node, h.hop, h.via.as_str());
            let item = if n.kind == garmr_graph::KIND_CASE {
                format!(
                    "{}({}, {hop}h/{via})",
                    n.name.get(..8).unwrap_or(&n.name),
                    n.label
                )
            } else {
                format!("{}({hop}h/{via})", n.name)
            };
            by_kind.entry(n.kind.as_str()).or_default().push(item);
        }
        let mut out = format!("Linked to {start} (depth {depth}, via case/event):\n");
        for (k, items) in by_kind {
            out.push_str(&format!("  {k}: {}\n", items.join(", ")));
        }
        // Attack paths: the riskiest reachable cases, ranked (level × verdict).
        let ranked = graph.rank_paths(&start, depth);
        if !ranked.is_empty() {
            out.push_str("Risky attack paths (ranked):\n");
            for rp in ranked.iter().take(3) {
                let route: Vec<&str> = rp.path.iter().map(String::as_str).collect();
                out.push_str(&format!("  {:.1}  {}\n", rp.score, route.join(" → ")));
            }
        }
        if graph.degraded() {
            out.push_str("(event edges were skipped this run — may miss raw-activity links)\n");
        }
        Ok(out)
    }

    async fn ip_reputation(&self, input: &Value) -> std::result::Result<String, String> {
        let ip = input
            .get("ip")
            .and_then(Value::as_str)
            .ok_or("missing ip")?;
        // Require a real IP: this both makes the lookup meaningful and ensures
        // the value carries no LIKE metacharacters (a valid address has no
        // `%`/`_`), so the sightings query can't be widened by a crafted arg.
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("invalid IP: {ip}"));
        }
        let e = self.enricher.lookup(ip);
        let escaped = ip.replace('\'', "''");
        let sql = format!(
            "SELECT count(*) AS n, min(event_ts) AS first_seen, max(event_ts) AS last_seen \
             FROM events WHERE fields LIKE '%\"src_ip\":\"{escaped}\"%'"
        );
        let sightings = match self.bounded_sql(&sql).await {
            Ok(b) => format_batches(&b),
            Err(e) => format!("(could not count sightings: {e})"),
        };
        let ioc = if e.is_ioc() {
            format!("YES — on IOC list '{}'", e.ioc_source)
        } else {
            "no (not on any loaded IOC list)".to_string()
        };
        let geo = match (e.country.is_empty(), e.asn.is_empty()) {
            (true, true) => "(no GeoIP data loaded)".to_string(),
            _ => format!("country={} asn={}", e.country, e.asn),
        };
        Ok(format!(
            "IP {ip}\nprivate (RFC1918/loopback): {}\nGeoIP: {geo}\nIOC: {ioc}\nsightings in the logs:\n{sightings}",
            e.private
        ))
    }

    async fn domain_reputation(&self, input: &Value) -> std::result::Result<String, String> {
        let raw = input
            .get("domain")
            .and_then(Value::as_str)
            .ok_or("missing domain")?;
        let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        // Constrain to a hostname charset before it goes near SQL: a real domain
        // is [a-z0-9.-] only, so a crafted value can't carry LIKE metacharacters
        // (`%`/`_`) or a quote to widen/break the sightings query below.
        if domain.is_empty()
            || domain.len() > 253
            || !domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || !domain.contains('.')
        {
            return Err(format!("invalid domain name: {raw}"));
        }
        let ioc = match self.enricher.domain_ioc(&domain) {
            Some(src) => format!("YES — on threat-data list '{src}'"),
            None => "no (not on any loaded domain IOC list)".to_string(),
        };
        // Sightings: DNS queries for this exact domain in the stored events.
        // `domain` is already charset-validated (no LIKE metachars / quotes).
        let sql = format!(
            "SELECT count(*) AS n, min(event_ts) AS first_seen, max(event_ts) AS last_seen \
             FROM events WHERE fields LIKE '%\"dns\":\"{domain}\"%'"
        );
        let sightings = match self.bounded_sql(&sql).await {
            Ok(b) => format_batches(&b),
            Err(e) => format!("(could not count sightings: {e})"),
        };
        Ok(format!(
            "Domain {domain}\nIOC: {ioc}\nsightings in the DNS logs:\n{sightings}"
        ))
    }

    fn get_rule(&self, input: &Value) -> String {
        let id = input.get("rule_id").and_then(Value::as_str).unwrap_or("");
        self.rules
            .get(id)
            .cloned()
            .unwrap_or_else(|| format!("no rule with id {id} loaded"))
    }

    fn search_cases(&self, input: &Value) -> std::result::Result<String, String> {
        let q = input
            .get("query")
            .and_then(Value::as_str)
            .ok_or("missing query")?;
        let cases = self
            .store
            .state
            .search_cases(q)
            .map_err(|e| e.to_string())?;
        if cases.is_empty() {
            return Ok("No previous cases matched.".into());
        }
        let mut out = String::new();
        for c in cases.iter().take(10) {
            out.push_str(&summarize_case(c));
            out.push('\n');
        }
        Ok(out)
    }
}