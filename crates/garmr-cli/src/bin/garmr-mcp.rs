// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-mcp` — exposes a running garmr daemon over the Model Context Protocol.
//!
//! An MCP (stdio) server that registers garmr's READ + ASK surface as tools, so
//! an LLM agent (Claude Code / Desktop) can drive investigations directly:
//! search, SQL, tail, cases, entity pages, graph pivot, risk, ATT&CK coverage,
//! semantic search, and the natural-language `ask`. It is a thin client — every
//! tool proxies to `garmr serve`'s authenticated HTTP API. It deliberately
//! exposes NO write/admin surface (no silence/approve/deny), so it never holds
//! the admin token: propose≠act extends to the agent driving garmr too.
//!
//! Wire into Claude Code (against a running daemon):
//!   claude mcp add garmr \
//!     --env GARMR_API_URL=http://127.0.0.1:3110 \
//!     --env GARMR_API_TOKEN=<token> -- garmr-mcp
//!
//! Config (env): GARMR_API_URL (default http://127.0.0.1:3110), GARMR_API_TOKEN.

use std::time::Duration;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde_json::Value;

#[derive(Clone)]
struct GarmrServer {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
    // Populated by `#[tool_router]` and consumed by the `#[tool_handler]`-generated
    // `ServerHandler` glue. Clippy's dead-code pass doesn't follow that generated
    // path (it only sees the derived `Clone`), so it wrongly flags the field.
    #[allow(dead_code)]
    tool_router: ToolRouter<GarmrServer>,
}

// ---- tool argument shapes (doc comments become the JSON-schema descriptions) --

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SearchArgs {
    /// Full-text query over event messages (Tantivy syntax: terms, "phrases", AND/OR/NOT).
    query: String,
    /// Max hits to return (default 20).
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SemanticArgs {
    /// Natural-language description of what to find (matches on MEANING, not keywords).
    query: String,
    /// Max hits to return (default 20).
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SqlArgs {
    /// Read-only SQL over the `events` table (DataFusion). SELECT/aggregate only;
    /// results are capped. Columns: event_ts, host, service, source, severity,
    /// log_type, message, environment, fields (JSON string).
    sql: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct TailArgs {
    /// How many of the most recent events to return (default 100).
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CaseArgs {
    /// Case id (a prefix is accepted).
    id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EntityArgs {
    /// Entity kind: `host`, `ip`, or `user`.
    kind: String,
    /// Entity name (a hostname, IP address, or username).
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PivotArgs {
    /// Start-node kind: `host`, `ip`, `user`, or `case`.
    kind: String,
    /// Start-node name.
    name: String,
    /// BFS hop depth (default 2, max 6).
    #[serde(default)]
    depth: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AskArgs {
    /// A question in natural language. garmr's agent plans a read-only query,
    /// runs it, and answers grounded in the rows with [n] citations. Costs real
    /// model spend (daily-budget-capped); prefer `search`/`query` for simple lookups.
    question: String,
}

#[tool_router]
impl GarmrServer {
    fn new() -> Self {
        let base = std::env::var("GARMR_API_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:3110".to_string())
            .trim_end_matches('/')
            .to_string();
        let token = std::env::var("GARMR_API_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        // `ask` can take up to ~180s server-side; keep the total above that, but
        // a short connect timeout so a black-hole host fails fast (not after 200s).
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(200))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");
        Self {
            http,
            base,
            token,
            tool_router: Self::tool_router(),
        }
    }

    /// GET `path` with optional query params, returning parsed JSON.
    async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, McpError> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.http.get(&url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if !query.is_empty() {
            req = req.query(query);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| internal(format!("GET {path}: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet: String = body.chars().take(300).collect();
            return Err(internal(format!("GET {path}: HTTP {status}: {snippet}")));
        }
        // A 200 whose body is HTML means the daemon served its SPA fallback — the
        // API route isn't mounted (e.g. semantic built without the feature).
        if body.trim_start().starts_with('<') {
            return Err(internal(format!(
                "GET {path}: endpoint not available on this daemon (feature off?) — got HTML, not JSON"
            )));
        }
        serde_json::from_str(&body).map_err(|e| internal(format!("GET {path}: bad JSON: {e}")))
    }

    #[tool(
        description = "Full-text search over event messages. Returns scored hits \
        (ts, host, service, severity, message). Fast keyword/phrase lookup."
    )]
    async fn search(
        &self,
        Parameters(a): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let q = vec![("q", a.query), ("limit", a.limit.unwrap_or(20).to_string())];
        ok_json(&self.get("/api/search", &q).await?)
    }

    #[tool(
        description = "Semantic (embedding) search over events — finds events by MEANING, \
        not keywords (e.g. 'login rejected' finds 'Failed password'). Requires the daemon's \
        semantic feature + model; errors otherwise."
    )]
    async fn semantic(
        &self,
        Parameters(a): Parameters<SemanticArgs>,
    ) -> Result<CallToolResult, McpError> {
        let q = vec![("q", a.query), ("limit", a.limit.unwrap_or(20).to_string())];
        ok_json(&self.get("/api/semantic", &q).await?)
    }

    #[tool(
        description = "Run a read-only SQL query over the `events` table (DataFusion). \
        SELECT/aggregate only. Use for counts, group-bys, time windows, field filters."
    )]
    async fn query(&self, Parameters(a): Parameters<SqlArgs>) -> Result<CallToolResult, McpError> {
        ok_json(&self.get("/api/query", &[("sql", a.sql)]).await?)
    }

    #[tool(description = "Return the most recent events (live tail).")]
    async fn tail(&self, Parameters(a): Parameters<TailArgs>) -> Result<CallToolResult, McpError> {
        ok_json(
            &self
                .get(
                    "/api/tail",
                    &[("limit", a.limit.unwrap_or(100).to_string())],
                )
                .await?,
        )
    }

    #[tool(
        description = "List all triage cases (newest first) with state, rule, host, and verdict."
    )]
    async fn cases(&self) -> Result<CallToolResult, McpError> {
        ok_json(&self.get("/api/cases", &[]).await?)
    }

    #[tool(
        description = "Fetch one case by id (prefix accepted), including its full triage transcript."
    )]
    async fn case(&self, Parameters(a): Parameters<CaseArgs>) -> Result<CallToolResult, McpError> {
        ok_json(&self.get(&format!("/api/cases/{}", enc(&a.id)), &[]).await?)
    }

    #[tool(
        description = "Entity page for a host, ip, or user: volume tiles, the cases it \
        triggered (institutional memory), and its recent events."
    )]
    async fn entity(
        &self,
        Parameters(a): Parameters<EntityArgs>,
    ) -> Result<CallToolResult, McpError> {
        let kind = a.kind.trim().to_ascii_lowercase();
        if !matches!(kind.as_str(), "host" | "ip" | "user") {
            return Err(internal(format!(
                "kind must be host|ip|user, got {:?}",
                a.kind
            )));
        }
        ok_json(
            &self
                .get(&format!("/api/entity/{}/{}", kind, enc(&a.name)), &[])
                .await?,
        )
    }

    #[tool(
        description = "Graph pivot / link analysis: everything connected to an entity \
        (host/ip/user/case) within `depth` hops, with edge provenance (case vs raw-event \
        co-occurrence) and ranked attack paths. Answers 'show everything connected to this IP'."
    )]
    async fn graph_pivot(
        &self,
        Parameters(a): Parameters<PivotArgs>,
    ) -> Result<CallToolResult, McpError> {
        let kind = a.kind.trim().to_ascii_lowercase();
        if !matches!(kind.as_str(), "host" | "ip" | "user" | "case") {
            return Err(internal(format!(
                "kind must be host|ip|user|case, got {:?}",
                a.kind
            )));
        }
        let q = vec![
            ("kind", kind),
            ("name", a.name),
            ("depth", a.depth.unwrap_or(2).min(6).to_string()),
        ];
        ok_json(&self.get("/api/graph/pivot", &q).await?)
    }

    #[tool(
        description = "Current risk (RBA) scores for BOTH axes — per host and per entity \
        (staff / db_user) — adjudicated risk decayed over the scoring window, highest first, \
        each row tagged with its `kind` and its top contributing cases."
    )]
    async fn risk(&self) -> Result<CallToolResult, McpError> {
        ok_json(&self.get("/api/risk", &[]).await?)
    }

    #[tool(
        description = "MITRE ATT&CK coverage of the detection ruleset: per-technique and \
        per-tactic coverage, plus rules with no ATT&CK tag. Shows detection blind spots."
    )]
    async fn attack_coverage(&self) -> Result<CallToolResult, McpError> {
        ok_json(&self.get("/api/attack/coverage", &[]).await?)
    }

    #[tool(
        description = "Ask garmr in natural language. The agent plans a read-only query, runs \
        it, and answers grounded in the rows with [n] citations. Costs model spend (budget-capped) \
        — prefer search/query for simple lookups."
    )]
    async fn ask(&self, Parameters(a): Parameters<AskArgs>) -> Result<CallToolResult, McpError> {
        ok_json(&self.get("/api/ask", &[("q", a.question)]).await?)
    }
}

#[tool_handler]
impl ServerHandler for GarmrServer {
    fn get_info(&self) -> ServerInfo {
        // `from_build_env()` reports rmcp's own crate name/version — override so
        // the client (Claude Code) lists this server as `garmr-mcp`.
        let mut info = Implementation::from_build_env();
        info.name = "garmr-mcp".to_string();
        info.version = env!("CARGO_PKG_VERSION").to_string();
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(info)
            .with_instructions(
                "garmr — a self-hosted agentic SOC/SIEM. READ-ONLY + ASK tools over a running \
                 `garmr serve` daemon: search (full-text), semantic (embedding search), query \
                 (read-only SQL over events), tail, cases, case, entity (host/ip/user pages), \
                 graph_pivot (link analysis + attack paths), risk (per-host RBA), \
                 attack_coverage (MITRE ATT&CK ruleset coverage), and ask (natural-language, \
                 grounded, budget-capped). No write/admin surface is exposed. For a fast lookup \
                 use search/query; use ask for open-ended questions; use graph_pivot + entity to \
                 investigate an IP/host/user. Target + auth come from GARMR_API_URL / \
                 GARMR_API_TOKEN."
                    .to_string(),
            )
    }
}

fn internal<E: std::fmt::Display>(e: E) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

fn ok_json(value: &Value) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(value).map_err(internal)?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

/// Minimal percent-encoding for a single path segment (case id / entity name).
fn enc(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "garmr-mcp {} — MCP (stdio) server exposing a running garmr daemon's read + ask \
             surface to an LLM agent.\n\n\
             Point it at a running `garmr serve`:\n  \
             GARMR_API_URL=http://127.0.0.1:3110 GARMR_API_TOKEN=<token> garmr-mcp\n\n\
             Wire into Claude Code:\n  \
             claude mcp add garmr --env GARMR_API_URL=http://127.0.0.1:3110 \\\n    \
             --env GARMR_API_TOKEN=<token> -- garmr-mcp",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("garmr-mcp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Logs go to STDERR — stdout is the MCP JSON-RPC transport.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "garmr_mcp=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let server = GarmrServer::new();
    eprintln!(
        "garmr-mcp: serving read + ask tools against {}",
        server.base
    );
    let running = server.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_encodes_path_unsafe_bytes() {
        assert_eq!(enc("203.0.113.7"), "203.0.113.7");
        assert_eq!(enc("DOMAIN\\user"), "DOMAIN%5Cuser");
        assert_eq!(enc("a b/c?"), "a%20b%2Fc%3F");
        assert_eq!(enc("::ffff:10.0.0.1"), "%3A%3Affff%3A10.0.0.1");
    }
}