// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Configuration, loaded from a TOML file overlaid with `GARMR_*` env vars.
//!
//! Kept in `garmr-core` so every crate shares one config shape. Secrets
//! (API keys, bot tokens) come from the environment, never the TOML file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Error;

/// Which LLM backend the agent talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmBackend {
    /// Anthropic Messages API (`ANTHROPIC_API_KEY`).
    #[default]
    Anthropic,
    /// Any OpenAI-compatible endpoint (Ollama, llama.cpp server, …).
    OpenAiCompat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Directory for the skade lakehouse (events) — one dir, embedded catalog.
    pub warehouse_dir: PathBuf,
    /// Path to the redb file holding agent state (cases, budget, baselines).
    pub state_db: PathBuf,
    /// Directory for the Tantivy full-text index over event messages.
    #[serde(default = "default_search_dir")]
    pub search_dir: PathBuf,
    /// Retention window for events, in days.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// Compact the events lakehouse once this many snapshots accrued since the
    /// last compaction (iceberg `fast_append` accretes one snapshot, one
    /// manifest, and one tiny file per commit; left unbounded it OOMs).
    /// Compaction rebuilds the table as a few large zstd files with a single
    /// snapshot — and, when retention is enabled, prunes rows already sealed to
    /// cold storage. `0` disables it; non-zero values are floored at 8 (a
    /// compacted table restarts at 1 snapshot, so a lower threshold would
    /// rebuild constantly).
    #[serde(default = "default_compact_snapshot_threshold")]
    pub compact_snapshot_threshold: u32,
    /// Seconds to wait after a compaction swap before deleting the retired data
    /// directory, so an in-flight query that resolved just before the swap can
    /// finish reading the old files. Must exceed the longest reader; the API
    /// query/tail timeouts sit well below the default.
    #[serde(default = "default_compact_gc_grace_secs")]
    pub compact_gc_grace_secs: u64,
    /// Event sources to EXCLUDE from the Tantivy full-text index. A high-volume
    /// endpoint firehose (e.g. `kunai` — millions of execve rows) can peg the
    /// single-writer indexer and backpressure ingest, lagging/dropping real
    /// attack logs. Excluded sources are still fully persisted (SQL-queryable)
    /// and evaluated by detection/correlation/anomaly — they only lose
    /// free-text (`/api/search`) coverage. Empty (default) = index everything.
    #[serde(default)]
    pub fulltext_exclude_sources: Vec<String>,
}

fn default_compact_snapshot_threshold() -> u32 {
    // 256 lets the events table routinely carry up to ~256 snapshots, and every
    // read query pays an O(snapshots) planning cost (per-manifest statistics
    // merge) — observed live as multi-second `/api/overview`. 64 keeps planning
    // cheap while still amortising the full-table rebuild over enough appends.
    64
}

fn default_compact_gc_grace_secs() -> u64 {
    300
}

fn default_search_dir() -> PathBuf {
    PathBuf::from("data/search")
}

fn default_retention_days() -> u32 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConfig {
    /// Bind address for the native canonical ingest endpoint
    /// (`POST /ingest/v1/events`), e.g. `0.0.0.0:3100`. `None` disables it.
    /// This is garmr's vendor-neutral primary ingest path.
    #[serde(default = "default_ingest_bind")]
    pub ingest_bind: Option<String>,
    /// Bind address for the Loki push receiver, e.g. `0.0.0.0:3100`. Only used
    /// when garmr is built with the `loki-compat` feature; ignored otherwise.
    /// Retained for backward compatibility with Grafana Alloy `loki.write`.
    #[serde(default = "default_loki_bind")]
    pub loki_bind: String,
    /// Optional syslog UDP/TCP bind, e.g. `0.0.0.0:5514`. `None` disables it.
    #[serde(default)]
    pub syslog_bind: Option<String>,
    /// Default environment label when a source doesn't set one.
    #[serde(default = "default_environment")]
    pub default_environment: String,
    /// Bind address for the read-only query/search/cases HTTP API on `serve`
    /// (e.g. `127.0.0.1:3110`). `None` disables it. This is how you query garmr
    /// while it is ingesting — the embedded store is single-process, so live
    /// queries go through the daemon, not a second CLI process.
    #[serde(default = "default_api_bind")]
    pub api_bind: Option<String>,
    /// Optional directory of the built web console (the garmr-webui `dist/`).
    /// When set — or overridden by the `GARMR_UI_DIR` env var — `serve` hosts
    /// the SPA at `/` on the same bind as the API, so a browser and the API
    /// share one origin (no CORS). `None` keeps `serve` API-only.
    #[serde(default)]
    pub ui_dir: Option<PathBuf>,
    /// Ingest deduplication: remember this many recent stable `event_id`s and
    /// drop an event whose id reappears (an at-least-once collector's retry).
    /// `0` (default) disables it. Size-bounded, so it can only collapse an exact
    /// re-appearance seen within the recent window — it never drops two genuinely
    /// distinct events. A value like `100000` is a good starting point.
    #[serde(default)]
    pub dedup_recent: usize,
    /// Bind address for the Arrow-Flight columnar ingest receiver (gRPC `DoPut`),
    /// e.g. `0.0.0.0:50051`. `None` (default) disables it. Only used when garmr is
    /// built with the `flight` feature; ignored otherwise. This is the zero-copy
    /// columnar swallow path (Arrow RecordBatches straight into the lakehouse, no
    /// JSON parse) that `flightbeat` shippers push to.
    #[serde(default)]
    pub flight_bind: Option<String>,
}

fn default_api_bind() -> Option<String> {
    Some("127.0.0.1:3110".to_string())
}

fn default_ingest_bind() -> Option<String> {
    Some("0.0.0.0:3100".to_string())
}

fn default_loki_bind() -> String {
    "0.0.0.0:3100".to_string()
}

fn default_environment() -> String {
    "prod".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectConfig {
    /// Directory of Sigma rule YAML files (loaded at `serve` start).
    pub rules_dir: PathBuf,
    /// Directory of correlation rule TOML files (windowed multi-event rules).
    #[serde(default = "default_correlations_dir")]
    pub correlations_dir: PathBuf,
    /// Suppress repeat cases for the same dedup key within this many seconds.
    #[serde(default = "default_realert_secs")]
    pub realert_secs: u64,
    /// Directory of scheduled threat-hunt TOML files (hypothesis + schedule).
    /// Missing or empty dir just means no scheduled hunts.
    #[serde(default = "default_hunts_dir")]
    pub hunts_dir: PathBuf,
    /// Application-audit / insider-risk detection plane (Phases 1/3/5/8): per
    /// audit event, project to the canonical model, enrich with the catalog,
    /// evaluate access policy, and run the application-audit detectors. Off by
    /// default (it adds per-event CPU on an audit firehose); enable per deployment.
    #[serde(default)]
    pub app_audit_enabled: bool,
    /// Directory of access-policy TOML files (one `Policy` per file), loaded at
    /// `serve` start. Missing/empty dir means allow-by-default (detectors still
    /// run on the record-derived signals).
    #[serde(default = "default_policies_dir")]
    pub policies_dir: PathBuf,
    /// Optional resource-catalog TOML file (applications, sensitive resources,
    /// classifications). File-imported entries are promoted to Trusted at load.
    #[serde(default)]
    pub catalog_file: Option<PathBuf>,
    /// Optional user-monitoring file (a JSON array of `UserMonitoringProfile`).
    #[serde(default)]
    pub monitoring_file: Option<PathBuf>,
    /// New-template anomaly detection: flag log shapes never seen before. Off
    /// by default; the loop seeds the existing corpus at startup so enabling it
    /// doesn't storm on history.
    #[serde(default)]
    pub anomaly_enabled: bool,
    /// A new shape must recur at least this many times in the window before it
    /// opens a case (a single odd line is noise).
    #[serde(default = "default_anomaly_min_count")]
    pub anomaly_min_count: u64,
    /// Flood cap: emit at most this many NEW-template anomaly detections per
    /// detection tick. A sudden churn in the log landscape (new sources/formats,
    /// a noisy rollout) can surface hundreds of genuinely-new shapes at once and
    /// storm the case store + agent budget. Detections beyond the cap are left
    /// UNRECORDED so they fire on a later tick once the burst subsides — no
    /// signal is lost, just paced. `0` = unlimited.
    #[serde(default = "default_anomaly_max_per_tick")]
    pub anomaly_max_per_tick: usize,
    /// Sources EXCLUDED from new-template anomaly detection. A high-volume
    /// firehose whose `message` is a unique-per-event blob (e.g. `kunai`)
    /// explodes into thousands of one-off "new template" cases; list it here.
    /// Those events are still stored and evaluated by Sigma/correlation — only
    /// the templating detector skips them. Empty (default) = consider all.
    #[serde(default)]
    pub anomaly_exclude_sources: Vec<String>,
    /// Risk-based alerting (RBA): accumulate per-host risk from non-benign
    /// cases over a decaying 24h window and open ONE risk case when a host
    /// crosses `risk_threshold` — catching "many weak signals" that
    /// individually never escalate. Off by default.
    #[serde(default)]
    pub risk_enabled: bool,
    /// Cumulative decayed risk score at which a host opens a risk case. Scale:
    /// a medium case ≈ 4, high ≈ 8, critical ≈ 13 (× a disposition multiplier,
    /// × time decay), so ~20 is roughly "a couple of highs or several mediums".
    #[serde(default = "default_risk_threshold")]
    pub risk_threshold: f64,
    /// Half-life (hours) of a case's risk contribution: a case's weight halves
    /// every this-many hours, so stale activity fades and only sustained /
    /// recent risk accumulates.
    #[serde(default = "default_risk_halflife_hours")]
    pub risk_halflife_hours: f64,
    /// Suppress re-opening a host's risk case within this many seconds (the
    /// risk detection carries this as its own realert window).
    #[serde(default = "default_risk_realert_secs")]
    pub risk_realert_secs: u64,
    /// Frequency-baseline anomaly: flag a (host, service) whose event volume in
    /// the last hour is far above its own norm for the SAME clock-hour (a robust
    /// median ± MAD baseline over ~14 days). Off by default; needs a few days of
    /// history before it fires (warmup).
    #[serde(default)]
    pub freq_baseline_enabled: bool,
    /// MAD multiplier for the burst threshold, `median + k·max(MAD, 1)`. Higher
    /// is less sensitive.
    #[serde(default = "default_freq_k")]
    pub freq_k: f64,
    /// Absolute floor: a (host, service) must have at least this many events in
    /// the hour before a burst can fire (mutes tiny, naturally-bursty counts).
    #[serde(default = "default_freq_min_count")]
    pub freq_min_count: u64,
    /// RBA: how much an UNREVIEWED agent prediction (or the shadow verdict)
    /// counts toward a host's risk, relative to a trusted human/incident outcome
    /// (which counts at 1.0). Default 0.5 — unreviewed model output is
    /// discounted, so a human decision or incident outcome dominates it. A benign
    /// disposition still contributes zero regardless of this factor.
    #[serde(default = "default_prediction_discount")]
    pub prediction_discount: f64,
}

fn default_hunts_dir() -> PathBuf {
    PathBuf::from("hunts")
}

fn default_policies_dir() -> PathBuf {
    PathBuf::from("policies")
}

fn default_anomaly_min_count() -> u64 {
    3
}

fn default_anomaly_max_per_tick() -> usize {
    50
}

fn default_risk_threshold() -> f64 {
    20.0
}

fn default_risk_halflife_hours() -> f64 {
    12.0
}

fn default_risk_realert_secs() -> u64 {
    3600
}

fn default_freq_k() -> f64 {
    3.0
}

fn default_prediction_discount() -> f64 {
    0.5
}

fn default_freq_min_count() -> u64 {
    20
}

fn default_correlations_dir() -> PathBuf {
    PathBuf::from("correlations")
}

fn default_realert_secs() -> u64 {
    900
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub backend: LlmBackend,
    /// Model for the triage loop (e.g. `claude-opus-4-8` or an Ollama tag).
    pub model: String,
    /// Cheaper model for the "worth a full triage?" pre-filter.
    #[serde(default)]
    pub prefilter_model: Option<String>,
    /// Base URL for the OpenAI-compatible backend (ignored for Anthropic).
    #[serde(default)]
    pub openai_base_url: Option<String>,
    /// Max tool-loop iterations per case.
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    /// Max output tokens per model call.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Daily spend ceiling in USD; new cases queue as NeedsHuman past it.
    #[serde(default = "default_daily_budget_usd")]
    pub daily_budget_usd: f64,
    /// Allow online IP-reputation lookups (off by default — privacy/cost).
    #[serde(default)]
    pub allow_online_lookups: bool,
    /// Directory of MaxMind/DB-IP mmdb files for offline enrichment
    /// (`country.mmdb`, `asn.mmdb`).
    #[serde(default)]
    pub geoip_dir: Option<PathBuf>,
    /// Local IOC feed files (one IP per line) for the `ip_reputation` tool.
    #[serde(default)]
    pub ioc_feeds: Vec<String>,
    /// External MCP servers whose (read-only intel) tools are offered to the
    /// triage agent alongside the built-in tools. Empty by default — the whole
    /// feature is opt-in. Each server's tools are namespaced `mcp__<name>__<tool>`
    /// so they can never shadow a built-in tool, and their output is treated as
    /// untrusted third-party data. Only connect servers you trust to be
    /// side-effect-free: garmr proxies the call but cannot enforce read-only-ness
    /// on the far side.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
}

/// An external MCP server the triage agent may call tools on (stdio transport:
/// garmr spawns `command args…` and speaks MCP over its stdin/stdout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Short namespace for this server's tools (`mcp__<name>__<tool>`).
    pub name: String,
    /// Executable to spawn.
    pub command: String,
    /// Arguments passed to the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment variables for the child (e.g. an API token). Prefer
    /// referencing a value already in garmr's environment over inlining secrets.
    /// NEVER serialized: this map can hold secret tokens, so it must never ride
    /// out through a serialize-the-whole-config path (e.g. `/api/config/effective`).
    /// Still deserialized from the base TOML, so the running child gets it.
    #[serde(default, skip_serializing)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Set false to keep the entry but not connect it.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_max_iterations() -> u32 {
    12
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_daily_budget_usd() -> f64 {
    5.0
}

/// Which cold-storage backend seals aged windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdArchiverKind {
    /// Seal into a content-addressed znippy archive (Arrow-IPC manifest,
    /// BLAKE3, cross-tool-readable). The default when the `znippy` feature is
    /// compiled in (it is, in the default `garmr` binary).
    Znippy,
    /// Store the window as a plain zstd-parquet file. Pure Rust, no C toolchain
    /// — the fallback when garmr is built without the `znippy` feature.
    Plain,
}

impl Default for ColdArchiverKind {
    /// Default to the archiver this binary can actually run: `Znippy` when the
    /// `znippy` feature is compiled in, else `Plain`. A hardcoded `Znippy`
    /// default left a no-znippy build with retention dead-on-arrival (its
    /// archiver construction errors), so the default now tracks the build.
    fn default() -> Self {
        #[cfg(feature = "znippy")]
        {
            ColdArchiverKind::Znippy
        }
        #[cfg(not(feature = "znippy"))]
        {
            ColdArchiverKind::Plain
        }
    }
}

/// Cold-storage / retention: aged events are sealed into immutable cold
/// archives (never silently deleted) that stay queryable via `garmr cold-query`.
///
/// The cutoff is `store.retention_days`; everything older is rolled to cold, one
/// `window_days`-sized window at a time. A monotonic watermark in the state
/// store means each window is sealed exactly once and runs are idempotent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Master switch. Off by default — turn it on once a `cold_dir` is set and
    /// you've confirmed the cutoff, so garmr never archives real data unasked.
    #[serde(default)]
    pub enabled: bool,
    /// Directory holding cold archives + the thaw workspace.
    #[serde(default = "default_cold_dir")]
    pub cold_dir: PathBuf,
    /// Which archiver seals windows.
    #[serde(default)]
    pub archiver: ColdArchiverKind,
    /// Window granularity in days — one archive per window of aged data.
    #[serde(default = "default_window_days")]
    pub window_days: u32,
    /// How often the retention loop runs on `serve`, in seconds (default 6h).
    #[serde(default = "default_retention_interval_secs")]
    pub interval_secs: u64,
    /// znippy/zstd compression level for the archive layer.
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cold_dir: default_cold_dir(),
            archiver: ColdArchiverKind::default(),
            window_days: default_window_days(),
            interval_secs: default_retention_interval_secs(),
            compression_level: default_compression_level(),
        }
    }
}

fn default_cold_dir() -> PathBuf {
    PathBuf::from("data/cold")
}

fn default_window_days() -> u32 {
    1
}

fn default_retention_interval_secs() -> u64 {
    6 * 3600
}

fn default_compression_level() -> i32 {
    6
}

/// Alert routing: notification-side controls (see `garmr-route`). Case-level
/// dedup lives in `[detect] realert_secs`; this governs what actually leaves
/// garmr as a Matrix message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteConfig {
    /// After a notification for a rule goes out, drop further notifications for
    /// the SAME rule for this many seconds (0 = off). Caps the one-rule,
    /// many-hosts flood that case-dedup can't collapse. Human-approved silences
    /// are separate and always apply.
    #[serde(default)]
    pub throttle_secs: u64,
    /// The egress allowlist (`[route.egress]`, Phase-10 chokepoint). Empty =
    /// allow-all when not air-gapped; `GARMR_AIRGAP` overrides it entirely.
    #[serde(default)]
    pub egress: crate::egress::EgressConfig,
    /// The model router (`[route.router]`, Phase 10). Empty catalog = today's
    /// single `[agent]` model.
    #[serde(default)]
    pub router: crate::router::RouterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixConfig {
    /// Homeserver base URL (client-server API).
    pub homeserver: String,
    /// Room for every triaged verdict.
    pub investigation_room: String,
    /// Room for escalations (severity over threshold / malicious).
    pub alerts_room: String,
    /// Escalate to the alerts room at or above this analyst severity (0–10).
    #[serde(default = "default_escalate_severity")]
    pub escalate_severity: u8,
}

fn default_escalate_severity() -> u8 {
    7
}

/// Tamper-evident audit ledger (`garmr-audit`). Enabled by default: an
/// append-only, hash-chained, signed ledger of security-relevant actions,
/// verified offline with `garmr audit verify`. The strings here are mapped to
/// `garmr-audit` types in the CLI so this crate stays free of the audit
/// dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Master switch. When off, no ledger is opened and nothing is recorded.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Ledger root directory (holds `segments/` + `checkpoints/`). Default
    /// `data/audit`.
    #[serde(default = "default_audit_dir")]
    pub dir: PathBuf,
    /// ed25519 signing-key seed file. Default `<dir>/signing.key`, created on
    /// first run if absent. A hardware/PKCS#11 key plugs in at the CLI layer.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// Record content persisted: `off` | `digest_only` | `redacted` |
    /// `encrypted` | `full`. Default `digest_only` — never raw sensitive content.
    #[serde(default = "default_audit_content_mode")]
    pub content_mode: String,
    /// Sign every record individually (checkpoints are always signed anyway).
    #[serde(default)]
    pub per_record_sign: bool,
    /// fsync each append before returning — required for fail-closed durability
    /// on high-risk administrative operations.
    #[serde(default = "default_true")]
    pub fsync: bool,
    /// This node's identity, stamped into every record. Default: OS hostname.
    #[serde(default = "default_audit_node_id")]
    pub node_id: String,
    /// Seal + roll to a new segment after this many records.
    #[serde(default = "default_audit_segment_max")]
    pub segment_max_records: u64,
    /// Emit a checkpoint after this many records.
    #[serde(default = "default_audit_checkpoint_every")]
    pub checkpoint_every: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: default_audit_dir(),
            key_path: None,
            content_mode: default_audit_content_mode(),
            per_record_sign: false,
            fsync: true,
            node_id: default_audit_node_id(),
            segment_max_records: default_audit_segment_max(),
            checkpoint_every: default_audit_checkpoint_every(),
        }
    }
}

fn default_audit_dir() -> PathBuf {
    PathBuf::from("data/audit")
}
fn default_audit_content_mode() -> String {
    "digest_only".to_string()
}
fn default_audit_node_id() -> String {
    // Best-effort hostname, no extra dependency; falls back to "garmr".
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "garmr".to_string())
}
fn default_audit_segment_max() -> u64 {
    10_000
}
fn default_audit_checkpoint_every() -> u64 {
    1_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub store: StoreConfig,
    pub ingest: IngestConfig,
    pub detect: DetectConfig,
    pub agent: AgentConfig,
    /// Tamper-evident audit ledger. Enabled by default.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Cold-storage / retention. Defaults to disabled.
    #[serde(default)]
    pub retention: RetentionConfig,
    /// Alert routing (silences + throttle). Defaults to throttle off.
    #[serde(default)]
    pub route: RouteConfig,
    /// Matrix is optional so the pipeline runs headless in tests/selftest.
    #[serde(default)]
    pub matrix: Option<MatrixConfig>,
    /// Response-action executor (SOAR). Opt-in; ships with NO capability.
    #[serde(default)]
    pub executor: ExecutorConfig,
    /// HA read-replica role. Defaults to a single-node writer.
    #[serde(default)]
    pub ha: HaConfig,
    /// The temporal environment model (Phase 5). Defaults to OFF — an existing
    /// deployment is unaffected until the operator enables it.
    #[serde(default)]
    pub environment: EnvironmentConfig,
}

/// The temporal environment model (Phase 5). Governs the learned, gated model of
/// "normal" for this environment. Default posture is fully OFF: `enabled` gates
/// the query/API surface and `learn` gates the background learner loop, so a
/// deployment that does nothing sees no behavior change and no new work on any
/// hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Expose the environment query/API surface. Default off.
    #[serde(default)]
    pub enabled: bool,
    /// Run the background learner + auto-promote loops. Default off.
    #[serde(default)]
    pub learn: bool,
    /// Hours a Candidate must age before it can auto-promote.
    #[serde(default = "default_env_quarantine_hours")]
    pub quarantine_hours: u64,
    /// Shorter quarantine for Asserted (inventory) facts.
    #[serde(default = "default_env_asserted_quarantine_hours")]
    pub asserted_quarantine_hours: u64,
    /// Minimum total sightings before auto-promotion.
    #[serde(default = "default_env_min_observations")]
    pub min_observations: u64,
    /// Minimum distinct bounded sources before auto-promotion.
    #[serde(default = "default_env_min_distinct_sources")]
    pub min_distinct_sources: usize,
    /// No single source's trust-weighted share of the evidence may exceed this.
    #[serde(default = "default_env_max_single_source_share")]
    pub max_single_source_share: f64,
    /// A stale Candidate older than this expires to Retired.
    #[serde(default = "default_env_fact_ttl_days")]
    pub fact_ttl_days: u64,
    /// Trust for a source absent from `source_trust`.
    #[serde(default = "default_env_source_trust")]
    pub default_source_trust: f32,
    /// bounded-source-id -> trust weight (for the influence cap + value conflict
    /// resolution). Assigned at write time; never self-declared in event content.
    #[serde(default)]
    pub source_trust: std::collections::BTreeMap<String, f32>,
    /// Attributes / entity-kind tags that additionally REQUIRE analyst approval,
    /// ON TOP OF the non-removable code floor — config may only ADD to it.
    #[serde(default)]
    pub high_impact_attributes: Vec<String>,
    /// Directory the operator drops offline inventory files in (import is always
    /// operator-triggered — never an auto directory-watch).
    #[serde(default)]
    pub inventory_dir: Option<PathBuf>,
    /// Seconds between learner-loop passes.
    #[serde(default = "default_env_learn_interval_secs")]
    pub learn_interval_secs: u64,
    /// Seconds between auto-promote/expiry-loop passes.
    #[serde(default = "default_env_promote_interval_secs")]
    pub promote_interval_secs: u64,
    /// Phase 7 environment-aware detection (default off).
    #[serde(default)]
    pub detect: EnvDetectConfig,
}

/// Phase 7 — environment-aware detection (the env_edge detector + ensemble
/// scoring over the Trusted view). Default OFF; `enabled` here gates the detector
/// loop, on top of `environment.enabled` gating the whole model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvDetectConfig {
    /// Run the env_edge detector loop. Default off.
    #[serde(default)]
    pub enabled: bool,
    /// The domain profile (Generic default | Register).
    #[serde(default)]
    pub profile: crate::DomainProfileKind,
    /// Minimum Trusted facts about a host before it can produce a rarity finding
    /// (an unseeded baseline must not flag everything).
    #[serde(default = "default_env_min_baseline")]
    pub min_baseline: usize,
    /// Seconds between detector-loop passes.
    #[serde(default = "default_env_detect_interval_secs")]
    pub interval_secs: u64,
    /// Ensemble asset-criticality coefficient (monotonic-up multiplier).
    #[serde(default = "default_env_crit_coef")]
    pub crit_coef: f64,
    /// Ensemble corroboration coefficient.
    #[serde(default = "default_env_corr_coef")]
    pub corr_coef: f64,
}

fn default_env_min_baseline() -> usize {
    3
}
fn default_env_detect_interval_secs() -> u64 {
    3600
}
fn default_env_crit_coef() -> f64 {
    1.0
}
fn default_env_corr_coef() -> f64 {
    0.25
}

impl Default for EnvDetectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            profile: crate::DomainProfileKind::default(),
            min_baseline: default_env_min_baseline(),
            interval_secs: default_env_detect_interval_secs(),
            crit_coef: default_env_crit_coef(),
            corr_coef: default_env_corr_coef(),
        }
    }
}

fn default_env_quarantine_hours() -> u64 {
    24
}
fn default_env_asserted_quarantine_hours() -> u64 {
    1
}
fn default_env_min_observations() -> u64 {
    5
}
fn default_env_min_distinct_sources() -> usize {
    2
}
fn default_env_max_single_source_share() -> f64 {
    0.8
}
fn default_env_fact_ttl_days() -> u64 {
    90
}
fn default_env_source_trust() -> f32 {
    0.5
}
fn default_env_learn_interval_secs() -> u64 {
    3600
}
fn default_env_promote_interval_secs() -> u64 {
    3600
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            learn: false,
            quarantine_hours: default_env_quarantine_hours(),
            asserted_quarantine_hours: default_env_asserted_quarantine_hours(),
            min_observations: default_env_min_observations(),
            min_distinct_sources: default_env_min_distinct_sources(),
            max_single_source_share: default_env_max_single_source_share(),
            fact_ttl_days: default_env_fact_ttl_days(),
            default_source_trust: default_env_source_trust(),
            source_trust: std::collections::BTreeMap::new(),
            high_impact_attributes: Vec::new(),
            inventory_dir: None,
            learn_interval_secs: default_env_learn_interval_secs(),
            promote_interval_secs: default_env_promote_interval_secs(),
            detect: EnvDetectConfig::default(),
        }
    }
}

impl EnvironmentConfig {
    /// The TTL as a duration.
    pub fn fact_ttl(&self) -> chrono::Duration {
        chrono::Duration::days(self.fact_ttl_days as i64)
    }

    /// The Candidate quarantine window as a duration.
    pub fn quarantine(&self) -> chrono::Duration {
        chrono::Duration::hours(self.quarantine_hours as i64)
    }

    /// The Asserted-fact quarantine window as a duration.
    pub fn asserted_quarantine(&self) -> chrono::Duration {
        chrono::Duration::hours(self.asserted_quarantine_hours as i64)
    }

    /// Build the pure promotion policy the anti-poisoning gate consumes.
    pub fn to_policy(&self) -> crate::PromotionPolicy {
        crate::PromotionPolicy {
            quarantine: self.quarantine(),
            asserted_quarantine: self.asserted_quarantine(),
            min_observations: self.min_observations,
            min_distinct_sources: self.min_distinct_sources,
            max_single_source_share: self.max_single_source_share,
            fact_ttl: self.fact_ttl(),
            extra_high_impact: self.high_impact_attributes.clone(),
            source_trust: self.source_trust.clone(),
            default_source_trust: self.default_source_trust,
        }
    }
}

/// Which side of an HA pair this node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaRole {
    /// The single writer: ingests, detects, seals, and (if configured) ships a
    /// warehouse snapshot to object storage for followers.
    #[default]
    Writer,
    /// A read replica: pulls the writer's shipped snapshot and serves only the
    /// read API. Never ingests, never writes — so there is never a second writer.
    Follower,
}

/// HA read-replica configuration. Defaults to a standalone writer (no shipping,
/// no follower) so a single-node deployment is unaffected. The object store is
/// the same one the cold tier uses (`GARMR_S3_*`), under `GARMR_HA_S3_PREFIX`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaConfig {
    /// This node's role.
    #[serde(default)]
    pub role: HaRole,
    /// Writer: seconds between shipping a warehouse snapshot to object storage.
    /// `0` (default) disables shipping — a plain single-node writer.
    #[serde(default)]
    pub ship_interval_secs: u64,
    /// Follower: seconds between pulling the latest shipped snapshot (floored at
    /// 30 so a follower can't hammer the store).
    #[serde(default = "default_ha_pull_secs")]
    pub pull_interval_secs: u64,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            role: HaRole::Writer,
            ship_interval_secs: 0,
            pull_interval_secs: default_ha_pull_secs(),
        }
    }
}

fn default_ha_pull_secs() -> u64 {
    300
}

impl Config {
    /// Load from a TOML file, the generated WebUI override layer, and `GARMR_*`
    /// environment variables — precedence `defaults < base TOML < override < env`.
    ///
    /// The override is a machine-generated file the config-write API owns (never
    /// hand-edited); it lets an operator persist changes from the console without
    /// touching the operator-owned base TOML. It lives in the service-writable
    /// state dir (a sibling of `store.state_db`), NOT the base config dir, which
    /// is typically root-owned `/etc`. Because the state dir isn't known until the
    /// config is parsed, this does a cheap first pass (base + env, which every
    /// field defaults so it always extracts) to discover it, then the real load.
    ///
    /// `GARMR_AIRGAP` is NOT part of this chain — airgap is read from the process
    /// env directly ([`airgap_from_env`](crate::airgap_from_env)), so the override
    /// layer can never disable it. A missing override file is an empty layer.
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        use figment::providers::{Env, Format, Toml};
        // First pass: base + env. Every field defaults over a present [store], so
        // this is the same contract the loader always had; it also discovers the
        // state dir (where the override lives) and is the fallback below.
        let base_and_env: Self = figment::Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("GARMR_").split("__"))
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;
        let override_path = base_and_env.config_override_path();
        if !override_path.exists() {
            return Ok(base_and_env);
        }
        // Second pass: base < override < env. FAIL-SOFT — a malformed or
        // out-of-band-corrupted override must never brick offline/recovery commands
        // (audit verify, backup, query) that never depended on it; fall back to
        // base+env with a loud warning. The write path validates before persisting,
        // so a self-applied override always parses here.
        match figment::Figment::new()
            .merge(Toml::file(path))
            .merge(Toml::file(&override_path))
            .merge(Env::prefixed("GARMR_").split("__"))
            .extract()
        {
            Ok(cfg) => Ok(cfg),
            Err(e) => {
                eprintln!(
                    "WARN: ignoring an invalid config override layer at {}: {e}; using base config + env",
                    override_path.display()
                );
                Ok(base_and_env)
            }
        }
    }

    /// The override path the loader WOULD read for `base_path`, resolved from the
    /// base+env view alone (never the merged config). The config-write API stashes
    /// this at startup so the file it writes is provably the file the loader reads,
    /// independent of override content.
    pub fn resolve_override_path(base_path: &std::path::Path) -> Result<std::path::PathBuf, Error> {
        use figment::providers::{Env, Format, Toml};
        let first: Self = figment::Figment::new()
            .merge(Toml::file(base_path))
            .merge(Env::prefixed("GARMR_").split("__"))
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(first.config_override_path())
    }

    /// Path of the generated WebUI config-override layer: `garmr.override.toml`
    /// in the state dir (sibling of `store.state_db`). The config-write API is the
    /// sole writer; `Config::load` merges it between the base TOML and env. Falls
    /// back to the current dir if `state_db` has no parent.
    pub fn config_override_path(&self) -> std::path::PathBuf {
        match self.store.state_db.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join("garmr.override.toml"),
            _ => std::path::PathBuf::from("garmr.override.toml"),
        }
    }

    /// Build the `Config` that WOULD result from installing `override_body` as the
    /// override layer, WITHOUT persisting it — the dry-run behind the config-write
    /// validate/diff endpoint. Same precedence as [`load`](Self::load) (base TOML
    /// < proposed override < env); a parse or type error in the proposed override
    /// surfaces here as `Err`, so the API can reject an invalid change before it is
    /// ever written. `GARMR_AIRGAP` is not in this chain (env-only), so a proposed
    /// override can never flip airgap even in a dry run.
    pub fn preview_override(base_path: &std::path::Path, override_body: &str) -> Result<Self, Error> {
        use figment::providers::{Env, Format, Toml};
        figment::Figment::new()
            .merge(Toml::file(base_path))
            .merge(Toml::string(override_body))
            .merge(Env::prefixed("GARMR_").split("__"))
            .extract()
            .map_err(|e| Error::Config(e.to_string()))
    }
}

/// The response-action executor. garmr ships NO built-in capability to change
/// system state: each allowlisted action type is wired to an operator-provided
/// argv COMMAND TEMPLATE (no shell — the validated argument substitutes the
/// literal token `{arg}` in exactly one element). With a template absent the
/// executor REFUSES and records the manual command for the human. `enabled`
/// gates the automatic in-`serve` poll loop; `garmr execute` runs it manually
/// regardless (when serve is stopped — the embedded store is single-process).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// Run the executor poll loop inside `serve`. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// argv template for `block_ip`, e.g. `["nft", "add", "element", "inet",
    /// "filter", "blocklist", "{arg}"]`. `{arg}` is the validated public IP.
    #[serde(default)]
    pub block_ip: Option<Vec<String>>,
    /// argv template for `isolate_host`. `{arg}` is the validated host name.
    #[serde(default)]
    pub isolate_host: Option<Vec<String>>,
    /// Addresses/CIDRs that must NEVER be blocked — your own management IP,
    /// gateway, and upstream resolvers. A guardrail below the human: even an
    /// approved `block_ip` on one of these is refused by the executor, so a bad
    /// approval can't sever your own out-of-band undo path. Plain IPs or
    /// `addr/prefix` CIDRs (e.g. `100.64.0.0/10`, `192.0.2.1`).
    #[serde(default)]
    pub never_block: Vec<String>,
}

impl ExecutorConfig {
    /// The configured argv template for an action kind, if any.
    pub fn template(&self, kind: crate::ActionKind) -> Option<&Vec<String>> {
        match kind {
            crate::ActionKind::BlockIp => self.block_ip.as_ref(),
            crate::ActionKind::IsolateHost => self.isolate_host.as_ref(),
        }
    }

    /// Is `ip` covered by the never-block list (exact IP or containing CIDR)?
    /// An unparseable list entry is ignored (a typo must not silently disable
    /// the guard for OTHER entries).
    pub fn is_never_block(&self, ip: &str) -> bool {
        let Ok(target) = ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        let target = target.to_canonical();
        self.never_block
            .iter()
            .any(|entry| match entry.split_once('/') {
                None => entry.parse::<std::net::IpAddr>().map(|a| a.to_canonical()) == Ok(target),
                Some((net, bits)) => cidr_contains(net, bits, target),
            })
    }
}

/// Is `target` inside `net/bits`? Best-effort; a malformed CIDR is `false`.
fn cidr_contains(net: &str, bits: &str, target: std::net::IpAddr) -> bool {
    let Ok(net) = net.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    match (net.to_canonical(), target) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(t)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(n) & mask == u32::from(t) & mask
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(t)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(n) & mask == u128::from(t) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_defaults_off_and_backward_compatible() {
        // A config with no [environment] section still parses, and the model is
        // fully off — an existing deployment is unaffected.
        let cfg = EnvironmentConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.learn);
        // Missing keys fall back to the documented defaults.
        let parsed: EnvironmentConfig = toml::from_str("enabled = true\n").unwrap();
        assert!(parsed.enabled);
        assert!(!parsed.learn, "learn stays off unless set");
        assert_eq!(parsed.min_distinct_sources, 2);
        // The policy conversion carries the thresholds through.
        let pol = parsed.to_policy();
        assert_eq!(pol.min_observations, 5);
        assert_eq!(pol.fact_ttl, chrono::Duration::days(90));
        assert!((pol.max_single_source_share - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn agent_config_parses_mcp_servers() {
        // Guards the `[[agent.mcp_servers]]` shape documented in garmr.example.toml.
        let toml = r#"
backend = "anthropic"
model = "claude-opus-4-8"

[[mcp_servers]]
name = "whois"
command = "whois-mcp"
args = ["--stdio"]
enabled = true

[mcp_servers.env]
WHOIS_TOKEN = "x"
"#;
        let cfg: AgentConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.mcp_servers.len(), 1);
        let s = &cfg.mcp_servers[0];
        assert_eq!(s.name, "whois");
        assert_eq!(s.command, "whois-mcp");
        assert_eq!(s.args, vec!["--stdio".to_string()]);
        assert!(s.enabled);
        assert_eq!(s.env.get("WHOIS_TOKEN").map(String::as_str), Some("x"));
    }

    #[test]
    fn mcp_server_defaults_enabled_and_empty_args() {
        let cfg: AgentConfig = toml::from_str(
            "backend = \"anthropic\"\nmodel = \"m\"\n[[mcp_servers]]\nname = \"a\"\ncommand = \"b\"\n",
        )
        .unwrap();
        let s = &cfg.mcp_servers[0];
        assert!(s.enabled, "enabled defaults to true");
        assert!(s.args.is_empty());
        assert!(s.env.is_empty());
    }

    #[test]
    fn agent_config_without_mcp_servers_defaults_empty() {
        let cfg: AgentConfig = toml::from_str("backend = \"anthropic\"\nmodel = \"m\"\n").unwrap();
        assert!(cfg.mcp_servers.is_empty(), "opt-in: no servers by default");
    }
}