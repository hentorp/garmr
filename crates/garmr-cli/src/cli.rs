// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The command-line grammar: the `garmr` CLI clap definitions — the root
//! [`Cli`] plus the [`Cmd`] subcommand enum and its per-group enums. Pure
//! declarations; dispatch lives in `main`, the handlers in the command modules.

use super::*;

#[derive(Parser)]
#[command(name = "garmr", version, about = "A one-person agentic SOC in Rust")]
pub(crate) struct Cli {
    /// Path to the TOML config (or set GARMR_CONFIG).
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Run the live pipeline: ingest, detect, triage, escalate.
    Serve,
    /// Run a read-only SQL query over the events table.
    Query { sql: String },
    /// Inspect triage cases.
    Cases {
        #[command(subcommand)]
        what: CasesCmd,
    },
    /// Show the most recent events.
    Tail {
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Replay a captured file: canonical event JSON (a top-level array or
    /// newline-delimited event objects), or one raw syslog line per row.
    Replay {
        file: PathBuf,
        /// Treat the file as canonical event JSON (array or NDJSON) rather than
        /// raw syslog lines. Also inferred from a `.json` extension.
        #[arg(long)]
        json: bool,
        /// Parse the file with a named source format instead of json/syslog.
        /// Runs the file through a source adapter — e.g. `postgres-csvlog`,
        /// `postgres-jsonlog`, `ocsf`, `otel`. Offline import for audit files.
        #[arg(long)]
        format: Option<String>,
    },
    /// Full-text search over event messages (Tantivy syntax; bare terms hit
    /// the message, e.g. `failed password` or `host:pve invalid`).
    Search {
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Hybrid search: fuse a structured filter + full-text + (with the `semantic`
    /// build) meaning, ranked with per-result provenance ([S]tructured /
    /// [F]ull-text / [V] semantic). Composes the safe Query IR — no raw SQL.
    Hsearch {
        /// Full-text (Tantivy) query.
        #[arg(long)]
        text: Option<String>,
        /// Semantic (natural-language) query — needs the `semantic` build + a model.
        #[arg(long)]
        semantic: Option<String>,
        /// Restrict to a host (repeatable → OR).
        #[arg(long)]
        host: Vec<String>,
        #[arg(long)]
        service: Vec<String>,
        #[arg(long)]
        source: Vec<String>,
        #[arg(long)]
        environment: Vec<String>,
        #[arg(long)]
        severity: Vec<String>,
        #[arg(long = "log-type")]
        log_type: Vec<String>,
        /// Field predicate `key=value` (repeatable, AND-ed).
        #[arg(long = "field")]
        field: Vec<String>,
        /// Restrict to the last N hours.
        #[arg(long)]
        since: Option<f64>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long = "rrf-k", default_value_t = 60)]
        rrf_k: u32,
    },
    /// List the detection plane's security findings (Phase 7); `--host` narrows.
    Findings {
        #[arg(long)]
        host: Option<String>,
    },
    /// Run the correlation rules once over recent events (on-demand hunt).
    Correlate {
        /// Window to correlate over, in hours. Omit to correlate all history.
        #[arg(long)]
        hours: Option<u64>,
    },
    /// Scan recent events for never-before-seen log-template shapes and open a
    /// case for each (new-template anomaly). First run seeds the corpus.
    Anomaly {
        /// A new shape must recur at least this many times to open a case.
        #[arg(long, default_value_t = 3)]
        min_count: u64,
        /// Seed the corpus WITHOUT opening any cases (baseline the store).
        #[arg(long)]
        seed_only: bool,
    },
    /// Show current per-host risk scores (RBA): accumulated, decayed risk from
    /// adjudicated cases. Read-only inspection — does not open cases.
    Risk {
        /// Show at most this many hosts (highest risk first).
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Entity graph — pivot / link-analysis over cases (host↔ip↔user↔case):
    /// "show everything connected to this IP", or the shortest path between two
    /// entities. Read-only, built in-memory from the case store.
    Graph {
        /// Entity kind: host | ip | user | case.
        kind: String,
        /// Entity value (an IP, host name, user, or case id).
        name: String,
        /// Pivot depth in hops.
        #[arg(long, default_value_t = 2)]
        depth: usize,
        /// Instead of a pivot, show the shortest path to this "kind:name".
        #[arg(long)]
        path_to: Option<String>,
        /// Instead of a pivot, rank the attack paths (reachable risky cases).
        #[arg(long)]
        attack_paths: bool,
    },
    /// Run one frequency-baseline pass: report (host, service) whose last-hour
    /// volume is anomalously high vs its own same-clock-hour norm. Read-only —
    /// does not open cases (that is the serve loop's job).
    Baseline {
        /// MAD multiplier for the burst threshold (median + k·max(MAD,1)).
        #[arg(long, default_value_t = 3.0)]
        k: f64,
        /// Absolute floor: at least this many events this hour to be a candidate.
        #[arg(long, default_value_t = 20)]
        min_count: u64,
    },
    /// Build/refresh the semantic vector index: embed recent event messages into
    /// the semantic store (batch, off any hot path). Needs the `semantic` build
    /// feature + GARMR_EMBED_MODEL; run with `serve` stopped (opens the store).
    #[cfg(feature = "semantic")]
    EmbedIndex {
        /// Look back this many hours of events.
        #[arg(long, default_value_t = 168)]
        hours: u64,
        /// Cap on the number of distinct messages embedded (bounds the index).
        #[arg(long, default_value_t = 100_000)]
        max: usize,
    },
    /// Verify the semantic vector index: confirm it is stamped with the CURRENT
    /// embedding model (a model change forces a rebuild) and report the record
    /// count + index lag. Needs the `semantic` feature + GARMR_EMBED_MODEL.
    #[cfg(feature = "semantic")]
    EmbedVerify,
    /// Rebuild the full-text (Tantivy) index from the warehouse events — the
    /// recovery path after `restore` (which leaves search COLD) or an index
    /// loss/corruption, and the migration after a full-text schema change. A
    /// corrupt index, and one that opens but carries an outdated schema (e.g.
    /// from before time-range filtered search), are moved aside and rebuilt, so
    /// recovery and migration are a single command. Run with `serve` stopped
    /// (opens the store writable).
    Reindex {
        /// Rebuild only the last N hours of events; omit to rebuild everything.
        #[arg(long)]
        hours: Option<u64>,
    },
    /// Durable PostgreSQL/pgAudit collector: follow the newest pgAudit csvlog and
    /// ship AUDIT records to garmr's native ingest through a bounded disk spool
    /// (never drops on a receiver outage) with sequence headers. Runs ON the
    /// PostgreSQL host. Config via env — see docs/packaging/pgaudit-collector.md.
    PgauditShip {
        /// Catch up the existing tail and exit (default: follow forever).
        #[arg(long)]
        once: bool,
    },
    /// Synthetic detection eval: generate a labeled audit dataset (normal traffic
    /// plus injected known attack scenarios), run it through the deterministic
    /// detection plane, and report which scenarios were caught + the normal-event
    /// false-positive rate. Validates the shipped detectors offline (no warehouse).
    SynthEval,
    /// Shadow evaluation (DoD 19): the running champion-vs-challenger comparison
    /// for a `DetectorConfig` challenger registered on the `shadow` channel — the
    /// disagreement counts, dangerous-miss count, and a recommended (human-gated)
    /// decision. Reads the live daemon's `/api/shadow/summary`.
    Shadow,
    /// Semantic search — find events by MEANING (embedding cosine), not
    /// keywords. Needs the `semantic` feature + GARMR_EMBED_MODEL; queries the
    /// index built by `embed-index` (works while `serve` runs).
    #[cfg(feature = "semantic")]
    Semantic {
        /// The natural-language query.
        query: String,
        /// Show at most this many results.
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
    /// Collector-credential lifecycle over the registry file
    /// (`ingest.collectors_file`). Tokens are shown ONCE at mint and stored
    /// only as keyed digests; `list` never prints a secret.
    Collector {
        #[command(subcommand)]
        what: CollectorCmd,
    },
    /// Cold-storage / retention.
    Retention {
        #[command(subcommand)]
        what: RetentionCmd,
    },
    /// Targeted erasure (GDPR-style): place a persistent tombstone and remove
    /// every matching row from the hot store and the full-text index. OFFLINE —
    /// run with `serve` stopped. DRY RUN unless `--apply`: this destroys data,
    /// so the default is to show the plan. Cold archives are NOT rewritten yet;
    /// overlapping ones are named in the certificate as pending.
    Erase {
        /// Which attribute to erase by: "host", "src_ip" or "user".
        #[arg(long)]
        field: String,
        /// The exact value to erase. Never a pattern.
        #[arg(long)]
        value: String,
        /// Optional lower time bound (RFC3339, inclusive).
        #[arg(long)]
        from: Option<String>,
        /// Optional upper time bound (RFC3339, exclusive).
        #[arg(long)]
        to: Option<String>,
        /// Why (e.g. the erasure-request reference). Recorded in the audit
        /// ledger and the certificate.
        #[arg(long)]
        reason: String,
        /// Actually erase. Without this the command prints the plan only.
        #[arg(long)]
        apply: bool,
        /// Where to write the deletion certificate (JSON).
        #[arg(long, default_value = "./erasure-certificate.json")]
        out: std::path::PathBuf,
    },
    /// Query the cold tier (thaws aged archives and runs read-only SQL over the
    /// `events` table). Use `--from`/`--to` to only thaw archives overlapping
    /// that range: RFC3339 timestamps are exact bounds (half-open, `to`
    /// exclusive); a bare `YYYY-MM-DD` covers the whole named day on both ends.
    ColdQuery {
        sql: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    /// Notification silences: quiet a noisy rule for a bounded time. The agent
    /// can only PROPOSE a silence — creating one happens here (or via
    /// POST /admin/silence with GARMR_ADMIN_TOKEN); the authenticated action IS
    /// the human approval. While `serve` runs, this command talks to the daemon
    /// API (set GARMR_ADMIN_TOKEN); otherwise it writes the store directly.
    Silence {
        #[command(subcommand)]
        what: SilenceCmd,
    },
    /// Entity page: a host, IP or user as one document — volume, history,
    /// recent events and every case it triggered (institutional memory).
    /// Talks to a running daemon's API when one is up; otherwise reads the
    /// store directly.
    Entity {
        /// Entity type: host | ip | user.
        kind: String,
        /// The host name, IP address, or user name.
        name: String,
    },
    /// Ask a natural-language question over the events ("ask, don't SPL").
    /// The model plans a read-only query, garmr executes it, and the answer is
    /// grounded in the returned rows with [n] citations. Needs an LLM backend
    /// (ANTHROPIC_API_KEY or a configured OpenAI-compatible endpoint) and
    /// charges the daily budget.
    Ask { question: String },
    /// Threat hunting: run an ad-hoc hypothesis hunt, or list past reports.
    /// A hunt runs the agent's full read-only tool loop (model-priced,
    /// budget-capped); scheduled hunts live as TOML files in detect.hunts_dir.
    Hunt {
        /// The hypothesis to test, e.g. "is there outbound ssh from servers
        /// that never normally talk outward?". Omit to list past hunt reports.
        hypothesis: Option<String>,
        /// Show one report (by id prefix) with its full transcript.
        #[arg(long)]
        report: Option<String>,
    },
    /// Detection authoring: the agent DRAFTS rules grounded in real log data;
    /// you review and approve them into the ruleset (propose ≠ act).
    Rules {
        #[command(subcommand)]
        what: RulesCmd,
    },
    /// Response actions (SOAR): the agent proposes; you approve/deny; a
    /// separate executor re-validates and acts. garmr ships NO capability —
    /// wire each action to an argv template under [executor] first.
    Action {
        #[command(subcommand)]
        what: ActionCmd,
    },
    /// Run the response-action executor once: re-validate + act on every
    /// human-APPROVED action, then exit. Run this when `serve` is stopped
    /// (the embedded store is single-process); with `serve` running, use the
    /// opt-in `[executor] enabled` loop instead.
    Execute,
    /// Offline maintenance: collapse the events table's snapshot log into a
    /// single snapshot. Fixes iceberg metadata bloat from continuous ingest
    /// (thousands of tiny `fast_append` snapshots) that starves in-`serve`
    /// auto-compaction. Run with `serve` STOPPED (single-writer store).
    Compact,
    /// Exercise the full agent loop offline on a canned case.
    Selftest,
    /// Break-glass recovery: regain admin access from the HOST when a passkey is
    /// lost. Local-only (needs host access — the root of trust) and requires
    /// `serve` STOPPED (single-writer store). Audited, never a bypass.
    Recover {
        #[command(subcommand)]
        what: RecoverCmd,
    },
    /// Replay a golden set of (alert → expected verdict) cases through the
    /// triage agent and score the verdicts — regression + calibration harness.
    Eval {
        /// Golden-set JSON file (see fixtures/eval-demo.json).
        file: PathBuf,
        /// Emit the full report as JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
    /// Tamper-evident audit ledger: verify integrity offline, show status,
    /// export signed segments, or force a checkpoint. `verify` exits non-zero on
    /// any tampering, so it is CI/monitoring friendly.
    Audit {
        #[command(subcommand)]
        what: AuditCmd,
    },
    /// Versioned registries (models, prompts, toolsets, rules, detector configs,
    /// datasets, eval runs, releases). Inspect records and their approval/active
    /// state; register + promote are admin-gated.
    Registry {
        #[command(subcommand)]
        what: RegistryCmd,
    },
    /// The temporal environment model (Phase 5): the learned, gated model of
    /// "normal". Inspect facts/candidates and an entity's current or as-of view;
    /// promote/demote/import are admin-gated.
    Env {
        #[command(subcommand)]
        what: EnvCmd,
    },
    /// Application-audit behavioral baselines (Phase 7/8): the learned per-entity
    /// model of normal behavior. List profiles + maturity; promote a profile to
    /// Trusted (only then do its behavioral detectors fire), or mark/clear
    /// Suspicious. Promote/suspect/clear are admin-gated (go through the daemon).
    AppBaseline {
        #[command(subcommand)]
        what: AppBaselineCmd,
    },
    /// The safe learning plane (Phase 8): OFFLINE, LLM-free champion/challenger.
    /// Build an immutable dataset, fit + evaluate a challenger detector-config
    /// against the live champion, and shadow the divergence. Nothing here mutates
    /// the serving policy — a challenger goes live only via `registry promote`.
    Learn {
        #[command(subcommand)]
        what: LearnCmd,
    },
    /// Agent mistake learning (Phase 9): OFFLINE, LLM-free reflection. Distil
    /// analyst-authored mistakes into a Draft procedural-memory LessonSet. It
    /// goes live only via the audited `registry promote lesson triage <version>`.
    Reflect {
        #[command(subcommand)]
        what: ReflectCmd,
    },
    /// The model router (Phase 10): show the catalog + the fence decision per
    /// data class, offline (no store, no spend). Reflects the CURRENT egress
    /// policy (GARMR_AIRGAP + [route.egress]).
    Models {
        /// Show which model a data class would route to
        /// (public|internal|confidential|restricted|secret).
        #[arg(long = "for")]
        for_sensitivity: Option<String>,
    },
    /// Air-gap bundles (Phase 11): build/sign/verify a signed, content-addressed
    /// release bundle for a disconnected SOC. `verify` is offline + fail-closed
    /// and needs an OUT-OF-BAND trusted key.
    Bundle {
        #[command(subcommand)]
        what: BundleCmd,
    },
    /// Per-collector ingest delivery health (Phase 12): last sequence and
    /// cumulative gaps/replays per authenticated collector. A gap means batches
    /// were never delivered (silent loss); replays are benign retries.
    IngestHealth,
    /// Consistent, verifiable BACKUP + fail-closed restore (Phase 13). `create`
    /// captures a signed, content-addressed image of the warehouse + state DB +
    /// audit ledger (run with serve stopped).
    Backup {
        #[command(subcommand)]
        what: BackupCmd,
    },
    /// High availability: the writer lease that fences a failed-over node out.
    Ha {
        #[command(subcommand)]
        what: HaCmd,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum HaCmd {
    /// Show the current writer lease (epoch + holder), if any.
    Lease,
    /// Take the writer lease, moving the epoch forward.
    ///
    /// Run this on the node you are promoting, AFTER the old writer is known to
    /// be stopped. The write is conditional, so if two nodes promote at once
    /// exactly one succeeds and the other is told it lost. A snapshot shipped
    /// under a superseded epoch is refused by followers.
    Promote {
        /// Why — recorded in the audit ledger. Promotion is a decision someone
        /// has to account for later, so it is not optional.
        #[arg(long)]
        reason: String,
        /// Name recorded as the lease holder (default: this machine's hostname).
        #[arg(long)]
        holder: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum BackupCmd {
    /// Create a signed backup into `<dir>` (warehouse + state DB + audit ledger,
    /// content-addressed, secrets excluded). OFFLINE / writer-stopped — refuses
    /// if a `serve` is live. `--include-cold` also captures the cold tier.
    Create {
        dir: std::path::PathBuf,
        /// Also capture the cold-storage archives (retention.cold_dir).
        #[arg(long)]
        include_cold: bool,
        /// The ed25519 signing key seed (default: the audit signing key).
        #[arg(long)]
        signing_key: Option<std::path::PathBuf>,
    },
    /// Verify a backup OFFLINE, fail-closed (non-zero on any tamper/foreign key).
    /// `--key <hex>` is the out-of-band trusted key; without it the local audit
    /// public key is tried, else the result is UNVERIFIED.
    Verify {
        dir: std::path::PathBuf,
        #[arg(long)]
        key: Option<String>,
    },
    /// Verify (fail-closed) THEN restore a backup into the config's targets
    /// (serve stopped). Nothing is written until every check passes; the live
    /// targets are moved aside to `*.pre-restore-<ts>` and swapped atomically. The
    /// restored node is a read-only FOLLOWER until `garmr backup promote`.
    Restore {
        dir: std::path::PathBuf,
        /// The out-of-band trusted key (required — the embedded key is never trusted).
        #[arg(long)]
        key: Option<String>,
        /// Restore even on a garmr-version or absolute-path mismatch (see the
        /// path-binding warning). Use only when you understand the risk.
        #[arg(long)]
        force: bool,
        /// Restore a backup whose create-time integrity verdict was `degraded`.
        #[arg(long)]
        accept_degraded: bool,
        /// Also restore the cold tier (if the backup captured it).
        #[arg(long)]
        include_cold: bool,
        /// Verify + print the plan, write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Promote a restored follower to writer: fence (refuse if a writer is live) +
    /// audited follower→writer transition + clear the restored marker. Run with
    /// serve stopped. Single-host authoritative; multi-node failover is UNVERIFIED.
    Promote {
        #[arg(long, default_value = "restored-follower promotion")]
        reason: String,
    },
    /// Show a backup's manifest (coordinates + entries), no verification.
    Show { dir: std::path::PathBuf },
}

#[derive(Subcommand)]
pub(crate) enum BundleCmd {
    /// Build + sign a bundle into `<dir>` (binary + rules/correlations/hunts +
    /// config template + SBOM + provenance + release record), signed with the
    /// audit key (or `--signing-key`).
    Build {
        dir: std::path::PathBuf,
        /// The garmr binary to bundle (default: the running one).
        #[arg(long)]
        binary: Option<std::path::PathBuf>,
        /// The ed25519 signing key seed (default: the audit signing key).
        #[arg(long)]
        signing_key: Option<std::path::PathBuf>,
        /// Build a CONTENT-ONLY bundle (rules/correlations/hunts — no binary):
        /// the signed content-update channel. Registers as `garmr-content` so
        /// it never shadows a release, and `import` installs its content into
        /// the configured detection dirs after the same fail-closed verify.
        #[arg(long)]
        content_only: bool,
    },
    /// Verify a bundle OFFLINE, fail-closed (non-zero on any tamper/foreign key).
    /// `--key <hex>` is the out-of-band trusted key; without it the local audit
    /// public key is tried, else the result is UNVERIFIED.
    Verify {
        dir: std::path::PathBuf,
        #[arg(long)]
        key: Option<String>,
    },
    /// Show a bundle's manifest (entries + digests), no verification.
    Show { dir: std::path::PathBuf },
    /// Verify (fail-closed) THEN apply a bundle offline: register the release +
    /// promote it (audited, reversible). `--key` is REQUIRED (only `--dry-run`
    /// may run without it). Run with serve stopped.
    Import {
        dir: std::path::PathBuf,
        /// The out-of-band trusted key (required unless --dry-run).
        #[arg(long)]
        key: Option<String>,
        #[arg(long, default_value = "production")]
        channel: String,
        /// Override the release version (default: the record's version).
        #[arg(long)]
        version: Option<String>,
        #[arg(long, default_value = "air-gap bundle import")]
        reason: String,
        /// Verify + print the plan, write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Offline audited rollback: re-point the release channel to a prior version
    /// (serve stopped). The symmetric reversal of `import`.
    Rollback {
        to_version: String,
        #[arg(long, default_value = "production")]
        channel: String,
        /// Which registered name to re-point (`garmr` for releases,
        /// `garmr-content` for content bundles).
        #[arg(long, default_value = "garmr")]
        name: String,
        #[arg(long, default_value = "air-gap bundle rollback")]
        reason: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReflectCmd {
    /// Draft a LessonSet from the last `--hours` of mistakes (fail-closed on any
    /// injection/weakening/cap finding), and register it Draft.
    Build {
        #[arg(long, default_value = "720")]
        hours: i64,
        /// Minimum corroborating mistakes for a category to yield a lesson.
        #[arg(long, default_value = "2")]
        min_support: usize,
    },
    /// List drafted/approved lesson sets.
    List,
    /// Show one lesson set (by version).
    Show { version: String },
    /// Re-validate a stored lesson set (injection + weakening + caps + digest).
    /// Non-zero on any finding.
    Verify { version: String },
}

#[derive(Subcommand)]
pub(crate) enum LearnCmd {
    /// Build an immutable, content-addressed dataset from Trusted-only,
    /// poison-excluded labels over the last `--hours`, with a temporal split.
    DatasetBuild {
        #[arg(long, default_value = "720")]
        hours: i64,
        /// Fraction of labels in the oldest Train slice.
        #[arg(long, default_value = "0.5")]
        train: f64,
        /// Fraction in the middle Val slice (the rest is the newest Test holdout).
        #[arg(long, default_value = "0.25")]
        val: f64,
        #[arg(long, default_value = "dataset")]
        name: String,
    },
    /// List stored datasets.
    DatasetList,
    /// Show one dataset (by digest prefix).
    DatasetShow { digest: String },
    /// Verify a dataset's content digest + its registry-record join. Non-zero on
    /// mismatch.
    DatasetVerify { digest: String },
    /// Fit a challenger detector-config on a dataset and register it Draft.
    ChallengerFit {
        /// Dataset digest (prefix).
        dataset: String,
        #[arg(long, default_value = "50")]
        alert_budget: usize,
    },
    /// Evaluate champion vs a challenger on the Test holdout + the promotion gate.
    ChallengerEval {
        /// Dataset digest (prefix).
        dataset: String,
        /// A registered challenger version (else one is fitted on the fly).
        #[arg(long)]
        challenger: Option<String>,
        #[arg(long, default_value = "50")]
        alert_budget: usize,
    },
    /// Offline, read-only divergence report: which rows a challenger would newly
    /// escalate / suppress vs the champion. Writes nothing.
    Shadow {
        /// Dataset digest (prefix).
        dataset: String,
        /// A registered challenger version.
        challenger: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AppBaselineCmd {
    /// List every learned baseline profile (kind, id, state, maturity, counts).
    List,
    /// Promote an entity's baseline to Trusted (admin). Refused by a hard block
    /// (open case / prior policy violation / suspicious). Kind: user | role |
    /// group | service-account | application | peer-group.
    Promote {
        kind: String,
        id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Mark an entity's baseline Suspicious (admin; stops answering detectors).
    Suspect {
        kind: String,
        id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Clear a Suspicious marking after review (admin; → Candidate, re-learns).
    Clear {
        kind: String,
        id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum EnvCmd {
    /// List materialized facts (optionally `--state trusted|candidate|…`).
    Facts {
        #[arg(long)]
        state: Option<String>,
    },
    /// List facts awaiting promotion (Candidate state).
    Candidates,
    /// Show the facts about one entity; `--as-of <rfc3339>` for historical belief.
    Show {
        kind: String,
        id: String,
        #[arg(long)]
        as_of: Option<String>,
    },
    /// Integrity pass over the environment streams. Exits non-zero on a finding.
    Verify,
    /// Promote a fact to Trusted (admin; hard anti-poisoning blocks re-checked).
    Promote {
        fact_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Analyst approval of a high-impact fact's promotion (admin).
    Approve {
        fact_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Flag a fact Suspicious/KnownMalicious (admin; never gate-blocked).
    Demote {
        fact_id: String,
        /// suspicious | known_malicious
        state: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Retire a fact (admin).
    Retire {
        fact_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Import a local inventory file (TOML/JSON) as Asserted facts (admin).
    Import {
        /// Path to the inventory file.
        file: std::path::PathBuf,
        /// A bounded source name for the inventory.
        #[arg(long)]
        source: String,
        /// Optional trust weight (else the config default).
        #[arg(long)]
        trust: Option<f32>,
    },
}

#[derive(Subcommand)]
pub(crate) enum RegistryCmd {
    /// List records of a kind (model|prompt|toolset|rule|detector_config|
    /// dataset|eval_run|release|…), each with its effective approval state.
    List {
        /// The registry kind.
        kind: String,
    },
    /// Show every version + promotion history of one name within a kind.
    Show { kind: String, name: String },
    /// Show the live (active) record for every kind/name on production.
    Active,
    /// Integrity pass: every promotion is audit-bound and resolves to a present
    /// record. Exits non-zero on any finding.
    Verify,
    /// Register an immutable content record (admin; needs a running daemon with
    /// GARMR_ADMIN_TOKEN).
    Register {
        kind: String,
        name: String,
        version: String,
        /// The artifact's BLAKE3 content digest (its immutable identity).
        #[arg(long)]
        digest: String,
        #[arg(long, default_value = "")]
        rationale: String,
    },
    /// Promote a registered version to live/approved (admin).
    Promote {
        kind: String,
        name: String,
        version: String,
        #[arg(long, default_value = "production")]
        channel: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Re-promote a prior version — rollback (admin).
    Rollback {
        kind: String,
        name: String,
        version: String,
        #[arg(long, default_value = "production")]
        channel: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Clear the active pointer on a channel — retire (admin).
    Retire {
        kind: String,
        name: String,
        version: String,
        #[arg(long, default_value = "production")]
        channel: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Mark a specific version rejected (admin).
    Reject {
        kind: String,
        name: String,
        version: String,
        #[arg(long, default_value = "production")]
        channel: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuditCmd {
    /// Show ledger status: record/segment/checkpoint counts, chain head, and
    /// whether integrity currently verifies.
    Status,
    /// Verify the ledger offline against a trusted public key. Non-zero exit on
    /// failure. With no `--key`, trusts the ledger's own published key (trust on
    /// first use) — for an independent audit, pass the out-of-band trusted key.
    Verify {
        /// Trusted ed25519 public key (64 hex chars). Defaults to the local key.
        #[arg(long)]
        key: Option<String>,
    },
    /// Export signed segments + checkpoints + public key to a directory, for
    /// offline verification on another machine.
    Export {
        /// Destination directory (created if absent).
        dir: PathBuf,
    },
    /// Force a signed checkpoint now. Run with `serve` stopped.
    Checkpoint,
}

#[derive(Subcommand)]
pub(crate) enum RecoverCmd {
    /// Mint a SHORT-LIVED emergency Admin credential and print its token ONCE.
    /// Use it as a bearer to log in, register a fresh admin passkey, then revoke
    /// it in System → Access. Recorded to the tamper-evident ledger when auditing
    /// is enabled (a loud warning is printed if it is not).
    IssueAdmin {
        /// Label for the emergency credential (shown in System → Access).
        #[arg(long, default_value = "emergency-admin")]
        label: String,
        /// Hours until the credential expires (clamped to 1..=168).
        #[arg(long, default_value_t = 12)]
        hours: i64,
    },
}

#[derive(Subcommand)]
pub(crate) enum ActionCmd {
    /// Draft an action proposal by hand (the agent proposes automatically
    /// during triage; this is for operator-initiated proposals).
    Propose {
        /// block_ip | isolate_host.
        kind: String,
        /// The IP to block, or the host to isolate.
        arg: String,
        /// The case this action responds to.
        #[arg(long)]
        case: String,
        #[arg(long, default_value = "")]
        rationale: String,
    },
    /// List action proposals, newest first.
    List,
    /// Show one action (id prefix ok) with its full audit trail.
    Show { id: String },
    /// Approve a proposed action (the human gate). Does NOT execute.
    Approve { id: String },
    /// Deny a proposed action, or recall one already approved (before the
    /// executor runs it). Terminal.
    Deny {
        id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum RulesCmd {
    /// Draft a rule for a pattern ("catch repeated sudo failures per host").
    /// Model-priced + budget-capped; the draft is validated and backtested.
    Propose { request: String },
    /// Import community Sigma rules (a file or a directory, recursively).
    /// DRY RUN by default: prints a lint report checking every referenced field
    /// against garmr's event projection — the silent-never-match class becomes
    /// a printed rejection. No LLM anywhere on this path.
    Import {
        /// A .yml file or a directory of rules (searched recursively).
        path: std::path::PathBuf,
        /// Install the clean rules (verbatim YAML + provenance header) into
        /// rules_dir/imported/ and register each in the registry.
        #[arg(long)]
        write: bool,
        /// Also accept rules referencing fields outside garmr's projection.
        /// They match only if your collectors ship those fields verbatim.
        #[arg(long)]
        allow_unknown: bool,
    },
    /// List rule proposals, newest first.
    Proposals,
    /// Show one proposal (id prefix ok) with its full rule body + backtest.
    Show { id: String },
    /// Approve a pending proposal: writes the rule file into the matching rule
    /// directory. Takes effect at the next `serve` start.
    Approve { id: String },
    /// Reject a pending proposal.
    Reject {
        id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum CasesCmd {
    /// List cases, newest first.
    List,
    /// Show one case with its full transcript.
    Show { id: String },
    /// Prune (delete) cases matching filters — case retention / cleanup. Prints
    /// a preview; pass --yes to actually delete. At least one filter is required
    /// (it refuses to wipe the whole case store unguarded).
    Prune {
        /// Cases whose last update is older than N days.
        #[arg(long)]
        older_than_days: Option<i64>,
        /// Cases opened at/after this RFC3339 time (e.g. 2026-07-19T19:25:00Z).
        #[arg(long)]
        opened_after: Option<String>,
        /// Cases opened at/before this RFC3339 time.
        #[arg(long)]
        opened_before: Option<String>,
        /// Only cases in this state (repeatable): new, investigating, triaged,
        /// escalated, closed, needs_human.
        #[arg(long = "state")]
        states: Vec<String>,
        /// Only cases whose triggering rule id equals this.
        #[arg(long)]
        rule: Option<String>,
        /// Only cases whose triggering event source equals this (e.g. kube-audit, soak).
        #[arg(long)]
        source: Option<String>,
        /// Actually delete (default is a dry-run preview).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SilenceCmd {
    /// Silence a rule's notifications for N hours (0 clears; max 168). NOTE: a
    /// silence suppresses escalations too — it is your explicit, bounded call;
    /// prefer --host to keep it narrow. (The automatic throttle, by contrast,
    /// never suppresses an escalation.)
    Set {
        /// Sigma/correlation rule id (as shown in `garmr cases list`).
        rule: String,
        #[arg(long)]
        hours: f64,
        /// Only silence the rule on this host (default: every host).
        #[arg(long)]
        host: Option<String>,
        /// Why — lands in the audit trail.
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// List active silences.
    List,
}

#[derive(Subcommand)]
pub(crate) enum CollectorCmd {
    /// Mint a credential for a new collector id. Refused if the id already has
    /// an active credential — `rotate` is the verb for replacement.
    Add {
        /// Collector id (the trusted source identity stamped on its events).
        id: String,
        /// `event.source` values this collector may assert (comma-separated).
        /// Empty = any (the collector id remains the trust anchor).
        #[arg(long, value_delimiter = ',')]
        sources: Vec<String>,
        /// Days until the credential expires. Omit for no expiry — a deliberate
        /// choice, not a default.
        #[arg(long)]
        expires_days: Option<i64>,
    },
    /// Mint a replacement credential and revoke the old one (kept in the file,
    /// revoked, so an incident review can trace the history).
    Rotate { id: String },
    /// Revoke every active credential for the id.
    Revoke { id: String },
    /// Show the registry: status, fingerprints, bindings. Never a secret.
    List,
}

#[derive(Subcommand)]
pub(crate) enum RetentionCmd {
    /// Run one retention pass now: seal every aged window into the cold tier.
    Run,
    /// List the sealed cold archives (the manifest).
    List,
    /// Delete cold archives whose window is entirely older than `--older-than`
    /// days. DRY RUN unless `--apply` is given: deleting evidence is the one
    /// operation here a retry cannot undo, so the default is to show the plan.
    /// Archives under legal hold are always skipped and always reported.
    Expire {
        /// Age cutoff in days. An archive expires only when its whole window
        /// is older — a window straddling the cutoff still holds retained data.
        #[arg(long)]
        older_than: u32,
        /// Actually delete. Without this the command only prints what it would
        /// do, which is how it should be run first, every time.
        #[arg(long)]
        apply: bool,
    },
    /// Show the deletion ledger: what expiry has removed, and whether every
    /// copy actually went. This is the evidence for "prove what you deleted".
    Deletions,
    /// Place or clear a legal hold on one archive, exempting it from expiry.
    Hold {
        /// Archive id (the window key shown by `retention list`).
        id: String,
        /// Clear the hold instead of placing it.
        #[arg(long)]
        clear: bool,
    },
}
