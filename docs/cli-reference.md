# garmr CLI reference

Every `garmr` subcommand and its one-line purpose. Generated from `garmr --help`;
run `garmr <command> --help` for a command's flags. `serve` runs the daemon; every
other command is one-shot and prefers the running daemon's API when one is up.

| Command | Purpose |
|---|---|
| `serve` | Run the live pipeline: ingest, detect, triage, escalate |
| `query` | Run a read-only SQL query over the events table |
| `cases` | Inspect triage cases |
| `tail` | Show the most recent events |
| `replay` | Replay a captured file: canonical event JSON (a top-level array or newline-delimited event objects), or one raw syslog line per row |
| `search` | Full-text search over event messages (Tantivy syntax; bare terms hit the message, e.g. `failed password` or `host:pve invalid`) |
| `hsearch` | Hybrid search: fuse a structured filter + full-text + (with the `semantic` build) meaning, ranked with per-result provenance ([S]tructured / [F]ull-text / [V] semantic). Composes the safe Query IR — no raw SQL |
| `findings` | List the detection plane's security findings (Phase 7); `--host` narrows |
| `correlate` | Run the correlation rules once over recent events (on-demand hunt) |
| `anomaly` | Scan recent events for never-before-seen log-template shapes and open a case for each (new-template anomaly). First run seeds the corpus |
| `risk` | Show current per-host risk scores (RBA): accumulated, decayed risk from adjudicated cases. Read-only inspection — does not open cases |
| `graph` | Entity graph — pivot / link-analysis over cases (host↔ip↔user↔case): "show everything connected to this IP", or the shortest path between two entities. Read-only, built in-memory from the case store |
| `baseline` | Run one frequency-baseline pass: report (host, service) whose last-hour volume is anomalously high vs its own same-clock-hour norm. Read-only — does not open cases (that is the serve loop's job) |
| `embed-index` | Build/refresh the semantic vector index: embed recent event messages into the semantic store (batch, off any hot path). Needs the `semantic` build feature + GARMR_EMBED_MODEL; run with `serve` stopped (opens the store) |
| `embed-verify` | Verify the semantic vector index: confirm it is stamped with the CURRENT embedding model (a model change forces a rebuild) and report the record count + index lag. Needs the `semantic` feature + GARMR_EMBED_MODEL |
| `reindex` | Rebuild the full-text (Tantivy) index from the warehouse events — the recovery path after `restore` (which leaves search COLD) or an index loss/corruption. Run with `serve` stopped (opens the store writable) |
| `pgaudit-ship` | Durable PostgreSQL/pgAudit collector: follow the newest pgAudit csvlog and ship AUDIT records to garmr's native ingest through a bounded disk spool (never drops on a receiver outage) with sequence headers. Runs ON the PostgreSQL host. Config via env — see docs/packaging/pgaudit-collector.md |
| `synth-eval` | Synthetic detection eval: generate a labeled audit dataset (normal traffic plus injected known attack scenarios), run it through the deterministic detection plane, and report which scenarios were caught + the normal-event false-positive rate. Validates the shipped detectors offline (no warehouse) |
| `shadow` | Shadow evaluation (DoD 19): the running champion-vs-challenger comparison for a `DetectorConfig` challenger registered on the `shadow` channel — the disagreement counts, dangerous-miss count, and a recommended (human-gated) decision. Reads the live daemon's `/api/shadow/summary` |
| `semantic` | Semantic search — find events by MEANING (embedding cosine), not keywords. Needs the `semantic` feature + GARMR_EMBED_MODEL; queries the index built by `embed-index` (works while `serve` runs) |
| `retention` | Cold-storage / retention |
| `cold-query` | Query the cold tier (thaws aged archives and runs read-only SQL over the `events` table). Use `--from`/`--to` to only thaw archives overlapping that range: RFC3339 timestamps are exact bounds (half-open, `to` exclusive); a bare `YYYY-MM-DD` covers the whole named day on both ends |
| `silence` | Notification silences: quiet a noisy rule for a bounded time. The agent can only PROPOSE a silence — creating one happens here (or via POST /admin/silence with GARMR_ADMIN_TOKEN); the authenticated action IS the human approval. While `serve` runs, this command talks to the daemon API (set GARMR_ADMIN_TOKEN); otherwise it writes the store directly |
| `entity` | Entity page: a host, IP or user as one document — volume, history, recent events and every case it triggered (institutional memory). Talks to a running daemon's API when one is up; otherwise reads the store directly |
| `ask` | Ask a natural-language question over the events ("ask, don't SPL"). The model plans a read-only query, garmr executes it, and the answer is grounded in the returned rows with [n] citations. Needs an LLM backend (ANTHROPIC_API_KEY or a configured OpenAI-compatible endpoint) and charges the daily budget |
| `hunt` | Threat hunting: run an ad-hoc hypothesis hunt, or list past reports. A hunt runs the agent's full read-only tool loop (model-priced, budget-capped); scheduled hunts live as TOML files in detect.hunts_dir |
| `rules` | Detection authoring: the agent DRAFTS rules grounded in real log data; you review and approve them into the ruleset (propose ≠ act) |
| `action` | Response actions (SOAR): the agent proposes; you approve/deny; a separate executor re-validates and acts. garmr ships NO capability — wire each action to an argv template under [executor] first |
| `execute` | Run the response-action executor once: re-validate + act on every human-APPROVED action, then exit. Run this when `serve` is stopped (the embedded store is single-process); with `serve` running, use the opt-in `[executor] enabled` loop instead |
| `compact` | Offline maintenance: collapse the events table's snapshot log into a single snapshot. Fixes iceberg metadata bloat from continuous ingest (thousands of tiny `fast_append` snapshots) that starves in-`serve` auto-compaction. Run with `serve` STOPPED (single-writer store) |
| `selftest` | Exercise the full agent loop offline on a canned case |
| `eval` | Replay a golden set of (alert → expected verdict) cases through the triage agent and score the verdicts — regression + calibration harness |
| `audit` | Tamper-evident audit ledger: verify integrity offline, show status, export signed segments, or force a checkpoint. `verify` exits non-zero on any tampering, so it is CI/monitoring friendly |
| `registry` | Versioned registries (models, prompts, toolsets, rules, detector configs, datasets, eval runs, releases). Inspect records and their approval/active state; register + promote are admin-gated |
| `env` | The temporal environment model (Phase 5): the learned, gated model of "normal". Inspect facts/candidates and an entity's current or as-of view; promote/demote/import are admin-gated |
| `app-baseline` | Application-audit behavioral baselines (Phase 7/8): the learned per-entity model of normal behavior. List profiles + maturity; promote a profile to Trusted (only then do its behavioral detectors fire), or mark/clear Suspicious. Promote/suspect/clear are admin-gated (go through the daemon) |
| `learn` | The safe learning plane (Phase 8): OFFLINE, LLM-free champion/challenger. Build an immutable dataset, fit + evaluate a challenger detector-config against the live champion, and shadow the divergence. Nothing here mutates the serving policy — a challenger goes live only via `registry promote` |
| `reflect` | Agent mistake learning (Phase 9): OFFLINE, LLM-free reflection. Distil analyst-authored mistakes into a Draft procedural-memory LessonSet. It goes live only via the audited `registry promote lesson triage <version>` |
| `models` | The model router (Phase 10): show the catalog + the fence decision per data class, offline (no store, no spend). Reflects the CURRENT egress policy (GARMR_AIRGAP + [route.egress]) |
| `bundle` | Air-gap bundles (Phase 11): build/sign/verify a signed, content-addressed release bundle for a disconnected SOC. `verify` is offline + fail-closed and needs an OUT-OF-BAND trusted key |
| `ingest-health` | Per-collector ingest delivery health (Phase 12): last sequence and cumulative gaps/replays per authenticated collector. A gap means batches were never delivered (silent loss); replays are benign retries |
| `backup` | Consistent, verifiable BACKUP + fail-closed restore (Phase 13). `create` captures a signed, content-addressed image of the warehouse + state DB + audit ledger (run with serve stopped) |
| `help` | Print this message or the help of the given subcommand(s) |
