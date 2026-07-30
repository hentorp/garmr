# garmr WebUI — terminology glossary

**Principle (Phase 4 / product principle 1): one concept has exactly one primary user-facing name.**
A concept may appear in many places, but the *word* must not change between nav, page title, button,
field label, empty state, error, toast, and notification. Internal names (Rust types, enum variants,
env vars, storage-plane names, config keys, CLI verbs) must never surface as the primary user-facing
label.

This file is the source of truth for user-facing wording. When adding UI copy, use the **Preferred**
column and never the **Banned** column. Findings below were inventoried from `crates/garmr-webui/src/`
(see the audit for file:line detail).

---

## Glossary

| Preferred (user-facing) | Description shown to users | Internal name(s) | Banned variants |
|---|---|---|---|
| **Investigation** | A triaged case: evidence, agent analysis, and the analyst's decision. | `Case`, `View::Investigation` | Case, Case item, Detection case, Triage object |
| **Finding** | A single detector hit — a behavior a detector flagged. | detector output | (keep "Finding"; don't reuse it for audit/hunt — see below) |
| **Verification issue** | A problem found while verifying the audit ledger. | "Verification findings" | Verification finding (collides with detector Finding) |
| **Hunt result** | A row returned by a threat hunt. | hunt row | hunt "finding" |
| **Policy violation** | An access that an active policy denies. | violation | (consistent — keep) |
| **Behavioral anomaly** | Activity that departs from an entity's learned baseline. | detector band/level/score | (currently unnamed — adopt "Behavioral anomaly") |
| **Monitoring** / **Heighten monitoring** | Raised attention on a user; never a verdict of guilt. | monitoring | Watched user, Watchlist entry |
| **Application** | An application/service (and the host it runs on) that touches sensitive resources. | `View::Application`, `host` entity | host (as a user-facing label for this entity) |
| **Data source** | A configured origin of events. | source | feed |
| **Collector** | An authenticated agent that ships events from a data source. | collector | shipper, ingester |
| **Model provider** | A configured LLM endpoint (local or external) garmr can call. | `LlmBackend`, provider, router | LLM backend, Backend, provider adapter, provider implementation, "external backend" (as a name) |
| **Model** | The specific model a provider serves. | model | — |
| **API credential** | A machine credential (bearer) for collectors, CLI, integrations. | token, `ApiCredential` | Bearer secret, Auth token, API key (for machine creds), "operator token" |
| **Legacy environment credential** | A pre-existing env-var token, shown but not editable in the UI. | `GARMR_ADMIN_TOKEN` | (don't show the raw env var name as the label) |
| **Secret** | A stored provider/integration secret (LLM key, SMTP password, …). Write-only. | sealed store entry | (keep "Secret"; distinct from API credential) |
| **Passkey** | A WebAuthn credential for interactive login. | authenticator | Authenticator (as the primary noun) |
| **Configuration revision** | A versioned config override; each apply/rollback is one revision. | override revision | — (consistent) |
| **Audit reference** | A pointer to the tamper-evident ledger record for a protected action. | audit token/id | — |
| **Baseline** | An entity's learned normal behavior. | baseline | — (consistent) |
| **Champion** | The active detector configuration. | champion | — (consistent) |
| **Challenger** | A shadow detector configuration evaluated against the champion. | challenger | — (consistent) |
| **Detector** | A rule/model that produces Findings. | detector, `detector_config` | detector_config (raw) |
| **Detections** (area) | Where detectors, findings, baselines and proposals live. | — | — |

---

## Status / enum label map (never render raw enum variants)

Raw backend values must be mapped to sentence-case, human labels before display. Provide the
accessible label in full even where a compact chip is shown.

| Raw value(s) | User label | Where seen |
|---|---|---|
| `Candidate` / `Trusted` / `Suspicious` / `Retired` (baseline) | Learning / Trusted / Suspicious / Retired | status.rs:46, detections.rs:159, users.rs:84 |
| `Draft` / `Approved` / `Rejected` / `Deprecated` (policy lifecycle) | Draft / Approved / Rejected / Deprecated (sentence-case, keep) | policies.rs:239 |
| `benign` / `suspicious` / `malicious` / `needs_human` (disposition) | Benign / Suspicious / Malicious / Needs human review | investigations.rs:449 |
| `governed` / `hot` / `restart` (reload class) | Governed / Hot-reload / Restart required | system.rs:670–672 |
| `structured` / `full_text` / `semantic` → `S` / `F` / `V` chips | Structured / Full-text / Semantic (as the accessible name behind each chip) | audit.rs:298–301 |

---

## Jargon-removal rules (internal terms must not be the primary label)

| On screen today | file:line | Replace with |
|---|---|---|
| `Application-audit plane` (disabled-panel title, 4 areas) | detections.rs:138; users.rs:43; applications.rs:53; resources.rs:70 | **Application audit** (a feature, not a "plane") |
| `the application-audit plane is disabled` | users.rs:52; resources.rs:79 | "Application audit is turned off." |
| `set detect.app_audit_enabled = true` | detections.rs:138 | "Turn on Application audit in **System → Configuration → Detection**." |
| `detect.policies_dir is empty` | policies.rs:42 | "No policies are configured yet." + link to add one |
| `audit.enabled = false` | system.rs:198 | "The audit ledger is turned off." |
| `systemctl restart garmr` (raw shell) | system.rs:355 | Keep the exact command **inside** a "How to restart" block, but lead with plain text ("garmr must be restarted for this to take effect."). |
| `garmr hunt` / `garmr learn` / `garmr synth-eval` / `garmr backup …` | intelligence.rs:191; learning.rs:44,49; system.rs:725 | Explain the action in words first; show the exact command as an offline-operation snippet (Phase 15 honest offline panels). |
| `GARMR_ADMIN_TOKEN` (input placeholder) | system.rs:777 | "Paste the existing admin credential" (don't name the env var as the label) |
| `GARMR_SECRET_KEY` / `/etc/garmr/secret.key` | system.rs:904 | "A secret-store master key must be provisioned." + where |
| `GARMR_SHADOW` | learning.rs:49,63 | "shadow evaluation is not enabled" (describe, don't name the var) |
| `hybrid Query-IR (structured + full-text + meaning)` | audit.rs:122 | "Searched by structure, text and meaning." (put "Query IR" in an explainability popover only) |
| `CodeVault 3D entity topology` (iframe title + body) | map.rs:39,45 | **3D topology** |
| `detector_config` (raw) | learning.rs:36,63 | "detector configuration" |
| `read-only follower` | system.rs:510 | Keep, but add help: what a follower is and why it's read-only |
| `sealed store` (secret-source badge) | system.rs:948 | "Encrypted store" |

Doc-comment-only jargon (`Tantivy`, `RBA`, `lakehouse`, `figment`, `eframe`, `facett`, `DoD`/`Phase`
markers, `garmr-core`) is **not** user-facing and needs no change — except `CodeVault 3D entity
topology`, which is on screen (above).

---

## Highest-priority renames (do first — most visible)

1. **Model provider** — collapse LLM / provider / Backend / model / "external backend" / Models &
   registry / model router to **Model provider** + **Model**. Rename the "Backend" field →
   **Provider type**; "Test model" → **Test model connection**. (system.rs:23,26,134,144,163;
   investigations.rs:334–335; ask.rs:50)
2. **Investigation** — replace every content-side "Case"/"case(s)" with "Investigation"/"investigations"
   (list count, empty/loading, kv key, drawer, entity section, command palette, Command Center tiles).
   Nav/URL already say Investigations. (route.rs:230; investigations.rs:74,69,132,204; command_center.rs;
   drawer.rs:75,77; entity.rs:63; command.rs:73; shell.rs:108)
3. **API credential** — standardize the Access tab: "API credential" (machine), "Legacy environment
   credential" (env token), "Secret" (provider secret). Drop bare "token"/"operator token" as names.
   (system.rs:769–921; shell.rs:66)
4. **Application vs host** — pick **Application** as the user label in the Applications area; rename
   "Open host"/"Peek host" → "Open application"/"Preview application"; change "filter by rule or host…"
   → "filter by rule or application…". (applications.rs:47; audit.rs:342–345; command.rs:89;
   investigations.rs:75; detections.rs:43) — *flag for Alice if Application≠host is intentional.*
5. **Behavioral anomaly** — introduce the term in Detections + user Behavioral profile help.
6. Map all **raw enum variants** through friendly labels (table above).
