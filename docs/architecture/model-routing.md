# Model routing & egress — architecture

Status: initial (expanded in the egress-chokepoint work and Phase 10). Covers the
air-gap kill-switch (invariant #1) and the policy-driven multi-model router with
local-GPU serving as an external process (invariant #6).

## Egress chokepoint (invariant #1)

Today `GARMR_AIRGAP` (`crates/garmr-cli/src/main.rs:39`) only empties the IOC-feed
list and sets a no-op flag. Twelve egress points exist; nine are reachable from
`garmr serve` and only one is actually closed by air-gap. The fix is one enforced
gate.

**`EgressPolicy`** — a single object, constructed once at startup, consulted at
**client-construction time** by every outbound-capable component:

- LLM providers (`crates/garmr-llm`: Anthropic const URL + OpenAI-compat base),
- notifier sinks (`crates/garmr-agent`: Matrix, webhook, SMTP),
- external MCP client spawn (`crates/garmr-agent/src/mcp_client.rs`),
- S3 object store (`crates/garmr-retention`: HA + cold tier).

Rules:

- `GARMR_AIRGAP=1` ⇒ **every external destination class is denied**, and the
  denial is **unoverridable** by any other config/env. Local-loopback endpoints
  (e.g. a vLLM at `127.0.0.1`) are the only permitted destinations, and only when
  a destination is explicitly classified `local`.
- Each egress attempt resolves an `EgressClass` (`llm_external`, `llm_local`,
  `ioc_feed`, `notify`, `object_store`, `mcp_remote`, `telemetry`,
  `model_download`, `update_check`) and is **allowed or denied by policy, and
  audited** (`AuditEvent`, egress-policy decision).
- **No silent fallback.** A denied local model never silently falls back to an
  external provider; the caller sees an explicit policy denial.

Tests prove air-gap blocks every class even when other config tries to enable it,
and that restricted data never routes to an external model.

### Shipped

The chokepoint is implemented in `garmr_core::egress` (`EgressPolicy` + the pure
`decide`/`check`, `host_of`, `is_local`, `airgap_from_env`, an `init`/`global`
singleton) and installed ONCE in `load_config` with the config allowlist
(`[route.egress] allow`) + a ledger audit sink; `GARMR_AIRGAP` (parsed in one
place) OVERRIDES config. All NINE in-daemon egress producers are gated at
construction: the two LLM providers, Matrix / webhook / SMTP, the external MCP
child spawn (categorically non-local — every external MCP child is denied under
air-gap), the IOC feeds, and the S3 cold / HA object store. A source-walk test
(`crates/garmr-cli/tests/egress_chokepoint_lint.rs`) FAILS the build if a raw
outbound client is constructed anywhere outside the reviewed allowlist — the
structural backing for "no bypass" (invariant #2). Security-critical parser
properties are pinned by test: the host is taken AFTER the last `@` (no
userinfo-SSRF bypass), `localhost` matches on a dotted boundary only, an
unparseable destination is non-local (fail-closed), and the allowlist is a
dotted-suffix parent-domain match.

### Scope of the guarantee (honest residuals)

The chokepoint governs **garmr's OWN autonomous egress**. It does NOT govern:

- **The SOAR executor** (`crates/garmr-agent/src/executor.rs`): a human-approved
  playbook command is a separate subprocess with a normal PATH; its egress is
  gated by the per-action human approval (`ActionState::Approved`), not by this
  policy. Air-gap does not forbid a subprocess a human explicitly approved.
- **Control-plane clients** (`garmr` CLI / `garmr-mcp` / `garmr-ui`) that talk to
  `GARMR_API_URL` — separate operator processes the daemon's in-process policy
  cannot govern; the default target is garmr's own loopback daemon.
- **What a (non-air-gap) external MCP server does once running** — the policy
  gates WHETHER the child spawns, not its behavior. Air-gap closes this entirely
  (every spawn denied); online mode trusts operator config.

These are documented residuals, not covered coverage.

## Model router (Phase 10) — shipped MLP

Shipped: a policy-driven `ModelRouter` selecting exactly ONE model per case by
**data classification + air-gap + availability**, over the SAME egress chokepoint.
The pure policy lives in `garmr_core::router` (`DataClassification` lattice,
`ModelEntry`, `decide`, `classify_event`); the runtime `ModelRouter` in `garmr-llm`
reuses the one egress-gated `build_backend_provider`; the agent routes per case in
`triage`; config is `[route.router]` (a catalog of models + a
`default_classification` floor), empty = today's single `[agent]` model. `garmr
models [--for <class>]` shows the catalog + the fence decision offline.

Two hard, non-removable floors: **restricted/confidential data never reaches an
EXTERNAL model** (`EXTERNAL_CEILING = Internal`; config may only tighten; locality
is derived from the endpoint host, not a flag) and **no silent fallback** (a
degrade or a build denial resolves to the existing audited `NeedsHuman` state, and
the chosen model is stamped as provenance on the immutable `AgentPrediction`).

**Scope + operator responsibilities (honest residuals):**

- **`cfg.agent` must be policy-constructible.** It is the base provider (the hunt
  loop + the empty-catalog fallback), built eagerly at startup. In an air-gapped
  deployment point `[agent]` at a LOCAL endpoint (`backend = open_ai_compat`,
  loopback/LAN `openai_base_url`), or startup fails — the catalog does not make an
  external `[agent]` constructible.
- **Classification is scoped to the trigger event.** `classify_event` lifts
  sensitivity only from the trigger event's canonical access fields (a data
  subject ⇒ Confidential, a watched subject ⇒ Restricted) + an explicit
  `data_classification` tag. PII in a free-text message body, or pulled in by the
  tool loop from OTHER events, is NOT auto-classified. The mitigation is the
  operator's `default_classification` FLOOR — **set it to `confidential` for a
  register/PII deployment** (this also fail-closes the ask/hunt/rule surfaces off
  external models). The router gates the MODEL endpoint; an external MCP tool call
  during a locally-routed case is a separate egress the chokepoint gates (closed
  under air-gap).

### Design vocabulary (target; the MLP is the subset above)

`garmr-llm` becomes a policy-driven router over model **roles**: `embedding`,
`reranker`, `classifier`, `local_reasoning_small`, `local_reasoning_large`,
`external_reasoning`, `evaluator`.

Local GPU serving is an **external local process** (vLLM / llama.cpp / Ollama)
reached over an OpenAI-compatible API. garmr owns routing, auth, capability
discovery, health, queueing, timeouts, model identity, structured outputs, audit,
and fallback policy — but embeds **no CUDA/vLLM**.

Routing policy inputs: task, data classification, site, security zone, air-gap
status, model capability, latency requirement, token budget, provider health,
operator policy. **Restricted raw logs never silently route to an external
model; every route decision is audited.**

### Capability probing → `ModelCapabilityProfile`

At startup each model is probed for: tool calling, structured output, JSON-schema
conformance, parallel tool calls, max context, token counting, stop reasons, seed
support, latency, throughput, a prompt-injection golden set, invalid-output rate,
and OOM behavior. Results persist in a `ModelCapabilityProfile`; structured-output
constraints are used when supported.

### Degraded mode (no model / CPU-only)

Fully functional without any LLM (invariant #5): ingest continues, deterministic
detections continue, cases open, queries work; agent triage is queued or marked
unavailable; no data is lost; health clearly reports the missing model.

### Observability & sensitivity

LLM operations are instrumented with OpenTelemetry-compatible GenAI fields where
practical, **but the tamper-evident audit ledger is the authoritative audit
source**. Prompts, tool arguments, and outputs are sensitive: filtered, truncated,
redacted, hashed, or encrypted per content mode. Telemetry export is itself an
egress class and is denied under air-gap.
