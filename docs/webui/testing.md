# garmr WebUI — testing

## Quality gates (run after every major change)

Backend (the main workspace):

```bash
cargo fmt -p garmr-cli --check
cargo clippy -p garmr-cli --features "semantic loki-compat flight" --bin garmr
cargo test  -p garmr-cli --features "semantic loki-compat flight"
```

Frontend (`crates/garmr-webui` — its own nested workspace):

```bash
cd crates/garmr-webui
cargo fmt --check
cargo clippy --target wasm32-unknown-unknown
cargo build  --target wasm32-unknown-unknown
trunk build --release           # the deployable bundle
```

Current status: backend tests **48 passed / 0 failed**; frontend builds with
**0 warnings** and **clippy-clean**; release bundle ≈ 1.3 MB.

## Browser verification

The console is driven headlessly against a **real** `garmr serve` with a seeded
warehouse (≈ 836 events / 6 hosts, 30+ triage cases, 11 behavioral baselines, a
live audit ledger, ingest health, ATT&CK coverage, 2 access policies). Verified
end-to-end:

- **Navigation** — every sidebar destination, deep links, `?tab=`/`?state=`/`?mode=`
  query state, browser back/forward, hard refresh, not-found.
- **Command Center** — prioritised attention feed (needs-human cases, risk over
  budget, stale sources, audit integrity) with links that navigate.
- **Investigations** — queue + filters; case detail with evidence timeline, the
  agent-analysis card (correctly surfacing the model-router *confidential-data
  fence* as the reason a case is held for a human), and a **recorded analyst
  decision returning a real audit reference** (`audit …`).
- **Audit Explorer** — Simple full-text + the time-range feed, Advanced hybrid
  Query-IR (per-result `[S]/[F]/[V]` provenance), Natural-language (capability-gated),
  structured event detail (not a raw JSON blob), pivots.
- **Users / Applications** — directory + detail derived from baselines/risk/host
  volume; the baseline-trust monitoring lifecycle.
- **Detections / Policies / Intelligence / Learning / Data Sources / System** — all
  render with real data or a labelled empty/disabled state; no error states.
- **Protected actions** — a decision without a credential returns **401 and the UI
  renders an "authorize as operator" state**; after holding the operator token
  (System › Access) the same action succeeds and shows the audit reference.
- **Command palette** (Ctrl/Cmd-K) — searches real entities (found the actual
  `reg_watchlist_target_lookup` case).
- **Responsive** — no horizontal page overflow at 375 / 768 / 1024 / 1440; wide
  tables scroll inside their own `overflow-x:auto` container.
- **No console errors, no failed unexpected requests, no WASM panics** in any tested
  workflow.

## Seeding a lab instance

```bash
# 1. config: enable the UI dir, the app-audit plane, the environment surface,
#    give the loki receiver a distinct loopback port (see garmr.example.toml).
# 2. start (placeholder LLM key is fine — the AI surfaces show a degraded state):
GARMR_CONFIG=./garmr.toml ANTHROPIC_API_KEY=… GARMR_ADMIN_TOKEN=… \
  ./target/release/garmr serve
# 3. seed via the live loki endpoint:
curl -XPOST --data-binary @fixtures/ssh-bruteforce.json  http://127.0.0.1:3101/loki/api/v1/push
GARMR_LOKI_URL=http://127.0.0.1:3101 bash scripts/audit-demo.sh
#    (+ ship fixtures/pg/audit-corpus.jsonl as source=postgres-jsonlog)
```

Note: behavioral baselines are **in-memory** and rebuild from live ingest, so
re-ship the pg corpus after a serve restart to repopulate Users/Detections.

## Deferred automated tests

A Playwright/`wasm-bindgen-test` suite is scaffolded conceptually by the manual
verification above but not yet committed as CI. See the final report's "deferred"
section for the exact reason and the recommended harness.
