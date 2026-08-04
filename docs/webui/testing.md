# garmr WebUI — testing

## Quality gates (run after every major change)

Backend (the main workspace):

```bash
cargo fmt -p garmr-cli --check
cargo clippy -p garmr-cli --features "semantic loki-compat flight" --bin garmr
cargo test  -p garmr-cli --features "semantic loki-compat flight" --bin garmr
```

Note the `--bin garmr`: **`garmr-cli` has no lib target**, so `cargo test -p
garmr-cli` alone finds nothing to run. Easy to miss, and it makes a suite look
green when it never executed.

Frontend (`crates/garmr-webui` — its own nested workspace):

```bash
cd crates/garmr-webui
cargo fmt --check
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo test  --target x86_64-unknown-linux-gnu --lib     # host-target unit tests
cargo build --target wasm32-unknown-unknown --tests     # browser tests compile
trunk build --release                                   # the deployable bundle
```

The nested workspace is the other easy miss: `cargo fmt --all`, `cargo clippy
--workspace` and `cargo test --workspace` **from the repo root all skip
garmr-webui entirely**. Every command that must cover it passes
`--manifest-path crates/garmr-webui/Cargo.toml`.

Current status: 87 frontend unit tests, 5 backend entity-search tests, 15 browser
tests (compiled — see below); clippy-clean with warnings as errors on the wasm
target; release bundle ≈ 2.3 MB against a 3 MiB CI budget.

## Where each kind of test lives, and why

**Host-target unit tests** (`cargo test --lib`) carry the decision logic. The
modules holding it — `auth`, `srcstate`, `confirm`, `setup`, `timerange`,
`palette`, `route` — are deliberately free of `web_sys`, so the rules that decide
whether a token is attached, whether the board may claim "all clear", whether a
validation still applies to the staged values, and whether a URL round-trips can
be tested with no browser and no wasm runner. That is what makes them runnable in
CI at all.

**Browser tests** (`crates/garmr-webui/tests/browser.rs`, 15) carry what needs a
DOM: focus movement and the modal tab trap, the ARIA attributes actually emitted,
roving tabindex on the tab list, the skip link's place in the tab order, and the
actionable shape of the authorization and loading states. They encode invariants
rather than markup, so they fail on a regression rather than on a reformat.

**Backend tests** cover the entity-search bounds: an empty query must match
nothing (so the endpoint cannot become a bulk export of the case store), and the
caller must not be able to raise the per-kind ceiling.

## CI

`.github/workflows/webui.yml` runs fmt, clippy against the wasm target with
warnings as errors, the host unit tests, the browser tests headless in Chrome,
axe-core against the built bundle, a layout check at four viewports, the release
build, and a 3 MiB bundle-size budget. Layout-check screenshots are uploaded as
artifacts.

**The browser tests, the axe step and the layout check have never been executed.**
They are compile- and syntax-verified only; CI is their first real run, and it
should be expected to need fixing.

### Why those three cannot run on a developer laptop (at least this one)

Both routes were tried; both are closed, for independent reasons:

- **A headless browser is OOM-killed.** `systemd-oomd` kills on PSI *pressure* in
  the user slice, not on a cgroup ceiling — verified at `MemoryHigh=8G`,
  `MemoryMax=3G` and `MemoryMax=10G`, all ending in `signal: 9`. That 10G fails
  identically to 3G is the proof that no memory setting helps. If you retry, use
  `MemoryMax` rather than `MemoryHigh` so the kill stays contained to the scope.
- **axe-core cannot be injected into the running console.** The CSP is
  `connect-src 'self'` — the same rule that stops a crafted URL repointing the
  SOC's data source — so the page correctly refuses to fetch an external analysis
  library. Serving axe from the same origin would work; weakening the CSP is not
  an acceptable way to make a check pass.

CI has a browser, memory and the bundle on disk, which is why all three live there.

## Browser verification against a real deployment

The console is driven against a **real** `garmr serve`. Prefer text tools
(`read_page`, `get_page_text`, `javascript_tool`) over screenshots — a burst of
screenshots is the OOM trigger described above.

Two traps worth knowing before verifying layout by hand:

- **`resize_window` does not resize the viewport reliably.** It reports success
  while the inner viewport stays clamped. Use a same-origin **iframe sized
  exactly** instead; media queries then resolve genuinely against it.
- **A hidden tab freezes in-flight CSS transitions.** A geometry read of an opened
  drawer can return its pre-animation position indefinitely. Assert on
  class/ARIA/DOM state, never on animated geometry.

Verified end-to-end against the lab, with evidence recorded per workstream:

- **Authorization** — protected GETs carry the operator token; a 401 bounces to
  the passkey login only when passkey auth is available, and never from `/login`
  itself; a 403 never redirects; `next=` is sanitized to same-site paths with
  credential-shaped parameters stripped.
- **Command Center** — with injected 500/503 responses, audit integrity goes
  verified/green → **Unknown**, counts from failed sources render **Unknown**
  rather than `0`, and a banner names each failed source with a recovery action.
- **Responsive** — no horizontal overflow at 386×840, 764×1020, 1020×764 and
  1436×896; the drawer opens, traps focus, closes on Escape/backdrop/navigation
  and restores focus to its toggle.
- **Confirmations** — Apply is gated on a validation of the *exact* staged values;
  editing after validating closes it again with a stated reason. Log-out-all
  requires an exact typed phrase.
- **Setup** — `/system` lands on Setup while incomplete; every unfinished step
  offers the route that actually resolves it; host-only steps show the command.
- **Time range** — lives in the URL as `t=`, survives reload and Back/Forward, is
  carried across areas, and refuses invalid custom ranges *visibly*.
- **Command palette** — searches `/api/entities/search`; **no bulk collection
  fetches remain**; nonsense input yields exactly one result, an explicitly
  labelled search action, and never an invented entity.

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
