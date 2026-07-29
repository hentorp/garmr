# garmr WebUI — architecture

The console is a **client-rendered single-page app** (Leptos 0.7 / CSR / WASM),
served by `garmr serve` at `/` and talking to the same `/api/*` REST surface as
every other garmr client. All rendering happens in the browser; the server stays a
read-mostly API with server-authoritative writes.

## Module map (`crates/garmr-webui/src`)

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | The `App` shell, the reactive `Store`, router wiring (popstate), global keyboard, the `postMessage` bridge, session restore. |
| `route.rs` | The task-oriented `Area`/`View` model and **real URL routing** (`Nav`) over the History API — every screen has a stable URL; filters/tabs/queries live in the query string. |
| `caps.rs` | The client of `GET /api/capabilities` — typed accessors over the manifest, resilient to added fields. |
| `api.rs` | The fetch client: `get`/`send_get`/`send_post`, the structured `ApiError`, and the in-memory operator token. |
| `ui.rs` | The design-system primitives (badges, states, confidence, audit-ref, tiles, page header, disabled panels…). |
| `shell.rs` | Sidebar (grouped task nav), top command bar (breadcrumbs + palette trigger + time range + theme), status bar, activity toast. |
| `command.rs` | The Ctrl/Cmd-K command palette (navigate + jump to real entities + launch a search). |
| `drawer.rs` | The universal entity drawer (fast pivot surface). |
| `status.rs` | The reserved severity/state → status-class mapping (colour is always paired with a text label). |
| `views/` | One module per task area: `command_center`, `investigations`, `audit`, `users`, `applications`, `detections`, `policies`, `intelligence`, `learning`, `data_sources`, `system`, plus the shared `entity`, `graph`, `ask` renderers and `mod.rs` (render dispatch + `Fetch` + table/tabs helpers). |

## State model

`Store` is a small `Copy` struct of reactive signals shared by context:

- `nav: Nav` — `{ view, query }` signals kept in sync with the URL.
- `caps` — the capability manifest (`Option<Caps>`).
- `api_ok`, `errors` — connection + per-source error surface.
- `time_range` — the global time picker (drives Audit Explorer, Command Center).
- `drawer`, `cmd_open` — the drawer target and palette open state.
- `activity` — the activity-center feed (bounded).
- `operator` — whether an operator token is held this session.

Each **view fetches its own data** on demand via `views::Fetch` (a generation-guarded
GET resource). There is **no fixed global 5-second poll** — the old console polled
tail+cases+total+volume every 5 s regardless of the visible view; the new console
loads per view and refreshes on explicit user action, so human-paced and
model-priced surfaces are never polled.

## Routing

`Nav` hand-rolls History-API routing (no router dependency, minimal WASM cost):

- Navigating calls `history.pushState` and updates the reactive `view`/`query`.
- A `popstate` listener re-syncs from the URL (browser back/forward).
- A hard refresh cold-loads because `garmr serve` serves `index.html` for any
  unmatched path (SPA fallback), and `View::from_path` re-derives the screen.
- Every entity id is percent-encoded in the path; **sensitive tokens never appear
  in a URL** (the operator token is memory/sessionStorage only).

See [information-architecture.md](information-architecture.md) for the URL table.

## Data flow for a protected action

1. A control calls `api::send_post(path, body)`.
2. If an operator token is held (System › Access, or a passkey session cookie in
   production), it is attached as a bearer / sent automatically.
3. The server authorizes **independently** (`check_admin` / `check_analyst`),
   evaluates policy, mutates state, and writes a tamper-evident audit record.
4. The response's audit id is surfaced inline (an `audit …` reference) and in the
   activity toast. On 401/403 the UI renders an "authorize as operator" state, not
   a dead button.

The capability manifest only decides **which controls to draw**; it is never an
authorization decision. A read-only follower hides write affordances; a disabled
plane renders a labelled panel explaining exactly what to configure.

## Backend additions

Two thin, read-only endpoints were added to expose already-present backend
capability (see [backend-capability-matrix.md](backend-capability-matrix.md)):

- `GET /api/capabilities` (`crates/garmr-cli/src/api/capabilities.rs`) — the
  runtime feature/permission/health manifest.
- `GET /api/policies` + `GET /api/policies/:id` (`.../api/policies.rs`) — the
  access-policy set the app-audit plane enforces.

No backend rule, authorization, policy evaluation, learning gate, or state
transition moved to the client.

## Build & serve

- Dev: `cargo build --target wasm32-unknown-unknown` (~2 s incremental).
- Bundle: `trunk build` (dev) / `trunk build --release` (wasm-opt=z, ~1.3 MB).
- Served by `garmr serve` when `ingest.ui_dir` (or `GARMR_UI_DIR`) points at
  `crates/garmr-webui/dist`. The server hashes the SPA `index.html` inline
  bootstrap into a strict `script-src` CSP at startup, so **rebuilding the bundle
  requires restarting serve** (the inline-script hash changes).
