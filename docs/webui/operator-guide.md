# garmr WebUI — operator guide

## Serving the console

`garmr serve` hosts the built bundle at `/` on the API bind when the UI dir is
configured:

```toml
[ingest]
api_bind = "127.0.0.1:3110"
ui_dir   = "./crates/garmr-webui/dist"   # or set GARMR_UI_DIR
```

Rebuild the bundle with `trunk build --release` (in `crates/garmr-webui`), then
**restart serve** — the server hashes the SPA's inline bootstrap into a strict
`script-src` CSP at startup, so a new bundle needs a restart or the script is
CSP-blocked.

## Deployment shapes the console adapts to

The console reads `GET /api/capabilities` on load and adapts — you do not configure
the UI separately:

- **Air-gapped** (`GARMR_AIRGAP=1`) — the AI/NL surfaces show a *degraded: local
  model only* state; the status bar shows `AIR-GAPPED`. No external request is ever
  made (the CSP is `connect-src 'self'`).
- **No LLM / no key** — the AI surfaces render a labelled disabled/degraded state
  rather than erroring; everything deterministic keeps working.
- **HA follower** (`read_only`) — write affordances are hidden; the status bar shows
  `role: follower`.
- **Disabled planes** — app-audit, environment model, cold storage, etc. each render
  a panel naming the exact config switch to enable them.

## Health at a glance

- **Command Center** — the prioritised attention feed + health strip.
- **Data Sources** — per-collector volume, ingest lag, staleness (STALE = > 1 h).
- **System › Audit integrity** — ledger records, head/verified sequence,
  checkpoints, signing key. (`garmr audit verify` is the offline, fail-closed check.)
- **System › Posture & HA** — auth/passkey/CSRF/headers/airgap/read-only + HA role.

## Air-gap / no-egress

Nothing in the console calls an external host: all assets are same-origin, the CSP
forbids external `connect-src`/`script-src`, and the optional 3D map is served
same-origin. Safe for air-gapped government, defense and industrial deployments.

## Status bar

Bottom of every screen: connection state, `garmr <version>`, HA role, and an
`AIR-GAPPED` marker when egress is denied. A per-source error replaces it when a
fetch fails.
