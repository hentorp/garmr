# ADR-0002: The Leptos WebUI is the single supported console; deprecate the native egui client

- Status: Accepted — **removal executed (Cycle 5)**
- Date: 2026-07-28
- Deciders: Alice (maintainer)
- Supersedes / Superseded by: —

> **Update (Cycle 5):** the removal condition is met — the WebUI now covers the
> full setup/config/access/LLM administration surface, so `garmr-ui` (crate,
> `--headless-state`, and the `facett-*`/`egui`/`eframe`/`ureq` workspace deps) has
> been deleted. `garmr-map` keeps its own egui in its independent workspace. The
> WebUI is verified end-to-end via the pve browser passes; `--headless-state`
> needed no replacement (it was garmr-ui's own smoke test, not the WebUI's).

## Context

garmr ships two analyst front-ends:

- **`garmr-webui`** — the Leptos CSR/WASM console served by `garmr serve` over the
  read/query + admin API. It is the deployed product surface (passkey login,
  capability manifest, the 12-area IA, the app-audit/UEBA planes, policies, the
  System governance tabs, and — as of this cycle — the Configuration Center,
  passkey/credential/session administration, and secret management).
- **`garmr-ui`** — a native desktop console (facett/egui + eframe) that talks to
  the same API over a blocking `ureq` client.

An active-code audit for the "configurable & securable through the WebUI"
initiative established the following ground truth (see
`docs/product/configuration-gap-analysis.md`):

- **`garmr-ui` is read-only.** It issues only GETs; it has no write/admin/approve
  path. Every operator action (approve/reject, promote, silence, case decision,
  and now config/credential/secret administration) exists only in the WebUI.
- **It is not daemon-wired.** It is a separate `[[bin]]` that requires a running
  `garmr serve`; it is a client, not part of the server.
- **It does not ship.** `scripts/deploy.sh` builds only `--bin garmr`; the systemd
  unit runs only `/opt/garmr/bin/garmr serve`; the reproducible release builds
  `--bin garmr`. `garmr-ui` reaches no production host.
- **It cannot do passkeys.** Browser WebAuthn + the HttpOnly session cookie are
  the interactive-auth model; a native egui window cannot participate.
- **The WebUI is a strict superset** of `garmr-ui`'s data views; `garmr-ui`'s only
  unique surfaces are "a native window" and the `--headless-state` render probe.
- **It is the sole main-workspace consumer** of `egui`/`eframe`/`facett-app`/
  `facett-grid`/`facett-card`/`facett-stat`/`ureq` and pulls the vendored facett
  subtree + GPU/display libs, which every `cargo build`/`clippy`/`test` in CI pays
  for.

`garmr-map` (the 3D topology) is assessed **separately** (see below) and is *not*
covered by this decision.

## Decision

**The Leptos WebUI (`garmr-webui`) is the single supported analyst and
administration console.** `garmr-ui` is **deprecated now** and **scheduled for
removal** once two conditions hold:

1. WebUI parity for every workflow an operator needs is confirmed (already true
   for the data surface; this cycle adds the remaining administration surfaces).
2. The test value of `--headless-state` is replaced by stronger **API-contract +
   Playwright browser tests** (deferred to the removal cycle).

Until then `garmr-ui` keeps building (no code is deleted in this cycle), but it is
marked deprecated and receives no new features.

`garmr-map` is **retained**. It is an independent workspace, served at `/map/` and
embedded via iframe; its use of `eframe`/`egui` is internal to a browser WASM
visualization and unrelated to the native desktop console. Removing `garmr-ui`
does not remove `egui`/`eframe` from `garmr-map`, and there is no browser
substitute for the 3D graph today.

## Consequences

Positive:
- One console to secure, test, and document; the passkey-first + scoped-credential
  + write-only-secret model has a single front-end boundary.
- On removal: the main workspace sheds `egui`/`eframe`/`facett-*`/`ureq` and the
  vendored facett subtree, cutting CI build/lint/test time and the dependency and
  packaging surface.

Negative / trade-offs:
- No native-desktop option for an operator who cannot use a browser. Given
  `garmr-ui` is read-only and unshipped, this is a theoretical loss.
- The `--headless-state` "see what the user sees, as data" probe must be replaced
  by browser/API tests before deletion, or render-regression coverage regresses.

Security impact:
- Net positive. Interactive access converges on the passkey/session model (no
  bearer token in a native client); the removal deletes a second API client and
  its duplicate auth/status code, shrinking the attack and maintenance surface.

Maintenance impact:
- Immediate: none (still builds). On removal: one binary, one API client, one set
  of status/severity formatting, one design system.

Migration:
- Operators using `garmr-ui` point a browser at `https://<host>` and log in with a
  passkey (or hold an operator token in System → Access on a token-only lab).
- Any future need for a scriptable, headless state dump is served by the API
  directly (the same endpoints `garmr-ui` consumed) rather than a native probe.

Follow-up (removal cycle, tracked in `docs/product/roadmap-webui-product.md`,
Cycle 5): port any last-minute unique helper, add API-contract + Playwright
coverage to replace `--headless-state`, then remove `garmr-ui` from the workspace,
CI, packaging, and docs, and drop the now-unused dependencies.

## Alternatives considered

- **Keep both consoles.** Rejected: two full analyst front-ends with no clear
  second role is exactly the duplication (API client, status formatting, views)
  this decision removes; `garmr-ui` cannot reach feature parity for the
  passkey/admin surfaces without re-implementing the browser security model.
- **Remove `garmr-ui` immediately.** Rejected for this cycle: the `--headless-state`
  render-probe still provides real test signal that must be replaced first, and a
  staged deprecation keeps a rollback path while WebUI parity is proven live.
- **Also retire `garmr-map`.** Rejected: it is an independent, shipped browser
  component with no WebUI substitute for 3D topology; it is out of scope here.
