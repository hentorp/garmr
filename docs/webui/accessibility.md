# garmr WebUI — accessibility

Target: **WCAG 2.2 AA** where practical for a dense analyst console.

## Implemented

- **Colour is never the only signal.** Every severity/status/confidence/data-quality
  indicator pairs its reserved colour with a text label (WCAG 1.4.1). See
  `status.rs` + the `ui::*` badges.
- **Contrast.** Normal text meets 4.5:1 on every background it is used on, in both
  themes — measured, not assumed. The muted tier (`--ink-mute`) previously failed
  on all five panel backgrounds (2.98–3.98:1); it was lifted the minimum amount
  that clears the threshold while keeping the slate hue: `#8493a5` dark (4.56–6.08)
  and `#5d6d7f` light (4.50–5.30). The 10px muted labels moved to 11px, since that
  tier is where the colour was least legible.
- **Keyboard.** All controls are real `<button>`/`<input>`/`<select>`/`<a>` elements
  (no click-only `div`s for actions). A **skip-to-main-content link is the first
  tab stop**. The command palette is Ctrl/Cmd-K; Escape peels one layer at a time
  (palette → entity drawer → navigation drawer). Focus is visible via a
  `:focus-visible` outline token, and navigation moves focus into `<main>` so a
  keyboard user is not left parked in the sidebar.
- **Tabs.** Full ARIA tab pattern: the tab list is a single tab stop (roving
  tabindex), Arrow/Home/End move selection and focus together, and `aria-controls`
  points at a real `role="tabpanel"` labelled by its tab. `aria-selected` is an
  explicit `"true"`/`"false"` string — passing a Rust bool makes Leptos render a
  bare attribute for true and omit it for false, which left the tabs never
  announcing their state.
- **Modal surfaces.** The confirmation dialog, the command palette and the entity
  drawer are `role="dialog"` with `aria-modal`, move focus in on open, **trap Tab
  and Shift-Tab inside**, close on Escape, and restore focus to the control that
  opened them (`ui::trap_tab`, `ui::manage_modal_focus`).
- **Forms.** Every input, select and search field has an accessible name; a
  placeholder is never used as the label. Validation errors are wired with
  `aria-invalid` and `aria-describedby` pointing at an element that exists.
- **Announcements.** State views are live regions: empty and loading announce
  politely, an error asserts (`role="alert"`), and decorative glyphs are
  `aria-hidden`. The activity toast is `aria-live="polite"`.
- **Landmarks & names.** `<nav aria-label="Primary">`, `<nav aria-label="Breadcrumb">`,
  `<header>`, `<main id="main" tabindex="-1">`, `<footer>` status bar; the
  relationship graph `<svg>` has `role="img"` + `aria-label`. Every icon-only
  control carries an `aria-label` — audited across five views.
- **Navigation is real links.** Sidebar entries, breadcrumbs and table rows are
  `<a href>` with the destination's actual URL, so middle-click, Ctrl-click,
  "open in new tab" and "copy link address" all work; the active destination
  carries `aria-current="page"`. Table rows are no longer mouse-only.
- **Mobile navigation.** Below 1000 px the sidebar is an off-canvas drawer with a
  visible toggle (`aria-controls` + live `aria-expanded`), backdrop and Escape to
  close, close-on-navigation, focus moved in and restored, and background scroll
  locked. Controls get 44px targets at phone width.
- **The 3D topology is never the only way to read relationships.** Intelligence ›
  Relationships leads with an **accessible table**; the node-link graph is an opt-in
  accompaniment, and the heavy WebGL 3D map is an explicit, separate "Open 3D map"
  link — not the default surface.
- **Reduced motion.** `@media (prefers-reduced-motion: reduce)` disables all
  transitions/animations.
- **Structured detail, not JSON blobs.** Event detail renders normalized fields as a
  definition list; the raw payload is a collapsed `<details>`.
- **Escaped untrusted content.** All log/model-derived text is rendered as text
  nodes and control-char-stripped (`api::clean`); no untrusted HTML is injected.
- **Themes.** Light and dark both defined with AA-clearing ink tokens; the viewer's
  choice persists (localStorage) and applies on load.

## Verification

Browser tests in `crates/garmr-webui/tests/browser.rs` encode the invariants above
that need a DOM: glyph-only controls carry a name, the tab trap's focusable query
excludes disabled controls and anything outside the container, `aria-selected` is
an explicit string, the tab list is one tab stop, the skip link is first, and the
authorization state offers both a route out and a Retry.

An **axe-core pass runs in CI** (`scripts/axe-check.mjs`), failing the build on any
serious or critical violation. It cannot be run against the live console locally:
the CSP is `connect-src 'self'` — the same rule that stops a crafted URL
repointing the SOC's data source — so the page correctly refuses to fetch an
external analysis library. Weakening the CSP to make a check pass is not an
acceptable trade.

## Known gaps

- **The axe-core pass has never been executed.** It is written and wired into CI
  but unobserved; a headless browser is OOM-killed on the maintainer's machine
  (see `docs/webui/testing.md` for why no memory setting helps). CI is its first
  real run, and it should be expected to surface violations.
- **No assistive-technology pass.** Semantics were verified by DOM inspection and
  automated assertions, not by driving an actual screen reader.
