# garmr WebUI — accessibility

Target: **WCAG 2.2 AA** where practical for a dense analyst console.

## Implemented

- **Colour is never the only signal.** Every severity/status/confidence/data-quality
  indicator pairs its reserved colour with a text label (WCAG 1.4.1). See
  `status.rs` + the `ui::*` badges.
- **Keyboard.** All controls are real `<button>`/`<input>`/`<select>`/`<a>` elements
  (no click-only `div`s for actions); the global command palette is Ctrl/Cmd-K;
  Escape closes the palette then the drawer. Focus is visible via a `:focus-visible`
  outline token. On navigation, focus/scroll returns to the top of `<main>`.
- **Landmarks & names.** `<nav aria-label="Primary">`, `<nav aria-label="Breadcrumb">`,
  `<header>`, `<main id="main" tabindex="-1">`, `<footer>` status bar; the drawer is
  `role="dialog"`, tabs are `role="tablist"`/`role="tab"` with `aria-selected`, the
  activity toast is `aria-live="polite"`, the relationship graph `<svg>` has
  `role="img"` + `aria-label`.
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
- **Themes.** Light and dark both defined with high-contrast ink tokens; the viewer's
  choice persists (localStorage) and applies on load.

## Known gaps / to-improve

- **Mobile navigation.** Below 1000 px the sidebar collapses off-canvas but has no
  hamburger toggle yet; the console is desktop-first (an analyst SOC surface). The
  page never overflows horizontally and tables scroll within their own container.
- **Formal audit.** Contrast ratios and screen-reader flows were verified by
  construction and DOM inspection, not yet by an automated axe-core / assistive-tech
  pass. Recommended as a follow-up.
- **Dialog focus-trap.** The drawer/palette close on Escape and scrim click; an
  explicit focus-trap loop is not yet implemented.
