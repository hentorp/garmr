# garmr WebUI — help & status system

The console explains itself in layers. This document is the decision guide: **which
component to reach for**, and the accessibility contract each one honours. All of these
live in `crates/garmr-webui/src/ui.rs` (help + states) and `status.rs` (the color model),
so the same concept looks and behaves the same on every page.

## Pick the right affordance

| Situation | Use | Notes |
|---|---|---|
| A control or term needs one or two sentences of explanation | **`ui::help_tip(text)`** | The "?" tooltip. Hover / focus / tap. The text is also the accessible name. |
| An explanation needs a heading, consequences, security implications, or a docs link | **`ui::InfoPopover`** | The "ⓘ" popover. Click / keyboard, Escape + click-outside to close. |
| A field in a form needs a label plus a hint | label text + a trailing `help_tip` | Keep the essential part in the visible label; the tooltip is supplementary only. |
| A capability is off / not configured | **`ui::disabled_panel(title, &FeatureState)`** | Explains *why* and *what to do*, never a dead control. |
| A whole page/section is empty, loading, or errored | **`ui::empty` / `ui::loading` / `ui::error_box`** | Distinguish "no data" from "no match" from "disabled" (see microcopy). |
| A standing, page-level condition (air-gap, degraded) | **`ui::banner(class, msg)`** | Persistent, in-flow. |
| A transient result of an action | the activity **toast** (`ActivityToast`) | Success/failure + audit reference. |
| A status value (state, severity, confidence, classification) | **`ui::pill` / `sev_badge` / `state_badge` / `confidence`** via `status.rs` | Colour is always paired with text (WCAG 1.4.1). |

**Do not** use a tooltip or popover for information the user must have to act — that stays
visible (product principle 5). Tooltips and popovers are supplementary.

## `help_tip` — the tooltip

`ui::help_tip(impl Into<String>) -> AnyView`

- Renders a focusable `<button class="helptip">` with a `?` glyph and a bubble.
- **Accessible name = the help text** (`aria-label`), so a screen reader announces the full
  explanation; the visual bubble is `aria-hidden` to avoid double announcement.
- Reveals on **hover, keyboard focus, and tap** (the trigger is a real button). Dismisses on
  blur. Honours `prefers-reduced-motion` (global rule disables the fade).
- The bubble is width-capped (`min(280px, 70vw)`) and opens upward; for triggers near the top
  of the viewport, prefer `InfoPopover` or revisit positioning (see Known limitations).

Example:
```rust
view! {
    <label>"Prefilter model" {ui::help_tip("A small, cheap model that screens events before the main model runs, to save budget. Optional.")}</label>
}
```

## `InfoPopover` — the rich popover

`<ui::InfoPopover heading="…" body="…" doc=Some("/docs/…".into()) />`

- `heading` and `body` are `impl Into<String>`; `doc` is an optional URL rendered as a
  "Documentation ↗" link (opens in a new tab, `rel="noopener"`).
- Opens on click or keyboard activation of the "ⓘ" trigger (`aria-haspopup="dialog"`,
  `aria-expanded` reflects state).
- On open, **focus moves to the dialog's close button**; **Escape** and an **outside click**
  (scrim) close it. The panel is `role="dialog"` with the heading as its accessible name.
- Width-capped (`min(340px, 84vw)`), opens upward.

Use it for the Phase-6 explanation sites that need more than a sentence — model data-classification
ceiling, air-gap eligibility, recovery, follower/writer role, dangerous-miss, etc.

## The status/color model (`status.rs`)

Every domain value maps to exactly one reserved class — `pass` / `warn` / `bad` / `dim` — and the
CSS turns that into the theme's reserved colour. One mapping, applied everywhere, so "escalated"
is the same red on the Command Center, the Investigation list, and the drawer. **Never** hardcode a
status colour in a view; add or reuse a mapper in `status.rs` and render through a `pill`. Always
pair the colour with the value's own text label.

Raw backend enum values must be humanised before display — see `docs/webui/terminology.md`
(status/enum label map). Do not render `needs_human`, `detector_config`, `governed`, etc. verbatim.

## Accessibility contract (applies to all of the above)

- Every interactive control has an accessible name (visible text, `aria-label`, or a labelled
  child). Icon-only buttons carry `aria-label` (see `drawer.rs` "Close", the theme toggle).
- Colour is never the only signal (WCAG 1.4.1). Keyboard operability for anything clickable
  (WCAG 2.1.1) — clickable tiles (`ui::metric`) are `role="button"`, focusable, and respond to
  Enter/Space.
- Hover is never the only way to reveal information — focus and tap work too.
- `prefers-reduced-motion` is respected globally (`index.html`).
- Focus is visible globally (`:focus-visible` outline in `index.html`).

## Known limitations / follow-ups

- `help_tip` and `InfoPopover` currently open **upward** with a CSS width cap; there is no
  JS-measured flip yet, so a trigger very close to the top or right edge can clip. Tracked for
  Phase 18 (add a direction prop or measured placement) and verified live at multiple widths/zooms
  in Phase 20.
- `field_help` (label + tooltip as one component) is not yet extracted; compose `label` + `help_tip`
  until forms are reworked (Phase 9).
