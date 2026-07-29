# garmr WebUI — design system

An operational command-center aesthetic: calm, credible, dense where analysis
benefits from density and spacious where comprehension benefits from space.
Dark-by-default with a light theme, high contrast, distinctive without decorative
science-fiction.

## Tokens (`index.html`)

CSS custom properties, themed via `:root` + `:root[data-theme="light"]` +
`prefers-color-scheme`:

- **Surfaces** — `--bg`, `--bg-2`, `--panel`, `--panel-2`, `--panel-3`, `--line`.
- **Ink** — `--ink`, `--ink-dim`, `--ink-mute`.
- **Reserved status** — `--point` (pass/calm), `--warn` (watch/running),
  `--bad` (attention/fail), `--accent` (glacier blue), `--violet` (AI).
- **Shape/motion** — `--radius`, `--radius-sm`, `--shadow`; all transitions honour
  `prefers-reduced-motion: reduce`.

## Reserved severity / status vocabulary

`status.rs` maps every domain state/severity to one of four classes — `pass`,
`warn`, `bad`, `dim` — and the CSS turns the class into the theme's reserved
colour. **Colour is always paired with the value's own text label** (WCAG 1.4.1);
no status is communicated by colour alone.

## Primitives (`ui.rs`)

| Primitive | Use |
|-----------|-----|
| `pill(class, label)` | the status/severity atom |
| `sev_badge`, `state_badge` | severity / lifecycle-state badges |
| `confidence(v)` | a bar + its own `%` text |
| `audit_ref(id)` | a tamper-evident ledger reference (evidence, not decoration) |
| `metric(k, v, cls, on_click)` | a dashboard tile |
| `page_header(title, blurb)` | self-describing screen header |
| `kv_list(pairs)` | detail lists |
| `empty` / `error_box` / `loading` | the non-happy-path states |
| `disabled_panel(title, feature_state)` | a labelled "not configured / disabled" panel with the exact missing dependency |
| `banner(class, msg)` | inline degraded/info notice |

Shared layout helpers live in `views/mod.rs`: `table(headers, body)` (wrapped in an
`overflow-x: auto` container so wide tables scroll inside themselves, never the
page), `tabs(items, current, on_select)`, and the `Fetch` resource with its
`framed(key, empty_msg, body)` state wrapper.

## System-state language

The console distinguishes, everywhere, between: **healthy**, **degraded**,
**disabled**, **not configured**, **learning**, **waiting for approval**,
**failed**, **stale**, and **incomplete data** — each with text + iconography +
an accessible label, never colour alone. The capability manifest's per-feature
`{state, reason}` drives the disabled/degraded panels.

## AI vs human

Model-generated content is fenced in a distinct violet-tinted **AI card** tagged
`AI`, always carrying a "verify against evidence" note; human judgement lives in a
separate **human card** tagged `human`. They are never visually merged (see
Investigations detail).

## Motion & density

- Motion is minimal and reduced-motion-aware (a spinner, a drawer slide, tile hover).
- Tables are dense (8 px row padding, tabular-nums) with sticky headers; prose and
  headers are spacious. No card-soup, no gradients/glow, no colour-only severity,
  no tiny-gray-text as the primary presentation, no raw-JSON-blob defaults (event
  detail is structured; raw payload is a collapsed `<details>`).
