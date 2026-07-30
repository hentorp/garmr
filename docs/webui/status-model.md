# garmr WebUI — status model

One status vocabulary, one colour mapping, applied everywhere — so the same concept looks the same
on every page and colour is never the only signal (WCAG 1.4.1). Implemented in
`crates/garmr-webui/src/status.rs` (mapping) and `src/ui.rs` (rendering).

## Reserved classes
Every domain value maps to exactly one reserved class; the CSS turns the class into the theme's
reserved colour. Colour is always paired with the value's own text label.

| Class | Meaning | Colour token |
|---|---|---|
| `pass` | ok / calm / healthy | `--point` (green) |
| `warn` | watch / running / pending | `--warn` (amber) |
| `bad`  | attention / failed | `--bad` (red) |
| `dim`  | neutral / inactive / unknown | muted |

Mappers (add here, never hardcode a colour in a view): `state_class`, `severity_class`,
`outcome_class`, `proposal_class`, `baseline_class`, `classification_class`, plus
`caps::FeatureState::class()`.

## The state vocabulary
Prefer these labels for equivalent states across pages (distinct appearances for distinct meanings —
never render Inactive, Failed, and Not-configured identically):

Active · Inactive · Healthy · Degraded · Failed · Not configured · Pending approval · Draft ·
Waiting for restart · Expired · Revoked · Learning · Stable · Drifting · Read-only.

## Never render raw enum values
Backend snake_case / internal variants must be humanised before display:
- `status::humanize(v)` — de-underscore + sentence-case (`needs_human` → "Needs human"). Used by
  `ui::state_badge`.
- Specific friendly maps where the plain form isn't enough: baseline `Candidate` → "Learning";
  reload class `governed`/`hot`/`restart` → "Governed"/"Hot-reload"/"Restart required";
  disposition `needs_human` → "Needs human".
See the full table in `docs/webui/terminology.md`.

## Rendering atoms (`ui.rs`)
`pill(class,label)` · `sev_badge` · `state_badge` · `confidence` · `audit_ref` · `metric` ·
`banner(class,msg)` · `empty` / `loading` / `error_box` / `disabled_panel`. Compose these; do not
re-implement status styling in a view.
