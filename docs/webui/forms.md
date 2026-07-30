# garmr WebUI — form standards

Group fields by the user's intent, not the backend object's shape. Show the common fields first;
put advanced settings behind a clearly labelled expandable area (progressive disclosure).

## Structure (example: a model provider)
- **Basic:** name · provider type · endpoint · model · credential.
- **Advanced (collapsed):** timeout · retry · task routing · data-classification ceiling ·
  concurrency · daily budget.

Do not show every advanced setting by default. Use sensible defaults, but never silently create an
unsafe configuration through a default.

## Behaviour
- Clear required-field indication.
- Inline validation **after** the user has interacted with a field — never a red error before a
  field is touched.
- Preserve entered data after a server error (don't wipe the form).
- Prevent accidental duplicate submissions (disable while saving; show a saving state, then a saved
  state).
- Warn before leaving with unsaved changes.
- Distinguish clearly: **Save draft**, **Validate**, **Apply**, and **Test** — these are different
  operations and must not share a vague label.

## Configuration-specific (Configuration Center)
- Show, per field: **configured value** vs **effective value**, the **source** (default / TOML /
  UI override / environment), the **reload class** (hot-reload / restart-required), and the
  **security impact**.
- When an environment variable overrides a UI field, say so plainly: "Set in the UI but overridden
  by an environment variable." Never present the UI value as active when it isn't.
- Use **staged editing** (edit → review → apply), not apply-on-blur. Show a review summary before
  applying multiple settings: fields changed, old → new, restart required, affected subsystem,
  rollback support.

## Secret fields
Never a plain text input. A secret field shows: **configured / missing**, last updated, provider,
a **Replace secret** action (write-only — the value is never read back), and a **Test connection**
action. See `docs/security/secret-storage.md`.
