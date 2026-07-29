# Configuration & the Configuration Center

garmr is configured through a compiled-defaults → base TOML → generated override →
`GARMR_*` env chain, and the **Configuration Center** (System → Configuration in the
web console) is the read/write surface over it. This document covers how config is
resolved, what you can change from the console, and how changes take effect.

## Precedence

Effective config is resolved in this order (later wins):

1. **Compiled defaults** — every field has a sensible default.
2. **Base TOML** (`--config` / `GARMR_CONFIG`, else `garmr.toml`) — operator-owned,
   hand-edited, the source of truth for install-time settings.
3. **Generated override** (`<state-dir>/garmr.override.toml`) — machine-written by
   the console's config-write path; never hand-edit it.
4. **`GARMR_*` environment** — wins over the file layers for the fields it maps.
5. **`GARMR_AIRGAP`** — a hard security override read directly from the env, *not*
   part of the figment chain, so the override layer can never disable airgap.

If the override file is malformed or corrupted, `Config::load` is **fail-soft**: it
logs a warning and falls back to base + env, so a bad override can never brick the
offline/recovery commands (`audit verify`, `backup`, `query`).

## Reading config (Configuration Center)

Each setting shows its **effective value**, **source** (file/default vs an
environment override), **reload class**, and any restart/airgap notes. Secret
values are never shown — only whether one is configured. The whole surface is
admin-gated.

Reload classes:

| Class | Meaning |
|-------|---------|
| `immutable` | Fixed at install (store paths, node identity). Never editable from the console. |
| `restart` | Read once at startup; a restart applies a change. |
| `governed` | A governed artifact (policies/catalog) — draft → approve → promote hot-swaps it. |

## Changing config (validate → apply → roll back)

The console edits a **deny-by-default** allow-list of safe operational settings
(retention, model, budget, prefilter model, max tokens/iterations, detector
toggles, risk threshold, cold-tier settings). Everything else — capability fields
(the executor argv templates), identity, store paths, egress, the audit ledger,
and secrets — is **refused**, so a console change can never grant a new capability.

The flow (each step is a real API call, all Admin + audited):

1. **Stage** edits in the Configuration Center — they don't apply on blur.
2. **Validate** (`POST /admin/config/validate`) — a dry-run that parses + type-checks
   the change, refuses non-editable and domain-invalid values (e.g. a non-positive
   `risk_threshold` with RBA on, or a zero `max_tokens`), and previews the diff
   (from → to, reload class) + restart requirement + any env-shadow warnings.
3. **Apply** (`POST /admin/config/apply`) — Admin + `config:write` scope + step-up +
   a fail-closed audit record. Persists a new **versioned revision** (atomic,
   0600, fsync'd) and swaps the active override.
4. **Roll back** — the revision history lets you re-apply any earlier revision as a
   new revision (linear history; nothing is rewritten).

Changes are read once at startup, so every response carries an honest
`restart_required`.

## Restart-pending

After an apply, the console shows a **"restart pending"** banner (with the exact
command, `systemctl restart garmr`) whenever the persisted override differs from
what the running process loaded. It clears after a restart. The daemon records its
startup override hash and compares it to the on-disk override to detect this.

Self-restart from the console is intentionally not offered: the service runs as an
unprivileged user with no permission to restart its own unit.

## Offline-only operations

Some operations require the daemon stopped (single-writer store) or host access:
compaction, reindex, restore, and promote. The Configuration Center shows an
**honest panel** for these — why each is offline, the exact host command, its
prerequisites, and cheap status — but it never runs them.

## Related

- [Secret storage](../security/secret-storage.md)
- [Configuration recovery](configuration-recovery.md)
- [First-run setup](../setup/first-run.md)
