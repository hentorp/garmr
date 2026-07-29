# Configuration recovery

The config-write path is designed so a bad change can't strand you. This covers how
to back out.

## Roll back from the console

Every apply/rollback is a **versioned revision**. In System → Configuration →
Revision history, roll back to any earlier revision — it is re-applied as a new
revision (linear history; nothing is rewritten). A restart loads it.

The `restart pending` banner tells you when an applied change hasn't yet been
loaded.

## If a change won't validate

`validate` refuses domain-invalid values before they can be applied — e.g. a
non-positive `risk_threshold` with RBA enabled (would fail startup) or a zero
`max_tokens` (would disable the agent). So the sanctioned console path cannot
persist a boot-bricking value; it is refused with a clear message.

## If the override is corrupted out of band

`Config::load` is **fail-soft**: if the generated override
(`<state-dir>/garmr.override.toml`) is malformed or produces a type conflict, garmr
logs a warning and falls back to base TOML + env. So a corrupted override never
bricks the daemon or the offline/recovery commands.

To fully reset the console-managed layer, remove the override file (and its
`config-revisions/` history) on the host with the daemon stopped; the next start
uses base + env.

## Immutable settings are never console-editable

Store paths, node identity, egress policy, the audit ledger location/key, executor
capability templates, and secrets are refused by the config-write validator, so a
console change can never move them. Change those in the base TOML on the host.

## Related

- [Configuration](configuration.md)
- [Break-glass recovery](../security/recovery.md)
