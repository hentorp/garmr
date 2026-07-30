# Secret storage

garmr's secrets (LLM keys, Matrix/webhook/SMTP, the collector ingest token) can be
provisioned three ways, resolved in this precedence at startup:

1. **Environment variable** — an explicit `GARMR_*` (or `ANTHROPIC_API_KEY`) always
   wins. Out-of-band; garmr never manages it.
2. **systemd credential** — if the unit declares `LoadCredential=<NAME>:…`, systemd
   places it in `$CREDENTIALS_DIRECTORY/<NAME>` and garmr reads it. Opt-in; nothing
   in garmr needs changing to enable it.
3. **Sealed store** — the console-managed encrypted store (below).

A secret set by a higher tier is used; garmr **hydrates** the lower tiers into the
process environment at startup (single-threaded, before any task spawns) so the
existing env-reading consumers pick them up.

## The sealed store

The writable secret store (`<state-dir>/secrets.sealed`) is:

- **ChaCha20-Poly1305 AEAD**, one random nonce per entry, the secret **name bound
  as AAD**, versioned, written atomically at `0600`.
- unlocked by a **master key** held **separately** — `GARMR_SECRET_KEY` (base64 32
  bytes) or `GARMR_SECRET_KEY_FILE` (default `/etc/garmr/secret.key`, `0400`). The
  master key must be **backed up separately** from the data backup, or sealed
  secrets become unrecoverable.

### Write-only from the console

System → Access → Secrets lets you **set/replace** a secret. It is strictly
write-only:

- the store never returns a stored value — the console shows only
  configured/source/**keyed fingerprint**/last-updated;
- the fingerprint is a **keyed** BLAKE3 (a master-derived key), so it is not an
  offline-guessable hash of a low-entropy secret;
- setting a secret requires **Admin + a recent user-verified passkey (step-up) +
  audit**;
- a secret already set in the environment is shown as env-managed and **cannot** be
  replaced from the console (the env wins anyway);
- a sealed secret takes effect **after a restart** (hydration runs at startup); the
  connection test reads the store live, so it works pre-restart.

Secrets are **never** part of the config override / revision history, and the
`mcp_servers` env map is never serialized out of the running config.

## Airgap

The connection test is airgap-aware: under `GARMR_AIRGAP` it refuses to test an
external backend (and the LLM test's real call is blocked by the egress chokepoint),
while a local backend still works.

## Related

- [Configuration](../operations/configuration.md)
- [Break-glass recovery](recovery.md)
