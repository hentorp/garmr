# First-run setup

garmr's setup state is **explicit** — computed live from the running system, never
inferred from an empty event store — so a fresh airgapped install with no data yet
is not mislabelled "misconfigured". System → Setup shows the checklist.

## The Setup checklist

Each of 11 steps reports `complete` / `incomplete` / `failed` / `info` / `optional`.
Only required steps that aren't complete hold back overall readiness.

| Step | What it checks |
|------|----------------|
| Deployment mode | Derived from airgap × LLM backend (airgapped / local / hybrid), with the security impact. |
| Storage | Warehouse / state DB / search dir exist and the state dir is writable. |
| Admin bootstrap | An Admin principal exists (env token or an Admin passkey). |
| Passkey registration | At least one — **ideally two** — admin passkeys (so a lost key isn't a lockout). |
| Recovery | Local break-glass is available (`garmr recover issue-admin`) — verify it once. |
| LLM configuration | Backend selected + its key present (local backends need none). |
| LLM reachability | Airgap-aware: an external backend under airgap is flagged. |
| Data sources | At least one source active in the last 24h (empty is informational, never a failure). |
| Detection & audit | Audit ledger on + at least one rule/correlation; app-audit state. |
| Notifications | Matrix / webhook / SMTP configured (optional; airgap-aware). |
| End-to-end self-test | Run `garmr selftest` on the host (offline). |

The Setup view is admin-gated (it reports secret presence + posture). On first run
you hold the bootstrap admin token (`GARMR_ADMIN_TOKEN`) or an admin passkey.

## Recommended first-run order

1. **Provision the master secret key** (`/etc/garmr/secret.key`, `0400`) so the
   sealed store works — see [secret storage](../security/secret-storage.md).
2. **Set an admin bootstrap token** (`GARMR_ADMIN_TOKEN`) out of band, or use the
   admin token you configured at install.
3. **Register ≥2 admin passkeys** on the login page (System → Access).
4. **Verify recovery** once — [break-glass recovery](../security/recovery.md).
5. **Configure the LLM** (System → Access → set the key; System → LLM & AI → Test
   model) — the Test runs a real round-trip.
6. **Point data sources** at the native `/ingest/v1/events` receiver (or import
   offline), and confirm ingest health.
7. **Review detection & audit**, then the [Configuration Center](../operations/configuration.md)
   for anything else.

Once passkeys + recovery are verified, you can retire the bootstrap admin token.

## Related

- [Configuration](../operations/configuration.md)
- [Break-glass recovery](../security/recovery.md)
- [Secret storage](../security/secret-storage.md)
