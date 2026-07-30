# Break-glass recovery

If you lose your admin passkey (and hold no admin bearer token), you can regain
admin access from the **host** — the ultimate root of trust — with a local,
offline, audited command. garmr deliberately has **no network-reachable recovery
surface**: recovery requires shell access to the machine.

## When you need it

- Your admin passkey (YubiKey) is lost or broken, and
- you don't have `GARMR_ADMIN_TOKEN` set out of band.

Prevention first: register **at least two** admin passkeys (the setup wizard nudges
you to). Recovery is the backstop when both are gone.

## How it works

```bash
# On the host, with the daemon stopped (the state DB is single-writer):
systemctl stop garmr
garmr recover issue-admin --label emergency-admin --hours 12
systemctl start garmr
```

`garmr recover issue-admin`:

- refuses to run on a restored-but-unpromoted node (the write fence — run
  `garmr backup promote` first);
- mints a **short-lived** emergency Admin credential (default 12h, clamped 1–168h)
  scoped `system:admin`;
- records a `recovery.admin_issued` entry to the tamper-evident audit ledger
  **before** the credential is saved (fail-closed — if auditing is enabled and the
  record can't be written, no credential is minted). If auditing is disabled it
  prints a loud warning and proceeds;
- prints the `garmr_pat_…` token **once** — it is never retrievable again.

## Using the recovery token

The token is a full admin: `system:admin` satisfies `check_admin` /
passkey-register / step-up, not just scoped endpoints. So you can:

1. Log in to the console with it (send it as a `Bearer` token / paste it into the
   admin-token field in System → Access).
2. **Register a fresh admin passkey** on the login page.
3. **Revoke the recovery credential** in System → Access → API credentials.

It expires on its own even if you forget to revoke it, and every step is audited.

## Security properties

- **Local-only.** No HTTP endpoint mints admin; recovery needs host access +
  (effectively) the ability to stop the service.
- **Audited, not a bypass.** The issuance is on the tamper-evident ledger.
- **Short-lived + revocable + visible.** It expires, you revoke it, and it shows in
  the API-credentials list the whole time.

## Related

- [Passkeys & authentication](authentication.md)
- [API credentials](api-credentials.md)
