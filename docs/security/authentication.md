# Authentication & passkeys

garmr's console is **passkey-first** for humans, with bearer tokens for machines.
Authorization is always enforced server-side — the frontend is never the boundary.

## Passkeys (WebAuthn)

- Registration is admin-gated and mints a **named identity + role** (not a single
  hardcoded operator). Register new keys on the login page.
- Login resolves the asserted credential to its stored identity + role and mints a
  session cookie (HttpOnly + Secure + SameSite=Strict, MAC'd, with an Origin
  guard). Normal login is user-presence; **step-up** additionally requires a recent
  **user-verified** (PIN/biometric) assertion.
- **Sensitive operations** (secret writes, credential issue/revoke, config apply/
  rollback) require step-up — a recent user-verified session.
- **Last-admin protection:** the last enabled Admin passkey cannot be revoked.
- **Session revocation:** "log out all sessions" bumps a stored epoch that
  invalidates every existing session immediately.

Register **at least two** admin passkeys so a lost key isn't a lockout; the
[recovery](recovery.md) command is the deeper backstop.

## Bearer tokens (machines)

- The legacy env tokens (`GARMR_API_TOKEN` / `GARMR_ADMIN_TOKEN`) keep working and
  are required to serve on a non-loopback bind.
- Scoped machine credentials are the modern path — see [API credentials](api-credentials.md).
- A credential holding the master `system:admin` scope is a full admin (satisfies
  the admin gates + step-up), which is how a break-glass recovery token can register
  a passkey and self-revoke.

## Airgap

`GARMR_AIRGAP` is a hard, env-only override that blocks all external egress and can
never be turned off from the console.

## Related

- [API credentials](api-credentials.md)
- [Break-glass recovery](recovery.md)
