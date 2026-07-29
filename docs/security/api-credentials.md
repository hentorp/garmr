# API credentials (scoped machine tokens)

Scoped machine credentials are the modern bearer for collectors, CLI automation,
and integrations — individually identifiable, revocable, and never a single global
token. Manage them in System → Access → API credentials.

## Properties

- A credential is `garmr_pat_<base64url(32 CSPRNG)>`, **shown once** at issuance and
  never retrievable again.
- Only a **keyed BLAKE3 digest** is stored — the digest cannot authenticate, and a
  stolen store row cannot be used as a bearer. Comparison is constant-time.
- Each credential has a **role**, a **scope set**, an optional **expiry**, and
  status/last-used metadata. Issue / rotate / revoke require **Admin + step-up +
  audit**.
- Legacy env tokens (`GARMR_API_TOKEN` / `GARMR_ADMIN_TOKEN`) still work and are
  labelled read-only ("cannot be viewed or rotated here").

## Scopes

Scopes gate specific privileged **actions** at the handler; reads follow the role.
The vocabulary is the write/admin set: `llm:ask`, `config:write`, `secrets:write`,
`rules:approve`, `actions:approve`, `backup:operate`, `collectors:ingest`,
`system:admin`.

`system:admin` is the **master scope**: a credential holding it is a full admin
(it satisfies `check_admin` / passkey-register / step-up, not merely `require_scope`).
Grant it deliberately — it is how the break-glass recovery credential works.

## Lifecycle

- **Issue** — name, role, scopes, optional expiry → the token is shown once.
- **Rotate** — a fresh token for the same credential, revoking the old one.
- **Revoke** — the digest is marked revoked; the token stops authenticating.
- **Expire** — an expired credential is rejected at auth time.

## Related

- [Authentication & passkeys](authentication.md)
- [Break-glass recovery](recovery.md)
