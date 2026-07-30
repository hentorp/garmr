# Authentication & RBAC

garmr's HTTP surface (query API, web console, admin actions) is gated by bearer
tokens resolved to **named principals** with **ordered roles**. This is the
multi-operator access model — the read/act split an enterprise SOC needs.

## Roles

Roles are a total order; a capability check is simply `role >= required`.

| Role | Grants |
|---|---|
| `viewer` | Read-only: query, search, cases/entities/graph, ATT&CK coverage, the UI. |
| `analyst` | Viewer **+** operator actions (acknowledge, silence a noisy rule, notes). |
| `admin` | Analyst **+** governance: approve rules/actions, prune cases, the `/admin` surface. |

## Configuring principals

Secrets come from the **environment**, never `garmr.toml`.

- `GARMR_API_TOKEN` — the primary operator token. Maps to principal `api` /
  **analyst**. Required for any non-loopback bind (fail-closed); a loopback bind
  may run unauthenticated for local `curl`.
- `GARMR_ADMIN_TOKEN` — maps to principal `admin` / **admin**. Enables the
  `/admin/*` surface. Keep it distinct from `GARMR_API_TOKEN` (sharing the value
  collapses the two tiers — garmr warns at startup).
- `GARMR_USERS` — named per-user tokens, a JSON array:

  ```json
  [
    {"token": "…64+ random bytes…", "user": "alice", "role": "analyst"},
    {"token": "…", "user": "bob",   "role": "viewer"}
  ]
  ```

  Prefer a file: `GARMR_USERS="$(cat /etc/garmr/users.json)"` (0600), so tokens
  don't linger in `ps`/`/proc/<pid>/environ` dumps.

At startup garmr logs `API authentication enabled (RBAC) principals=N`.

## How a request is authenticated

1. The presented secret is read from `Authorization: Bearer <token>` (API
   clients) or `Basic <base64(user:pass)>` (a browser's native login — the
   password half is the token; the username is ignored).
2. It is resolved against the registry in **constant time** (BLAKE3 digests, no
   byte- or length-timing leak). A miss is `401` with a `Basic` challenge.
3. On a hit the resolved `Principal {user, role}` is attached to the request.
   `/health` is exempt (unauthenticated liveness, exposes only `ok`).

Every admin action logs **who** authorized it:

```
INFO garmr::api: admin action authorized user=alice role=Admin
```

Pair that with the handler's own action log for a full audit-by-identity trail.

## Passkey / WebAuthn login (browser)

Tokens are fine for machines but weak for humans. Enable **passkey login** and
the operator signs in with a hardware authenticator (YubiKey, platform passkey)
instead of pasting a shared token. It is additive: bearer tokens keep working
for API/MCP/Alloy; the passkey mints a signed, HttpOnly session cookie for the
console. ES256 (P-256) authenticators, pure-Rust crypto (no openssl).

**WebAuthn requires HTTPS + a real hostname** (browsers refuse it over
`http://<ip>`). Put garmr behind TLS at a hostname — e.g. Tailscale:

```sh
tailscale serve --bg http://127.0.0.1:3110      # → https://<host>.ts.net
```

Then set the environment (in `/etc/garmr/garmr.env`) to that exact origin:

```sh
GARMR_WEBAUTHN_RP_ID=pve.example.ts.net          # the hostname (no scheme/port)
GARMR_WEBAUTHN_ORIGIN=https://pve.example.ts.net # defaults to https://<rp_id>
# GARMR_WEBAUTHN_RP_NAME=garmr                       # optional display name
```

Unset `GARMR_WEBAUTHN_RP_ID` → passkey stays off, surface is token-only as
before. Restart garmr; it logs `passkey (WebAuthn) login enabled`.

**Bootstrap (register your key once):** browse to `https://<host>/login`, open
*"Register a new passkey"*, paste `GARMR_ADMIN_TOKEN`, touch your key. From
then on the *"Log in with passkey"* button is all you need; the session key is
generated once and persisted in the state store (survives restarts). Register a
backup key the same way. The session grants the console (incl. the admin surface
— a hardware-verified operator is as strong a human-approval signal as the admin
token). "Log out" clears the session.

Flow when passkey is on: an unauthenticated browser hitting the console is
redirected to `/login`; the SPA also bounces to `/login` on a `401` (expired
session). The signature counter is checked to detect a cloned authenticator;
attestation (the key's *model*) is intentionally not verified — you register
your own key over an admin-authenticated channel, so possession is what matters.

## Backward compatibility

A pre-RBAC deployment that set only `GARMR_API_TOKEN` (+ optionally
`GARMR_ADMIN_TOKEN`) keeps working unchanged — those two tokens map to the
synthetic `api`/analyst and `admin`/admin principals. Add `GARMR_USERS` to
introduce named operators without touching the existing tokens.

## Related: case retention

Cases accrete in the state store. Prune them (admin-gated) online:

```sh
# dry-run preview (matched count only)
curl -s -X POST http://127.0.0.1:3110/admin/cases/prune \
  -H "Authorization: Bearer $GARMR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"source":"anomaly","apply":false}'

# apply
… -d '{"older_than_days":30,"state":["closed"],"apply":true}'
```

Filters: `older_than_days`, `opened_after`/`opened_before` (RFC3339),
`state` (repeatable), `rule`, `source`. At least one filter is required (it
never wipes the whole store). Offline (daemon stopped): `garmr cases prune …`.
