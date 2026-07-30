<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Secure deployment

garmr is **alpha** and hardened for a **trusted, isolated** single-operator
setting. This page is the checklist for tightening a deployment as far as the
current code allows. It must be read with
[../security/known-limitations.md](../security/known-limitations.md), which lists
the surfaces that are **not** yet hardened — some hardening has to happen at a
reverse proxy / firewall, not inside garmr.

> **Do not** expose garmr's ingest, Loki, or Flight endpoints, or its API, to an
> untrusted network. Do not rely on garmr as the sole security control for a
> production estate without your own security review.

## Network posture (do this first)

- **Ingest is the weak surface.** The native endpoint binds `0.0.0.0:3100` and
  accepts unauthenticated POSTs by default, with no request-body / event-count /
  field-size limits, and it does **not** fail closed on a non-loopback bind. The
  Loki endpoint has no collector auth at all; Arrow Flight is experimental.
  - Bind ingest to loopback or a trusted management interface only.
  - Put a reverse proxy / firewall / mTLS in front that enforces authentication,
    size limits, and rate limits.
  - Configure `GARMR_COLLECTORS` (below) so accepted events are source-bound.
- **The API/console fails closed off-loopback.** Binding `api_bind` to a
  non-loopback address requires `GARMR_API_TOKEN`, or `serve` refuses to start.
  Prefer keeping it on loopback and reaching it over an SSH tunnel or a
  hostname-fronted TLS proxy (needed for passkeys anyway).
- **Rate-limit two DoS-prone paths** at the proxy: `/api/audit/status`,
  `/api/audit/verify` (full ledger re-verification per request, reachable by any
  read principal), and `/auth/passkey/login/finish` (a public path that writes an
  fsync'd audit record per request). See
  [../security/known-limitations.md](../security/known-limitations.md).

## Authentication and RBAC

garmr's HTTP surface is gated by bearer tokens resolved to **named principals** with
**ordered roles** (`viewer < analyst < admin`); a capability check is `role >=
required`. Secrets come from the **environment**, never `garmr.toml`.

- `GARMR_API_TOKEN` — the primary operator token (principal `api` / analyst).
  **Required for any non-loopback API bind** (fail-closed).
- `GARMR_ADMIN_TOKEN` — principal `admin` / admin; enables the `/admin/*` surface.
  Keep it **distinct** from `GARMR_API_TOKEN` (sharing the value collapses the two
  tiers; garmr warns). Note that if an API token is set without a distinct admin
  token, the LLM-spend endpoints are reachable by any API-token holder.
- `GARMR_USERS` — named per-user tokens as a JSON array of `{token, user, role}`.
  Prefer a file: `GARMR_USERS="$(cat /etc/garmr/users.json)"` at `0600`, so tokens
  don't linger in `ps` / `/proc/<pid>/environ`.

Tokens are resolved in constant time (BLAKE3 digests). `/health` is the only
unauthenticated endpoint (liveness only).

### Passkey / WebAuthn login (recommended for humans)

Tokens are fine for machines but weak for humans. Passkey login lets an operator
sign in with a hardware authenticator; it mints a signed, HttpOnly session cookie.
It is additive — bearer tokens keep working for API/MCP.

WebAuthn **requires HTTPS + a real hostname** (browsers refuse it over
`http://<ip>`). Front garmr with TLS at a hostname, then set:

```sh
GARMR_WEBAUTHN_RP_ID=garmr-node.example.internal            # hostname, no scheme/port
GARMR_WEBAUTHN_ORIGIN=https://garmr-node.example.internal   # defaults to https://<rp_id>
# GARMR_WEBAUTHN_RP_NAME=garmr                               # optional display name
```

Bootstrap once: browse to `/login`, "Register a new passkey", paste
`GARMR_ADMIN_TOKEN`, touch your key. **Register at least two** admin passkeys so a
lost key is not a lockout. Unset `GARMR_WEBAUTHN_RP_ID` to keep passkeys off
(token-only).

## Secrets

Secrets resolve at startup in this precedence:

1. **Environment variable** (`GARMR_*` / `ANTHROPIC_API_KEY`) — always wins;
   out-of-band; garmr never manages it.
2. **systemd credential** — if the unit declares `LoadCredential=<NAME>:…`.
3. **Sealed store** — the console-managed encrypted store
   (`<state-dir>/secrets.sealed`, ChaCha20-Poly1305 AEAD, per-entry nonce, name
   bound as AAD, written `0600`).

The sealed store is unlocked by a **master key held separately**:
`GARMR_SECRET_KEY` (base64 32 bytes) or `GARMR_SECRET_KEY_FILE` (default
`/etc/garmr/secret.key`, `0400`). **Back the master key up separately from the data
backup**, or sealed secrets become unrecoverable. The console's secret UI is
strictly write-only: it never returns a stored value, only a keyed fingerprint;
setting a secret requires admin + a recent user-verified passkey (step-up) + audit.

> Note: `GARMR_SIGN_KEY` is **not** a daemon setting — it is the minisign key path
> used by the release script (see [../development/release-process.md](../development/release-process.md)).
> The in-binary signing key is the audit ledger's ed25519 key (`[audit] key_path`),
> which also signs backups and bundles.

## Collector authentication (source binding)

Set `GARMR_COLLECTORS` (a JSON array in the daemon environment, never in config or
logs) to require a per-collector bearer token on the native endpoint:

```jsonc
// GARMR_COLLECTORS
[{ "id": "pg-collector", "token": "…", "sources": ["postgres-audit"] }]
```

Each accepted event is stamped with the trusted collector `id` (a collector may
only assert its bound `sources`), and the environment learner keys anti-poisoning on
that id — so one compromised collector can forge only its own single source.
**Configure collectors before enabling `environment.learn`** (binding governs future
learning only). Collectors can also add `X-Garmr-Seq` / `X-Garmr-Epoch` headers so
garmr flags delivery gaps (`garmr ingest-health`).

## Keeping sensitive data local

- For a PII / register deployment, set the model-routing floor
  `default_classification = "confidential"` under `[route.router]`. Free-text PII in
  a message body is **not** auto-classified; the floor fail-closes the ask / hunt /
  rule surfaces off external models.
- Or run fully offline: `GARMR_AIRGAP=1` denies every external egress class and
  **overrides** any `[route.egress]` allowlist. See [airgap.md](airgap.md).
- Restrict who may query the audit stream (RBAC), and set a retention window on it —
  the audit is itself sensitive (it reveals who was investigated).

## Break-glass recovery

If you lose your admin passkey and hold no admin bearer token, regain admin from the
**host** (the ultimate root of trust) — there is deliberately **no
network-reachable recovery**:

```sh
systemctl stop garmr                                   # state DB is single-writer
garmr recover issue-admin --label emergency --hours 12
systemctl start garmr
```

It mints a short-lived (default 12h) admin credential, printed once, and records a
`recovery.admin_issued` entry to the audit ledger **before** the credential is
saved (fail-closed). Use it to log in, register a fresh passkey, and revoke the
recovery credential. See [../security/recovery.md](../security/recovery.md).

## Hardening checklist

1. Ingest / Loki / Flight off untrusted networks; proxy enforces auth + size +
   rate limits.
2. `GARMR_API_TOKEN` set (and a distinct `GARMR_ADMIN_TOKEN`); named `GARMR_USERS`.
3. Passkeys registered (≥ 2 admin keys); recovery verified once.
4. `GARMR_COLLECTORS` configured **before** `environment.learn`.
5. Master secret key provisioned (`/etc/garmr/secret.key`, `0400`) and backed up
   separately.
6. Classification floor set for PII, or `GARMR_AIRGAP=1`.
7. Rate-limit audit-status/verify and passkey-login at the proxy.
8. Backups treated as confidential; verified with an out-of-band key.
9. Your own security review — this list is not exhaustive.
