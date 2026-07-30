# garmr WebUI — admin guide

Protected (admin-tier) actions in the console — approve/reject a rule proposal,
approve/deny a response action, promote/suspect/clear a behavioral baseline,
heighten/clear user monitoring, set a silence — are all **server-authorized and
audited**. The console never holds business logic; it calls a real endpoint and
surfaces the outcome + audit reference.

## Authorizing protected actions

Two ways the browser resolves to an **Admin** principal:

1. **Passkey session (production).** When passkey/WebAuthn is enabled
   (`GARMR_WEBAUTHN_RP_ID`), a hardware login resolves to an Admin principal and the
   same-origin session cookie authorizes admin actions automatically. No token
   touches the browser.
2. **Operator token (token-only / lab).** On a deployment without passkey, open
   **System › Access** and hold the admin token for the session. It is sent as a
   bearer, **never placed in a URL and never written to disk** (sessionStorage only,
   cleared when the tab closes). This mirrors how a CLI/machine caller holds the
   token; a passkey session supersedes it.

If neither is present, a protected action returns **401/403** and the console renders
a clear "authorize as an operator" state pointing at System › Access — it never
leaves a dead button.

## What stays authoritative on the server

The console **cannot** weaken any of the invariants — they are enforced by the API,
not the UI:

- **Propose vs approve** — the agent proposes rules/actions; a human approves. The
  approve endpoint is the out-of-band human decision.
- **Read-only agent boundaries** — the agent surface is read-only; writes go through
  the audited admin/analyst endpoints.
- **Policy gates & registry governance** — promotion re-checks the inviolable hard
  blocks (open case, prior violation, suspicious mark; env anti-poisoning) server-side.
- **Audit logging** — every protected change is fail-closed audited; the change is
  not acknowledged without a durable audit record. The console shows that record's id.
- **Air-gap & RBAC** — the egress chokepoint and role checks are server-side; the
  capability manifest only hides controls that can never work, it never grants access.
- **Human promotion of learning** — a challenger goes live only via an audited
  `registry promote`, never from a console toggle.

## Where the admin controls live

| Action | Location | Endpoint |
|--------|----------|----------|
| Approve/reject rule proposal | Detections › Rule proposals | `POST /admin/rules/{approve,reject}` |
| Approve/deny response action | (per case) / activity | `POST /admin/action/{approve,deny}` |
| Promote/suspect/clear baseline | Detections › Baselines | `POST /admin/appaudit/baselines/*` |
| Heighten/clear user monitoring | Users › (user) › Monitoring | `POST /admin/appaudit/baselines/{suspect,clear}` |
| Record analyst decision | Investigations › (case) | `POST /api/cases/:id/decision` |
| Silences | Detections › Silences | `POST /admin/silence` |

## Governance actions still on the CLI

Registry register/promote/rollback, environment promote/approve, audit verify/export,
backup create/verify, and incident sealing remain audited **CLI** operations (some
have read-only console surfaces). This is deliberate: the highest-impact governance
transitions stay explicit, out-of-band actions. Where the console lacks a control it
shows a labelled panel naming the CLI command — never a silently broken button.
