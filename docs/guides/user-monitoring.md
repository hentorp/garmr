<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Guide: user monitoring and behavioral analytics

garmr can watch specific actors more closely and can compare an actor's behavior
against a learned baseline. Both are built on one principle that this guide keeps
front and center:

> **Monitoring raises attention, not guilt.** A monitoring profile can only
> *increase* how soon and how prominently an actor's events are reviewed — its
> attention multiplier is always `>= 1.0`. It never declares wrongdoing, never
> auto-closes anything as malicious, and never changes what actually happened. A
> notification is an attention signal, not a determination of incident truth.

These are part of the config-gated application-audit plane (see
[../architecture/application-audit.md](../architecture/application-audit.md)) and
apply to `log_type = audit` events.

## User-monitoring profiles

A monitoring profile marks a target for heightened attention for a bounded time.
It is loaded from `monitoring_file` when the app-audit plane is enabled:

```toml
[detect]
app_audit_enabled = true
monitoring_file = "./monitoring.json"   # a JSON array of profiles
```

Each profile watches a **target** (a single user, or everyone in a role / group /
application / matching a resource pattern) in a **state**, over a validity window:

```json
[
  {
    "user_id": "anna",
    "target": { "User": "anna" },
    "state": "ElevatedMonitoring",
    "reason": "Access review follow-up",
    "risk_level": "medium",
    "valid_from": "2026-07-01T00:00:00Z",
    "valid_until": "2026-09-01T00:00:00Z",
    "application_scope": ["registry"],
    "created_by": "analyst-1"
  }
]
```

- **States** (increasing attention): `Normal` → `Watched` → `ElevatedMonitoring` →
  `Investigation` → `Restricted`, plus `Retired` (ended, kept for history). Each
  active state contributes an attention multiplier `>= 1.0`; an expired or `Normal`
  profile contributes a neutral `1.0`.
- **Scope** it with `application_scope` / `resource_scope` (empty = everything).
- **Attribution is mandatory** — `created_by` is required (no anonymous change), and
  every mutation bumps `version` and records audit references.

While a profile is active, it raises the score of an actor's findings; it never
manufactures one. If nothing about the access is otherwise suspicious, monitoring
alone does not open a case.

## Govern monitoring changes

Start / modify / end monitoring can be managed as a **governed registry kind**
(config-gated with `GARMR_REGISTRY_MONITORING=1`): each profile becomes a versioned,
content-addressed record, so a change is a register + an audited promotion / rollback
with full history, instead of an unversioned file edit — and it hot-reloads without
restarting `serve`. Unset, the JSON file loader is used unchanged. Being the *live*
record is what makes a profile take effect (there is no "Trusted" marking here); the
profile's own expiry still governs.

## Per-actor risk (RBA)

With `[detect] risk_enabled = true`, the risk loop scores **each actor** (by
`db_user`) as well as each host. An actor who spreads low-and-slow misuse across
several rules — none individually paging — accumulates a decayed risk sum and, over
`risk_threshold`, opens a `garmr-risk-user-<actor>` case. This is the answer to the
hardest insider: the one who keeps every individual action below every threshold.

Two properties keep this honest:

- RBA needs the per-access rules to yield **Suspicious/untriaged** — a Benign verdict
  zeroes a case and risk never accrues. Individual accesses are not auto-closed
  Benign.
- The score consumes **trusted outcome first, discounted prediction otherwise, and
  never gives positive weight to an unresolved self-prediction** — so accumulation
  cannot be gamed by the agent's own guesses.

## Behavioral baselines (UEBA)

Behavioral analytics asks *"is this normal for this actor / role / peer group?"*
against a **learned, trusted** baseline. In garmr today:

- A newly observed behavior is a **Candidate**, not something a detector may treat
  as normal. It becomes trusted only through the anti-poisoning gate (quarantine
  age, minimum observations, minimum *distinct authenticated* sources, per-source
  influence cap). Detectors read only the trusted view.
- **Abstain-until-baseline** — a first sighting is *novelty*, not an anomaly; a
  detector abstains rather than flag every new actor, so an empty model does not
  produce a flood.
- A baseline touched by an open/malicious case is a **hard block** on promotion that
  no one — not even an analyst — can clear, so misuse under investigation can never
  teach the baseline.
- Inspect and manage profiles with `garmr app-baseline` (list, promote to Trusted,
  mark/clear Suspicious). A profile's behavioral detectors fire **only after** it is
  promoted to Trusted; promote/suspect/clear are admin-gated.

> **Status.** The candidate/trusted machinery, per-actor RBA, and the promotion
> workflow are wired. The **fuller multidimensional UEBA** — per-dimension baselines
> (query fingerprint, volume, distinct records, time-of-day, client), peer-group
> comparison, and service-account profiling — is described as target design in
> [../architecture/user-behavior-analytics.md](../architecture/user-behavior-analytics.md)
> and is partly implemented / in progress. Don't rely on the deeper behavioral
> coverage yet.

## What behavioral analytics never does

- Never treats a Candidate or Suspicious baseline as normal.
- Never learns from behavior under an open/malicious case.
- Never lowers a **policy violation** to "normal" because it is frequent — the policy
  engine is separate and authoritative (see [policies.md](policies.md)).
- Never emits a deviation without an established baseline — it abstains.
