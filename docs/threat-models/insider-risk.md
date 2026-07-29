# Threat model — insider risk

Scope: the **authorized** user who abuses (or negligently misuses) access they
legitimately hold. Integrity and poisoning controls do not help here — the events
are real and the actor is who they say they are. The defense is UEBA + weak-signal
RBA + explicit policy + monitoring.

Companion: [sensitive-search-and-export](sensitive-search-and-export.md) (the
insider who is an *auditor*). Design:
[../architecture/user-behavior-analytics.md](../architecture/user-behavior-analytics.md),
[../architecture/access-policy-engine.md](../architecture/access-policy-engine.md);
shipped register rules: [../access-audit.md](../access-audit.md).

## Assets

- Sensitive records (persons, cases, documents, customer data).
- The **least-privilege boundary**: that an actor touches only what their role and
  justification warrant.

## Adversary

A person with valid credentials and a valid role. Sub-types: the **malicious
insider** (deliberate exfiltration / snooping / sabotage), the **negligent
insider** (over-broad access out of convenience), and the **compromised account**
(an outsider wearing an insider's identity — behaviourally identical to a malicious
insider, so the same controls apply).

## Behaviour → signal → defense

Each behaviour projects from canonical `AuditRecord` fields
(`crates/garmr-core/src/app_audit.rs`) and is addressed by an existing or targeted
control.

| Behaviour | Signal (field / detector) | Defense |
|-----------|---------------------------|---------|
| **Self-access** (look up own record) | `classification.self_access` (`is_self`, `app_audit.rs:464`) | `reg-self-lookup` rule ([../access-audit.md](../access-audit.md) §3); app flag, garmr holds no self-map |
| **Watched-subject access** | `classification.watched_subject` (`watched`, `app_audit.rs:462`) | `reg-watchlist` rule (critical); route as escalation so a host silence can't mute it |
| **Peer access** (colleague's record) | `classification.peer_access` (`app_audit.rs:466`) | policy `RequireJustification` / `Deny`; UEBA peer-group deviation |
| **Bulk enumeration** | `action.bulk_operation` / `rows_read` (`app_audit.rs:409,399`) | `reg-bulk-lookups` (≥ N in window, `min_lookups`); UEBA volume/distinct-records baseline |
| **Sequential enumeration** | distinct `subject_id`/`record_id` over time | UEBA distinct-records baseline; RBA accrual |
| **Low-and-slow** (spread thin to stay sub-threshold) | many weak signals, none paging | **RBA accumulation** — see below |
| **Off-hours access** | `event_ts` vs working hours | `reg-off-hours` (`tz_offset`/`day_start`/`day_end`); UEBA time-of-day/weekday baseline |
| **New client / source** | `context.client_host`/`client_ip` (`app_audit.rs:354,356`) | UEBA new-client baseline; `env-new-edge` ([envdetect](../../crates/garmr-analytics/src/envdetect.rs)) |
| **Privilege change** | `action.privilege_operation` (GRANT/REVOKE/SET ROLE, `app_audit.rs:413,638`) | policy: forbid outside a change window; high-impact env facts need analyst approval |
| **Service-account misuse** | `actor.service_account` / `ActorType::ServiceAccount` (`app_audit.rs:317,135`) | tight service-account baseline — deviation is high-signal ([UEBA](../architecture/user-behavior-analytics.md) §2) |
| **Missing justification** | `missing_justification()` (`app_audit.rs:888`) | `reg-lookup-without-ticket`; policy `RequireJustification` effect |
| **Data-scientist raw-data deviation** | large `rows_read`/`bytes_read`, raw `SELECT`/`COPY` off the notebook's fingerprint | UEBA query-fingerprint + volume baseline; export controls ([sensitive-search-and-export](sensitive-search-and-export.md)) |

## Weak-signal accumulation (the low-and-slow answer)

The hardest insider is the one who keeps every individual action below every
threshold. The defense is **per-actor RBA**: `score_staff` groups by `db_user`
(`crates/garmr-analytics/src/risk.rs:351`) and decays a risk sum across *all* the
weak signals an actor triggers; over `risk_threshold` it opens a
`garmr-risk-user-<actor>` case (`risk.rs:372`). An actor who spreads misuse across
several rules — none individually paging — still surfaces as a single risk case.

Two properties keep this honest:

- RBA needs the per-access rules to yield **Suspicious/untriaged** — a Benign
  verdict zeroes the case and risk never accrues; individual accesses are not
  auto-closed Benign ([../access-audit.md](../access-audit.md) §4).
- The score consumes **trusted outcome first, discounted prediction otherwise, and
  never gives positive weight to an unresolved self-prediction**
  (`risk.rs:13-34`) — so the accumulation cannot be gamed by the agent's own
  guesses ([baseline-poisoning](baseline-poisoning.md) §5).

## Policy as the hard boundary

Where an action is simply **not allowed** for a role (regardless of frequency), the
access-policy engine ([../architecture/access-policy-engine.md](../architecture/access-policy-engine.md))
denies it deterministically — the first offense, with no baseline required. This is
what catches the insider whose *first* action is already a violation, which UEBA
(needing a baseline) structurally cannot.

## Monitoring & response

A rule/RBA hit rides the existing Matrix + webhook + SMTP path with per-rule
throttle + silences; the verdict body and webhook JSON name the parties (`Actor X →
Subject Y`, [../access-audit.md](../access-audit.md) §6). Any response action
travels the human-approved executor (invariant #2), never an autonomous action
against a user.

## Residual risks

- An insider acting **entirely within** their role, justification, baseline, and
  policy is invisible to behavioural controls — bounded by least-privilege and
  after-the-fact investigation, not prevented.
- A compromised account that perfectly mimics the real user's baseline evades UEBA;
  new-client / new-source and off-hours signals are the residual tripwires.
- App flags (`watched`/`is_self`/`peer_access`) are set by the application — garmr
  trusts the producer for these, by design (data minimization); a producer that
  lies about them is an [audit-log-poisoning](audit-log-poisoning.md) problem.
