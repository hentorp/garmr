<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Guide: access policies

garmr's **access-policy engine** answers a different question from its anomaly
detectors. Anomaly detection asks *"is this unusual?"*; the policy engine asks *"is
this allowed?"* — and the second answer does not depend on the first.

> **Explicit deny overrides learned-normal.** A forbidden action is a violation no
> matter how frequent or baseline-normal it has become. The policy engine is
> evaluated deterministically per audit record, sits **beside** (not downstream of)
> the anomaly plane, and its deny is authoritative — no baseline, risk sum, or
> criticality weight can soften it. This also gives coverage anomaly detection
> structurally cannot: a **first-ever** violation is caught on sighting one, where a
> behavioral detector must abstain until it has a baseline.

Policies are part of the config-gated application-audit detection plane. See
[../architecture/application-audit.md](../architecture/application-audit.md) for how
it fits the pipeline.

## Enable it

Policies are loaded when the application-audit plane is on, in `[detect]`:

```toml
[detect]
app_audit_enabled = true
policies_dir    = "./policies"          # one policy TOML per file
catalog_file    = "./catalog.toml"      # resource classification (below)
```

garmr deployments without an audit feed are unaffected: with the flag off (or no
`log_type = audit` events), nothing here runs.

## Write a policy

One `Policy` per file. A policy is deterministic, declarative, and explainable — it
matches on **subjects**, **resources**, and **conditions**, and produces an
**effect**:

```toml
# policies/deny-raw-person-data.toml
id = "deny-raw-person-data"
title = "No direct access to raw person tables"
description = "Raw person data is reached only via curated.* views."
effect = "deny"            # allow | deny | require_justification | require_approval
                           #   | alert | increase_risk | step_up_review
enabled = true
version = 1
priority = 100

[resource]
objects = ["raw.*"]        # a schema.* wildcard, or a qualified/unqualified name

# [subject]   users / roles / groups / applications / service_account
# [condition] environments / weekdays / hours / operations / client_ip_prefixes /
#             export / self_access / watched_subject / privileged / bulk_operation /
#             min_rows_read / ...
```

A require-justification policy flags access that lacks a ticket/case/approval
reference instead of forbidding it outright:

```toml
# policies/require-ticket-for-sensitive.toml
id = "require-ticket-for-sensitive-persons"
title = "Sensitive person access needs a ticket"
effect = "require_justification"
enabled = true
version = 1
priority = 50

[resource]
objects = ["curated.persons", "curated.persons_view"]
```

Every matcher and condition reads canonical audit-record fields, so a policy is
domain-neutral and portable across a register, PostgreSQL, and business-app feeds.

## Precedence

Evaluation is deterministic and order-independent by construction:

1. **Explicit `deny`** — wins over everything, including any learned-normal or a
   matching allow.
2. **`require_justification`** — a violation only when justification is absent.
3. **Explicit `allow`** — suppresses anomaly *escalation* for that exact action, but
   never suppresses audit recording and never overrides a deny.
4. **No matching policy** — fall through to the anomaly plane. The absence of a
   policy is not permission.

An allow narrows false positives without blinding the audit: the action is still
recorded and still counts toward per-actor risk; only the escalation is suppressed.

## Explainable decisions

A policy evaluation yields an explanation, not a bare boolean: the matched policy id
and version, the matched subject/resource/conditions, the record fields consulted
(with values), and a human-readable rationale. A violation lowers to a finding that
carries the matched policy id, so a case shows exactly which clause fired.

## Classify resources (the catalog)

The catalog stamps `data_classification` / `sensitive` on resources from **Trusted**
entries, so a policy and the detectors know which objects are sensitive.
File-imported entries are promoted to Trusted at load:

```toml
# catalog.toml
[[table]]
name = "raw.raw_persons"
application = "registry"
classification = "restricted"
sensitive = true
expected_users = ["anna", "bruno"]

[[sensitive_resource]]
object = "curated.persons"
application = "registry"
classification = "confidential"
expected_users = ["anna"]
```

## Backtest before you enforce (`simulate`)

Before a policy goes live, replay it over stored history with no side effects:
`POST /api/policies/simulate` reports how many past actions it would have denied /
flagged / required justification for, which actors and resources are most affected,
the false-positive surface (allowed-in-practice actions it would newly deny), and a
diff against the active version. Simulation reuses the read-only, bounded query path,
so it is safe and reproducible.

## Govern the lifecycle

A policy is a protected change. It travels the uniform change pipeline — propose →
validate → backtest → human approval → apply → audit → rollback — and can be
managed as a **versioned registry record** so it has an immutable id + version, an
approval record, and a rollback target. Registry-backed enforcement is config-gated
(`GARMR_REGISTRY_POLICIES=1`); unset, the file loader is used unchanged, and a plain
policy-file edit can be hot-reloaded via `POST /admin/appaudit/reload` without
restarting `serve`. See
[../architecture/storage.md](../architecture/storage.md#governed-persistence-versioned-registry).

## What the policy engine does not do

- It does not learn its rules from behavior — policies are authored and approved,
  not inferred (that is the anomaly plane's job, kept separate).
- It does not let an allow suppress audit recording (only escalation).
- It is not bypassable by the model — the LLM may only *propose* a policy; a human
  approves it through the audited channel.
