# Access-policy engine — architecture (Phase 5 target)

Status: target design. The Phase-1 model already exposes the hooks it builds on
(`AuditJustification::is_present`, `app_audit.rs:443`;
`AuditRecord::missing_justification`, `app_audit.rs:888`; the `policy_scope` key,
`app_audit.rs:120`). See [application-audit-analytics.md](application-audit-analytics.md)
for the taxonomy and [user-behavior-analytics.md](user-behavior-analytics.md) for
the anomaly plane this is deliberately separate from.

## 1. Why a policy engine SEPARATE from anomaly detection

The single most important product decision here: **explicit policy is not
statistics.** UEBA answers "is this unusual?"; the policy engine answers "is this
*allowed*?" — and the answer to the second question does not depend on the first.

> **Explicit-deny overrides learned-normal.** A forbidden action is a violation no
> matter how frequent or baseline-normal it has become (the invariant from
> [application-audit-analytics.md](application-audit-analytics.md) §2). The policy
> engine therefore sits **beside** the anomaly plane, evaluated deterministically
> per `AuditRecord`, and its deny is authoritative — no baseline, RBA sum, or
> criticality weight can soften it.

This also gives coverage the anomaly plane structurally cannot: a **first-ever**
policy violation is caught on sighting one (taxonomy row 1), where UEBA must
abstain until it has a baseline (row 3).

## 2. Policy model

A policy is deterministic, declarative, and explainable. The target shape:

```
Policy {
  id, version,
  subjects:    [ actor / role / group / service-account matchers ]
  resources:   [ application / database / schema / object_type / resource_path / classification ]
  conditions:  [ time-of-day, source-zone, justification-required, outcome,
                 bulk/export/privilege flags, peer/self access, MFA/auth-method ]
  effect:      Allow | Deny | RequireJustification | Warn | Monitor
}
```

Every matcher and condition reads canonical `AuditRecord` fields
(`app_audit.rs`), so a policy is domain-neutral and portable across the register,
Postgres, and business-app profiles. Example conditions already backed by the
model:

- **require-justification** — fires when `missing_justification()` is true
  (`app_audit.rs:888`); `is_present()` (`app_audit.rs:443`) covers any of the
  justification references (`ticket_ref`, `case_ref`, `approval_ref`, `change_ref`,
  …).
- **forbid-export / forbid-bulk** — reads `action.export_operation` /
  `action.bulk_operation` (`app_audit.rs:411,409`).
- **forbid-privilege-change outside a change window** — reads
  `action.privilege_operation` (`app_audit.rs:413`, inferred from
  `GRANT`/`REVOKE`/`SET ROLE`) crossed with an environment ChangeRecord
  (`within_change_window`, `environment.rs:907`).
- **restrict-by-classification** — reads `classification.data_classification`
  (`app_audit.rs:457`) and `sensitive_resource` (`app_audit.rs:460`).

## 3. Precedence

Evaluation is deterministic and order-independent by construction:

1. **Explicit `Deny`** — wins over everything, including any learned-normal or a
   matching `Allow`. This is the "explicit-deny-overrides-learned-normal" rule.
2. **`RequireJustification`** — a violation only when justification is absent.
3. **Explicit `Allow`** — suppresses anomaly *escalation* for that exact action,
   but never suppresses audit recording, and never overrides a `Deny`.
4. **No matching policy** — fall through to the anomaly plane (UEBA decides
   whether it is unusual); the absence of a policy is not permission.

An `Allow` narrows false positives without blinding the audit: the action is still
recorded and still counts toward RBA context; only the *escalation* is suppressed.

## 4. Explainable PolicyDecision

A policy evaluation yields an explainable decision, not a bare boolean:

```
PolicyDecision {
  effect, matched_policy_id + version,
  matched_subject, matched_resource, matched_conditions,
  the AuditRecord fields consulted (with values),
  rationale (deterministic, human-readable)
}
```

The coarse allow/deny is already recordable on the audit ledger envelope
(`garmr_audit::PolicyDecision` = `Allowed | Denied | NotApplicable`,
`crates/garmr-audit/src/event.rs:134`; the `AUTHZ_DENIED` action,
`event.rs:176`). The Phase-5 engine's richer `PolicyDecision` is the *explanation*
behind that verdict; a violation lowers to a `SecurityFinding` (`finding.rs:117`)
carrying the matched policy id so the case shows exactly which clause fired.

## 5. Lifecycle: versioned, validated, backtested, approved, audited, reversible

A policy is a protected change, so it travels the **same uniform change pipeline**
as every other protected change (invariant #2, `adaptive-audit-soc.md` §3):

```
propose → validate → evaluate(backtest) → human approval → apply → audit → rollback
```

- **Versioned & content-addressed** via the Phase-4 registry (rule/detector-config
  kind), so a policy has an immutable id+version and a promotion record.
- **Validated** — syntactic + semantic checks (no unresolvable subject, no
  contradictory effects) at propose time and re-validated at apply time (the
  executor never trusts the stored proposal, `executor.rs:185`).
- **Backtested** — see §6.
- **Approved** — RBAC-gated (`check_admin`, `crates/garmr-cli/src/api/auth.rs`),
  producing an `AuditEvent`.
- **Audited** — every propose/decide/apply emits a ledger record
  (`RULE_PROPOSE`/`RULE_DECIDE`, `event.rs:180-181`).
- **Reversible** — rollback repoints to the previous signed policy version.

## 6. Policy simulation over history (Phase 12 target)

Before a policy goes live, `simulate` replays it over a bounded window of stored
`AuditRecord`s and reports, without side effects:

- how many past actions it would have **denied** / flagged / required
  justification for,
- which actors/resources are most affected,
- the **false-positive surface** (allowed-in-practice actions it would newly deny),
- diff vs. the currently-active policy version.

Simulation reuses the read-only lakehouse query path (bounded, timed, read-only,
the same envelope as `ask`/hybrid search — [hybrid-investigation-search.md](hybrid-investigation-search.md)),
so it is safe by construction and reproducible (a simulation pins the policy
version + the event id set it ran over). A policy is not promotable on statistics
alone: the human approves the *intent* with the backtest as evidence, exactly as a
detector challenger is human-promoted (`learning-plane.md`).

## 7. What the policy engine must not do

- It must not learn its rules from behaviour — policies are authored/approved, not
  inferred (that is UEBA's job, kept separate).
- It must not let an `Allow` suppress audit recording (only escalation).
- It must not be bypassable by the model — the LLM may only *propose* a policy; a
  human approves it through the audited channel (invariant #2).
