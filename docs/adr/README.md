# Architecture Decision Records

This directory records the significant, hard-to-reverse decisions taken while
evolving garmr from a one-person agentic-SOC prototype into an audit-first,
adaptive security-analytics platform for disconnected and air-gapped
environments (branch `feature/adaptive-audit-soc`).

Each ADR is immutable once `Accepted`. A decision that is later changed gets a
new ADR that `Supersedes` the old one; the old ADR is marked `Superseded by`
rather than edited away. This mirrors the platform's own principle that
decisions are appended, never overwritten.

## Status vocabulary

- `Proposed` — drafted, not yet in force.
- `Accepted` — in force; code and docs must comply.
- `Superseded by ADR-NNNN` — replaced; kept for history.
- `Deprecated` — no longer recommended, not yet replaced.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-adaptive-audit-soc-initiative.md) | Adaptive-audit SOC initiative and non-negotiable invariants | Accepted |
| [0002](0002-webui-only-console.md) | Leptos WebUI is the single console; remove the native egui client | Accepted (removed Cycle 5) |

## Template

```markdown
# ADR-NNNN: <title>

- Status: Proposed | Accepted | Superseded by ADR-XXXX | Deprecated
- Date: YYYY-MM-DD
- Deciders: <roles>
- Supersedes / Superseded by: <links>

## Context
<forces at play, constraints, the problem>

## Decision
<what we will do, stated plainly>

## Consequences
<positive, negative, and neutral outcomes; follow-up work>

## Alternatives considered
<what else, and why not>
```
