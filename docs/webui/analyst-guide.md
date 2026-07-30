# garmr WebUI — analyst guide

## Start at the Command Center

The landing screen answers one question: *what needs attention now?* A prioritised
feed ranks needs-human/escalated cases, subjects over their risk budget, silent
sources, and audit-integrity failures — each row links straight to where you act.
The health strip (open cases, needs-human, risk over budget, stale sources, audit
integrity) is click-through.

## Investigate a case

Open a case from the queue (**Investigations**) or any link. The detail page is
evidence-first:

1. **Evidence timeline** — the trigger event and the full triage transcript.
2. **Agent analysis** (violet, tagged **AI**) — the model's predicted disposition,
   confidence and reasoning, *or* a plain explanation of why there is no
   prediction (e.g. the model router fenced confidential data from an external
   model, so the case is held for a human). Always verify it against the evidence.
3. **Analyst decision** (tagged **human**) — record your disposition, severity and
   narrative. This is audited; the resulting `audit …` reference appears inline and
   in the activity toast. Agent output and your judgement are never merged.
4. **Related entities** — one-click *peek* (drawer) or *open* for the host/user/ip.
5. **Reproduce evidence query** / **Pivot to Audit Explorer** — jump to the raw
   events behind the case.

## Search the audit log

**Audit Explorer** has three modes over one result table:

- **Simple** — full-text; empty box = the time-range feed (use the header picker).
- **Advanced** — hybrid Query-IR: structured filters (host/service/severity) fused
  with full-text + meaning; each result shows which signals matched (`S`/`F`/`V`).
- **Natural language** — ask a question; the model plans a read-only query and
  answers grounded in cited rows. (Shows a labelled disabled state where no model
  is reachable.)

Click any row to expand a **structured event detail** (normalized fields + a
collapsed raw payload); pivot to the host or open it.

## Users & applications

**Users** lists the people/accounts garmr profiles (from behavioral baselines +
risk). A user page shows behaviour, risk, cases, and baseline maturity. **Applications**
lists the assets/hosts with event volume, open cases, and collector coverage.

## Command palette

Ctrl/Cmd-K from anywhere: jump to a page, open a case/user/host by name, or launch
a search — over real backend entities.

## Reading system state

Anything not *healthy* is labelled — **degraded**, **disabled**, **not configured**,
**learning**, **waiting**, **failed**, **stale** — never a bare colour and never a
generic error. A disabled feature tells you exactly what to configure.
