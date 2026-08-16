<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: AGPL-3.0-only
-->

# LLM data governance

"You send our security logs to a model?" is the first question the AI layer
gets in any review. This page answers it precisely: what leaves the box, to
which endpoint, under whose control — and how to run garmr with nothing leaving
at all.

## The three postures

**LLM-off** (`daily_budget_usd = 0`). The triage plane is disabled: no provider
is contacted, no credential is required, and every case queues as `NeedsHuman`
for an analyst. Ingest, detection, correlation, search and the console are
unaffected — they never involve a model. This is not a degraded fallback; it is
a **first-class operating mode**, and it is the configuration garmr's own
longest-running production deployment used while its operator paused spending.
A budget of zero blocks the very first call, so the guarantee is structural
rather than statistical.

**Local models** (`backend = "open_ai_compat"` with a loopback/LAN endpoint).
garmr speaks to any OpenAI-compatible server — Ollama, llama.cpp, vLLM — so the
triage loop can run entirely on hardware you control. Under the airgap profile,
loopback endpoints are the *only* ones the egress policy permits: the answer to
"does log data leave the box" is enforced by the egress chokepoint, not by
configuration discipline. Local endpoints are exempt from the pricing gate
because no per-token invoice exists.

**External models** (Anthropic, or any hosted OpenAI-compatible endpoint). The
strongest models, with three controls always in force:

- the **model router** classifies each case's data sensitivity and keeps
  confidential data on a local model — an external ceiling that configuration
  can narrow but never remove;
- the **daily budget** is a hard gate checked before every call, and the
  pricing gate refuses to start if any configured model — including the
  prefilter — has no known price on a paid endpoint, so the budget can never
  be silently unbound;
- every prediction is an **immutable record** naming the exact model, prompt
  digest and toolset that produced it.

## What is sent, exactly

When triage runs, the model receives: the triggering event (labels, message,
extracted fields), compact results of the read-only tools the agent chooses to
call (log queries, baseline lookups, entity summaries), and garmr's system
prompt. Nothing else. The model never receives credentials, the audit ledger,
or bulk exports; tool responses are the same content an analyst would read in
the console.

Prompt-injection markers found in log data are flagged and recorded *before*
any model sees the event, and the tool surface is read-only by construction —
a model cannot execute an action, only propose one for human approval.

## The prefilter tier

`prefilter_model` inserts a cheap gate before the full tool-use loop: one
no-tools call that may close a low-severity case as routine noise, or hand it
to the full loop. Its boundaries are deliberate:

- it can say **Benign** or nothing — it can never escalate, never propose an
  action, never mark anything malicious;
- high/critical detections and anything carrying injection signals go straight
  to the full loop;
- every failure direction (error, refusal, unparseable answer, low confidence)
  falls through to the full loop — the prefilter can save money, never
  scrutiny;
- its verdicts are recorded under the **prefilter model's own identity**, so
  the analyst feedback plane measures the cheap model's error rate separately.

## Choosing

| Requirement | Posture |
|---|---|
| Nothing may leave the box, ever | LLM-off, or local models under airgap |
| Sensitive estate, capable hardware | Local models; router ceiling is then a no-op |
| Best triage quality, bounded spend | External + prefilter + daily budget |
| Regulatory review pending | Start LLM-off — enable a model tier later without re-deploying |

The postures are runtime configuration, not builds: moving between them is a
config change and a restart, in either direction.
