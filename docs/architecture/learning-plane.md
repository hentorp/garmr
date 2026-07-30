# Learning plane — architecture

Status: initial (expanded in Phases 3, 8, 9). Covers how garmr improves from
analyst feedback and its own mistakes **without** unrestricted online learning
(invariant #3) and without treating model output as ground truth (invariant #2).

Companion threat model:
[threat-model-learning-and-poisoning](../threat-model-learning-and-poisoning.md).

## Principles

1. **Offline only.** The serving process never fine-tunes a generative model from
   raw production logs. Learning happens as discrete, audited, reversible jobs.
2. **Trusted labels only.** Supervised labels come from `AnalystDecision` /
   `IncidentOutcome`, never from `AgentPrediction`.
3. **Immutable, content-addressed data.** Every dataset and feature snapshot is
   hashed and pinned; runs record exactly which case/event ids were in/out.
4. **Champion/challenger, never in-place.** A new detector/calibration/model is a
   *challenger*: replayed, adversarially evaluated, shadowed, human-approved,
   canaried, monitored, and rollback-able. The champion is untouched until
   promotion. The live shadow-evaluation of a stateful-detector challenger is
   implemented in [shadow-evaluation](shadow-evaluation.md) (DoD 19); the labeled
   precision/recall harness is `garmr synth-eval` (DoD 21).

## Record types (Phase 3)

Immutable and append-only; corrections supersede, never overwrite.

- `AgentPrediction` — model output + full provenance (model/prompt/toolset
  digests, calibrated confidence, evidence refs, cost/latency, stop reason).
- `AnalystDecision` — human ground truth (principal, reason codes, accepted/
  rejected evidence, was-prediction-correct, was-evidence-missed, `supersedes`).
- `IncidentOutcome` — post-incident truth, incl. false negatives with no case.
- `FeedbackRecord`, `FalseNegativeRecord`, `MistakeRecord`.

RBA/scoring consumption order: **trusted outcome → discounted prediction → no
positive weight for unresolved self-predictions.**

## The pipeline (Phase 8, `garmr-learning`) — shipped MLP

Phase 8 ships the smallest safe, end-to-end champion/challenger loop for ONE
deterministic surface — the Phase-7 ensemble score-band / criticality retune —
entirely OFFLINE and LLM-free, in a new pure crate `garmr-learning` (deps:
`garmr-core`/`-store`/`-analytics` only; no `garmr-agent`/`-llm`, so it ships in
the default build and does zero egress). The stages that landed:

```
garmr learn dataset build   → immutable content-addressed DatasetSnapshot
                              (Trusted-only labels, poison-excluded, temporal split)
garmr learn challenger fit   → bounded grid → Draft DetectorConfig record
garmr learn challenger eval  → replay champion vs challenger on the Test holdout
                              → precision/recall, p@budget, dangerous-FN gate
garmr learn shadow           → offline read-only divergence report (writes nothing)
garmr registry promote …     → the EXISTING human-admin-gated, audited channel
```

- **Dataset (`garmr-core::DatasetSnapshot`, `datasets` redb table).** A row is kept
  ONLY when `resolve_trusted` yields `Outcome`/`AnalystDecision` — a prediction is
  never a label (invariant #3). The Phase-5 poison exclusion is applied **only to
  benign rows**: an adverse (Malicious/Suspicious) trusted row is always kept, so
  the exclusion can't strip the positive class the guard needs. Rows carry the real
  per-case criticality from the Trusted env model. The manifest pins
  included/excluded case+event ids, label sources+trust, versions, and a temporal
  split whose newest slice is a never-fit Test holdout; the content digest is framed
  by hand (order-independent). **Never evaluate on training data.**
- **Challenger.** A candidate `DetectorConfigSpec` produced by a bounded grid over
  the *measurable* knobs (ensemble bands + `crit_coef`; `corr_coef`/RBA pinned to
  the champion). The champion is reconstructed EXACTLY as serve builds it
  (`crit_coef`/`corr_coef` from `environment.detect`, default bands).
- **The gate.** `replay` scores each row through the exact serve function
  `ensemble::assess`. A challenger is refused if it raises dangerous false
  negatives, OR if the Test holdout is too small or has too few dangerous positives
  (so a suppression regression can never pass on an all-negative holdout). The
  dataset records each row's PRE-boost base level (`finding_base_level`, injected
  by `into_detection`) rather than the criticality-boosted output level, so the
  replay applies criticality exactly once and reproduces serve's score. A property
  `assess` enforces: it floors a finding's band at its base level, so a finding
  whose *base* level is high is immune to band tuning — the tunable surface is only
  low/medium-base findings that criticality lifts.
- **Promotion is unchanged.** A challenger goes live ONLY through the existing
  `garmr registry promote detector_config …` (human-admin-gated, fail-closed
  audited, C5-enforced); rollback is a repoint. Nothing in the learning plane
  mutates the serving policy (invariant #2).

**Deferred:** a generative/LLM challenger (behind an off-by-default feature),
serve-adoption of a promoted `DetectorConfig` as the live control plane (the one
behavior-changing seam), RBA-threshold challengers (per-host aggregate knobs the
per-row replay can't score faithfully), a server-side promote guard (refuse a
`DetectorConfig`→production unless it links a passing EvalRun + Dataset), active
learning, rich feature snapshots, a real ML calibrator (the Brier here is a
labelled estimate), a canary channel, and a `[learning]` config sub-struct.

Champion/challenger metrics: precision, recall, FP/FN rate, precision/recall @
alert-budget, confusion matrix, Brier score, calibration error, under/over-trigger
rate, mean investigation tool-calls/cost, mean time-to-decision, analyst override
rate, citation/evidence completeness, prompt-injection violations. **A challenger
that improves aggregate accuracy while materially increasing dangerous false
negatives is not promotable.**

Active learning prioritizes analyst review by uncertainty, detector disagreement,
novelty, asset criticality, expected information gain, and repeated agent–human
disagreement.

## Agent mistake learning (Phase 9) — shipped MLP

No self-modification. Phase 9 ships the ONE genuinely-new memory class — an
approved **procedural-memory `LessonSet`** — end to end, reusing the Phase-4
registry as the entire change plane (no new crate, no new redb table, no Config
field). Episodic memory (the Phase-3 `MistakeRecord`/prediction/decision/outcome
history) and semantic memory (the Phase-5 Trusted env facts) are CONSUMED, not
extended.

```
garmr reflect build   → deterministic, LLM-free clustering of MistakeRecords
                        → static gate (injection + weakening + caps, fail-closed)
                        → Draft RegistryKind::Lesson "triage" record
garmr registry promote lesson triage <version>   → human-approved, audited;
                        RE-VALIDATES the lesson at the approval boundary
serve start           → leader binds active(Lesson,"triage") and RE-VALIDATES it
triage                → rendered lessons appended INSIDE the trusted system field,
                        fenced + subordinate to the HARD LIMITS/injection rules;
                        every AgentPrediction stamps the lesson_set_version it read
```

- **Deterministic + LLM-free (invariant #5).** `garmr_learning::reflect` clusters
  analyst-authored `MistakeRecord`s by `MistakeCategory` and, for a category with
  `>= min_support` corroboration, emits a lesson whose body is the FROZEN
  `garmr_core::category_guidance` string — never model/attacker bytes. A
  case-scoped mistake counts only when that case's current `AnalystDecision` is a
  genuine correction (invariant #3 — never learn from an unadjudicated
  prediction).
- **Injection-safe BY CONSTRUCTION (load-bearing precondition).** Because a lesson
  body is one of a closed set of frozen constants, it cannot smuggle a
  prompt-injection. This is the *reason* the deferred behavioral golden-replay gate
  is safe to defer today — the moment variable text could enter a lesson body (a
  future LLM drafter), the static scan becomes the sole barrier and the behavioral
  replay would be required.
- **Recall-preserving BY CONSTRUCTION.** The guidance strings are additive "look
  harder / correlate / verify" discipline. Tool-economy categories
  (`UnnecessaryTools`/`MissingTools`) ship NO lesson — "use fewer tools" could
  lower recall and no gate in this MLP can prove it doesn't. A build-time test
  asserts every guidance string is injection- and weakening-clean.
- **Two-layer static gate, single-sourced.** `garmr_core::validate_lesson_set`
  (shared injection deny-list + a detection-weakening deny-list + the
  `LESSON_CAPS` scope caps) runs at BOTH draft time and the promotion boundary,
  from ONE set of constants. Promote-time re-validation runs ONLY on
  Promote/Rollback — a Retire/Reject that clears a bad lesson always succeeds, so
  the operator can always fall back to the safe no-lessons state. (It does not
  defend a forged-promotion redb-write path; that is a pre-existing property of
  every registry kind.)
- **Provenance + reversibility.** Every `AgentPrediction` records the exact
  `lesson_set_version` it read; rollback/retire repoints through the same audited
  channel and takes effect on serve restart (hot-reload deferred).

Three explicit memory classes, none of which accept raw model-generated text as
trusted:

- **Episodic** — the Phase-3 case/mistake/decision/outcome history reflection reads.
- **Semantic** — *approved* environment facts/relationships (see
  [environment-model](environment-model.md)), unchanged.
- **Procedural** — the approved `LessonSet` + the existing prompts/rules.

**Deferred:** the remaining proposal families (`PromptProposal`/`ToolPolicyProposal`
/`ThresholdProposal`/`RetrievalPolicyProposal`); an LLM-assisted reflection drafter
(behind an off-by-default feature — needs the behavioral golden replay); the
behavioral golden-replay gate that would prove a free-text lesson preserves recall;
a challenger-only tool-selection ranker; and lesson hot-reload.

## Registries (Phase 4)

Versioned, content-addressed registries back the whole plane: models, embeddings,
rerankers, prompts, toolsets, rules, detector configs, feature defs, datasets,
eval runs, releases. Nothing is promoted without a versioned record **and** an
`AuditEvent`. `ModelRecord`/`PromptRecord` carry digests, capability/safety
results, and an approval state.

## What must be preserved

The existing offline evaluation harness (`crates/garmr-agent/src/eval.rs`,
`GoldenSet`/`EvalMetrics`, `fixtures/eval-demo.json`) and the replay path
(`crates/garmr-cli/src/cmd/pipeline.rs:7`) are the seed of the challenger
evaluation stage and must keep passing.
