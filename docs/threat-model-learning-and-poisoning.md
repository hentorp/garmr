# Threat model — learning and poisoning

Scope: the adaptive parts of garmr — baselines, the environment model, the
learning plane, and agent memory. The guarantee: an adversary who can inject logs,
influence analyst inputs, or drive the agent **cannot** durably corrupt what garmr
treats as "normal" or as "true", and cannot cause an unsafe automated change.

Companion: [threat-model-audit-integrity](threat-model-audit-integrity.md).
Design: [architecture/learning-plane.md](architecture/learning-plane.md),
[architecture/environment-model.md](architecture/environment-model.md).

## Assets

- The **trusted normal baseline** (frequency/template/seasonal, environment facts).
- The **supervised label set** used for training/calibration.
- **Agent memory** (episodic/semantic/procedural) and the prompts/lessons/rules
  derived from it.
- The **promotion decision** for any challenger detector/model.

## Adversaries and capabilities

| Adversary | Capability |
|-----------|-----------|
| Log injector | controls content/volume of ingested events on a host |
| Compromised host | attacker owns a monitored asset; its traffic is "normal-looking" |
| Malicious/careless insider (Analyst) | can enter feedback/decisions |
| Prompt injector | plants text in logs/tool output the agent will read |
| Malicious MCP/tool | returns crafted tool output |
| Supply-chain | tampered bundle/model/dataset |

## Attack → defense

Mapped to mandatory tests (brief §TESTING 12–15, 25) plus the adversarial suite.

- **Baseline poisoning (slow-ramp).** Gradually raise volume so it normalizes.
  - Defense: baselines exclude events belonging to open/malicious cases and to
    known poisoning windows; seasonal robust statistics (median/MAD) + change-point
    detection flag ramps; environment facts stay **Candidate** until delayed
    promotion. *Tests: open malicious cases cannot promote candidate normal;
    known poisoning windows do not update trusted baselines.*
- **Log poisoning / novelty laundering.** Fire a novel template once so it becomes
  "known".
  - Defense: novelty promotion is gated on case outcome, not first sighting;
    quarantine + expiry; influence caps.
- **Label poisoning.** Feed wrong labels via feedback.
  - Defense: only trusted `AnalystDecision`/`IncidentOutcome` become labels;
    analyst identity+role recorded; conflicting labels detected and, when
    high-impact, held for review; **per-source/analyst/host/time-window influence
    caps**; unresolved cases excluded; **agent predictions never used directly as
    labels.** *Tests: predictions are never trusted labels; a corrected decision
    does not delete the previous one.*
- **Prediction feedback loop.** The agent's own past verdict nudges the next one.
  - Defense: prediction and decision are distinct types; memory recall marks
    provenance; unresolved self-predictions carry no positive learning weight.
- **Prompt / tool-output / MCP-description injection.** Steer the agent via data
  it reads.
  - Defense: preserved read-only tool surface + AST-level SQL guard + injection
    boundary; the agent can only *propose*; sandboxed MCP with signed manifests;
    prompt-injection golden set in model capability probing and challenger eval.
    *Test: prompt-injection golden cases remain safe.*
- **Challenger self-promotion.** A model/detector promotes itself.
  - Defense: promotion requires human approval + a versioned record + audit;
    challengers are read-only in shadow. *Test: a challenger cannot self-promote.*
- **Dangerous-FN regression.** A challenger raises aggregate accuracy but misses
  more real attacks.
  - Defense: promotion blocked when dangerous false negatives materially increase,
    regardless of aggregate gains.
- **Supply-chain tampering.** Poisoned bundle/model/dataset.
  - Defense (Phase 11): signed, content-addressed, verify-before-import, atomic,
    audited bundles; datasets/models are content-addressed with provenance.

## Confusable-concepts discipline

Novelty, Anomaly, ConceptDrift, ExpectedChange, SecurityFinding, and
ConfirmedIncident are **distinct** types and are never silently coerced into one
another (brief §TESTING 15). Concept drift (the world changed) must not be scored
as malicious, and expected change (a maintenance window / change record) must not
raise a finding.

## Residual risks

- A patient adversary who also controls the analyst *and* stays under every
  influence cap can bias slowly; mitigated by holdouts, drift monitoring, and
  audit of every promotion, not eliminated.
- Offline inventory import trusts the inventory source; its trust level is
  recorded and capped like any other source.
- Determined insiders with Admin can approve bad changes; every approval is
  audited and reversible, bounding blast radius rather than preventing intent.
