# garmr documentation

A one-person agentic SOC in Rust. This index maps the docs; start with the
[root README](../README.md) for what garmr is and how to run it.

## Architecture

The detection, governance, and learning planes.

| Doc | Covers |
|---|---|
| [adaptive-audit-soc](architecture/adaptive-audit-soc.md) | The audit-first SOC initiative and its phases |
| [access-policy-engine](architecture/access-policy-engine.md) | Policy model, evaluation, `simulate` backtest |
| [application-audit-analytics](architecture/application-audit-analytics.md) | The app-audit detection plane (stateless + stateful) |
| [user-behavior-analytics](architecture/user-behavior-analytics.md) | Per-user baselines, footprint, peer groups |
| [postgresql-audit](architecture/postgresql-audit.md) | pgAudit ingestion and normalisation |
| [environment-model](architecture/environment-model.md) | The temporal environment model + anti-poisoning gate |
| [hybrid-investigation-search](architecture/hybrid-investigation-search.md) | Full-text + semantic + Query-IR search |
| [governed-persistence](architecture/governed-persistence.md) | Versioned registry: policies/catalog/monitoring/detector configs |
| [learning-plane](architecture/learning-plane.md) | Offline, human-gated learning; champion/challenger |
| [shadow-evaluation](architecture/shadow-evaluation.md) | **DoD 19** live champion/challenger shadow evaluation |
| [model-routing](architecture/model-routing.md) | LLM/model routing by sensitivity and capability |
| [webui-information-architecture](architecture/webui-information-architecture.md) | Console IA (the canonical 12-area map) |

## Operate

| Doc | Covers |
|---|---|
| [access-audit](access-audit.md) | The access-audit alert rules and how they fire |
| [authentication](authentication.md) | Bearer + passkey (WebAuthn) auth on the console/API |
| [backup-design](backup-design.md) | Backup, restore, and the restored-not-promoted refusal |
| [ha-design](ha-design.md) | Leader/follower roles and failover |
| [retention-and-scale](retention-and-scale.md) | Retention tiers, cold archives, scale envelope |
| [airgap](airgap.md) | The Skidbladnir airgapped profile (no egress) |
| [local-llm](local-llm.md) | Running the agent on a local LLM (Ollama / llama.cpp) + GPU |
| [supply-chain](supply-chain.md) | SBOM, provenance, signed releases |
| [packaging/pgaudit-collector](packaging/pgaudit-collector.md) | The pgAudit collector: systemd unit, spool, install |

## Lab & verification

| Doc | Covers |
|---|---|
| [lab/pve-topology](lab/pve-topology.md) | The Proxmox lab + isolated test-role estate |
| [lab/test-environment](lab/test-environment.md) | Standing up a test environment |
| `scripts/resilience-harness.sh` | **DoD 23/25** resilience/airgap scenarios (safety-interlocked) |
| `garmr synth-eval` | **DoD 21** labeled detection eval (recall/FPR over the fused pipeline) |

## WebUI

The console guides live under [webui/](webui/): the
[analyst](webui/analyst-guide.md), [operator](webui/operator-guide.md), and
[admin](webui/admin-guide.md) guides, plus
[information-architecture](webui/information-architecture.md),
[design-system](webui/design-system.md), [accessibility](webui/accessibility.md),
and [testing](webui/testing.md).

## Threat models

The invariants each subsystem defends, and the attacks it must survive:
[insider-risk](threat-models/insider-risk.md),
[audit-log-poisoning](threat-models/audit-log-poisoning.md),
[baseline-poisoning](threat-models/baseline-poisoning.md),
[sensitive-search-and-export](threat-models/sensitive-search-and-export.md),
and the cross-cutting
[audit-integrity](threat-model-audit-integrity.md) and
[learning-and-poisoning](threat-model-learning-and-poisoning.md) models.

## Status & decisions

- [status/productization-roadmap](status/productization-roadmap.md) — the DoD work and its state
- [status/pre-productization-assessment](status/pre-productization-assessment.md) — the Phase-0 subsystem map
- [adr/](adr/) — architecture decision records
- [ai-context](ai-context.md) — the generated AI context pack

## Reference

- [cli-reference](cli-reference.md) — every `garmr` subcommand
