// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 4 — versioned, content-addressed registries.
//!
//! Every governed artifact — the model and prompt the agent runs, its toolset,
//! approved rules, detector configs, datasets, evaluation runs, and releases —
//! gets an **immutable** [`RegistryRecord`] identified by a BLAKE3
//! `content_digest`. A record is never rewritten; a changed artifact is a new
//! record. Governance (which version is *approved* / live) is a separate,
//! **append-only** stream of [`PromotionEvent`]s folded to a current view — so a
//! rollback or retirement is another append, never a mutation.
//!
//! The hard invariant (enforced in the CLI/API layer, which owns the audit
//! ledger): **no artifact is promoted without a versioned record AND an audit
//! event.** A [`PromotionEvent`] with an empty `audit_id` is inert on read
//! (see [`active`]), so a hand-forged redb row can never make an artifact "live".
//!
//! This module is pure (no I/O): the store persists records/events, the CLI
//! mints audit ids and emits events, and these folds derive the current view.
//! The typed `*Spec` helpers serialize into [`RegistryRecord::spec`] (kept as a
//! `serde_json::Value` so a newer writer never faults an older reader).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::RuntimeIdentity;

/// The kind of artifact a record governs. `Unknown` is the forward-compat
/// catch-all (a newer writer's kind decodes to `Unknown`, never an error).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryKind {
    Model,
    EmbeddingModel,
    Reranker,
    Prompt,
    Toolset,
    Rule,
    DetectorConfig,
    FeatureDef,
    Dataset,
    EvalRun,
    Release,
    /// Phase 9: an approved procedural-memory LessonSet.
    Lesson,
    // --- Phase A (audit-platform productization): the governed application-audit
    // catalog domains, modelled as registry kinds so each carries versioning,
    // approval/rollback and an audit-bound promotion for free (instead of the old
    // TOML-on-start load). The record `spec` holds the typed payload (a `Policy`,
    // a catalog entry, an application/resource descriptor, a monitoring profile). ---
    /// An access `Policy` (the app-audit engine enforces the active set).
    Policy,
    /// A resource catalog entry (object → classification/sensitivity).
    Catalog,
    /// An application / asset descriptor.
    Application,
    /// A resource (table/view/api/column) descriptor.
    Resource,
    /// A user-monitoring profile.
    Monitoring,
    #[default]
    #[serde(other)]
    Unknown,
}

impl RegistryKind {
    /// Stable lowercase tag used in redb keys and the CLI/API.
    pub fn tag(self) -> &'static str {
        match self {
            RegistryKind::Model => "model",
            RegistryKind::EmbeddingModel => "embedding_model",
            RegistryKind::Reranker => "reranker",
            RegistryKind::Prompt => "prompt",
            RegistryKind::Toolset => "toolset",
            RegistryKind::Rule => "rule",
            RegistryKind::DetectorConfig => "detector_config",
            RegistryKind::FeatureDef => "feature_def",
            RegistryKind::Dataset => "dataset",
            RegistryKind::EvalRun => "eval_run",
            RegistryKind::Release => "release",
            RegistryKind::Lesson => "lesson",
            RegistryKind::Policy => "policy",
            RegistryKind::Catalog => "catalog",
            RegistryKind::Application => "application",
            RegistryKind::Resource => "resource",
            RegistryKind::Monitoring => "monitoring",
            RegistryKind::Unknown => "unknown",
        }
    }

    /// Parse a CLI/API tag into a kind (`None` for an unrecognized tag).
    pub fn from_tag(s: &str) -> Option<RegistryKind> {
        let k = match s.trim().to_ascii_lowercase().as_str() {
            "model" => RegistryKind::Model,
            "embedding_model" | "embedding" => RegistryKind::EmbeddingModel,
            "reranker" => RegistryKind::Reranker,
            "prompt" => RegistryKind::Prompt,
            "toolset" => RegistryKind::Toolset,
            "rule" => RegistryKind::Rule,
            "detector_config" | "detector" => RegistryKind::DetectorConfig,
            "feature_def" | "feature" => RegistryKind::FeatureDef,
            "dataset" => RegistryKind::Dataset,
            "eval_run" | "eval" => RegistryKind::EvalRun,
            "release" => RegistryKind::Release,
            "lesson" => RegistryKind::Lesson,
            "policy" => RegistryKind::Policy,
            "catalog" => RegistryKind::Catalog,
            "application" | "app" => RegistryKind::Application,
            "resource" => RegistryKind::Resource,
            "monitoring" | "monitor" => RegistryKind::Monitoring,
            _ => return None,
        };
        Some(k)
    }
}

/// The birth approval state of a record. The EFFECTIVE state is a fold of the
/// promotion stream (see [`effective_state`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    #[default]
    Draft,
    Proposed,
    Approved,
    Rejected,
    Deprecated,
    Revoked,
    #[serde(other)]
    Unknown,
}

/// Where a record came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrySource {
    /// Observed as the running artifact (auto-registered at startup).
    #[default]
    Observed,
    /// Hand-registered by an operator.
    Operator,
    /// Proposed by the agent.
    AgentProposed,
    /// Imported from a signed bundle (Phase 11).
    Imported,
    #[serde(other)]
    Unknown,
}

/// A governance operation on a promotion channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionOp {
    #[default]
    Promote,
    Rollback,
    Retire,
    Reject,
    Deprecate,
    #[serde(other)]
    Unknown,
}

/// A capability-probe result (Phase 10 populates these; the shape lives here).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CapabilityResult {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub passed: bool,
    #[serde(default)]
    pub detail: String,
}

/// A safety-evaluation result (e.g. a prompt-injection golden set).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SafetyResult {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub passed: bool,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub detail: String,
}

/// An immutable registry record. Never rewritten — a changed artifact is a new
/// record with a new `content_digest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub kind: RegistryKind,
    /// Logical group: `claude-opus-4-8`, `system`, `builtin`, a rule id, a
    /// dataset name.
    #[serde(default)]
    pub name: String,
    /// A human semver label (operator records) OR the content digest (observed /
    /// machine records). The `(kind, name, version)` triple is the storage key.
    #[serde(default)]
    pub version: String,
    /// The immutable BLAKE3-hex identity of the artifact's content.
    #[serde(default)]
    pub content_digest: String,
    /// Lineage — the version this one descends from.
    #[serde(default)]
    pub parent_version: Option<String>,
    /// Why this version exists (a prompt/model change rationale).
    #[serde(default)]
    pub rationale: String,
    /// Forward references to eval runs known at registration time. Never
    /// back-patched (that would violate immutability) — "evals for X" is derived
    /// by scanning EvalRun records instead.
    #[serde(default)]
    pub eval_run_refs: Vec<String>,
    /// The BIRTH approval state; the effective state is the promotion fold.
    #[serde(default)]
    pub approval: ApprovalState,
    #[serde(default)]
    pub source: RegistrySource,
    #[serde(default = "Utc::now")]
    pub registered_at: DateTime<Utc>,
    #[serde(default)]
    pub registered_by: String,
    /// The audit event for the registration (if auditing was on).
    #[serde(default)]
    pub audit_id: Option<String>,
    /// The typed payload, preserved verbatim for forward compatibility.
    #[serde(default)]
    pub spec: serde_json::Value,
}

/// An append-only governance event on a `(kind, name, channel)` pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionEvent {
    #[serde(default)]
    pub promotion_id: String,
    #[serde(default)]
    pub kind: RegistryKind,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub op: PromotionOp,
    #[serde(default)]
    pub to_version: Option<String>,
    #[serde(default)]
    pub from_version: Option<String>,
    #[serde(default)]
    pub to_state: ApprovalState,
    /// `production` (default) | `staging` | `shadow`.
    #[serde(default)]
    pub channel: String,
    /// MUST equal the target version's `content_digest` for the event to bind.
    #[serde(default)]
    pub target_digest: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub actor: String,
    /// The invariant binding: the audit event for this promotion. An EMPTY value
    /// makes the event inert on read (a forged redb row can never promote).
    #[serde(default)]
    pub audit_id: String,
    /// The prior promotion id this one supersedes on the same `(name, channel)`.
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default = "Utc::now")]
    pub at: DateTime<Utc>,
}

// ---- typed specs (serialize into RegistryRecord.spec) ----------------------

/// Model / embedding / reranker spec — carries every brief-mandated ModelRecord
/// field not already on the envelope (`registered_at`, `approval`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelSpec {
    #[serde(default)]
    pub logical_name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub revision: String,
    /// BLAKE3 of the local weights file; empty for a hosted model.
    #[serde(default)]
    pub artifact_digest: String,
    #[serde(default)]
    pub tokenizer_digest: String,
    /// Digest of the model configuration; the `content_digest` for a hosted model.
    #[serde(default)]
    pub configuration_digest: String,
    #[serde(default)]
    pub quantization: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub runtime: RuntimeIdentity,
    #[serde(default)]
    pub supported_context: u32,
    #[serde(default)]
    pub supports_tool_calling: bool,
    #[serde(default)]
    pub supports_structured_outputs: bool,
    #[serde(default)]
    pub capability_results: Vec<CapabilityResult>,
    #[serde(default)]
    pub safety_results: Vec<SafetyResult>,
    /// The router role (embedding | reranker | local_reasoning_* | …), Phase 10.
    #[serde(default)]
    pub role: String,
}

/// Prompt spec — `content_digest = blake3(prompt_bytes)`, identical to the
/// agent's `system_prompt_digest()`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptSpec {
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub schema_digest: String,
}

/// Toolset spec — `content_digest == toolset_digest()`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsetSpec {
    #[serde(default)]
    pub tools: Vec<ToolEntry>,
}

/// A snapshot of the detection knobs — DECOUPLED from `DetectConfig`, so adding
/// a knob never ripples this record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorConfigSpec {
    #[serde(default)]
    pub risk_threshold: f64,
    #[serde(default)]
    pub risk_halflife_hours: f64,
    #[serde(default)]
    pub freq_k: f64,
    #[serde(default)]
    pub freq_min_count: u64,
    #[serde(default)]
    pub anomaly_min_count: u64,
    #[serde(default)]
    pub prediction_discount: f64,
    /// Digests of the loaded rule files.
    #[serde(default)]
    pub rule_digests: Vec<String>,
    /// Catch-all for future knobs (forward-compat).
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatasetSpec {
    #[serde(default)]
    pub row_count: u64,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub license: String,
}

/// Eval-run spec — the one place eval↔model/prompt linkage lives (forward refs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvalRunSpec {
    #[serde(default)]
    pub dataset_ref: String,
    #[serde(default)]
    pub model_ref: String,
    #[serde(default)]
    pub prompt_ref: String,
    #[serde(default)]
    pub toolset_digest: String,
    #[serde(default)]
    pub detector_config_ref: String,
    /// The serialized `EvalMetrics` (a `Value` to avoid a garmr-agent dep here).
    #[serde(default)]
    pub metrics: serde_json::Value,
    #[serde(default)]
    pub build_ref: String,
    #[serde(default)]
    pub cost_micro_usd: u64,
}

/// Release spec — the "what was live" anchor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReleaseSpec {
    #[serde(default)]
    pub model_ref: String,
    #[serde(default)]
    pub embed_ref: Option<String>,
    #[serde(default)]
    pub reranker_ref: Option<String>,
    #[serde(default)]
    pub prompt_ref: String,
    #[serde(default)]
    pub toolset_ref: String,
    #[serde(default)]
    pub ruleset_digest: String,
    #[serde(default)]
    pub detector_config_ref: String,
    #[serde(default)]
    pub feature_refs: Vec<String>,
    #[serde(default)]
    pub eval_evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSpec {
    /// `sigma` | `correlation`.
    #[serde(default)]
    pub rule_kind: String,
    #[serde(default)]
    pub source_proposal_id: String,
    #[serde(default)]
    pub installed_path: String,
    #[serde(default)]
    pub backtest: serde_json::Value,
}

// ---- digest helper + pure folds --------------------------------------------

/// A length-framed BLAKE3 hex digest over `parts` — deterministic and
/// independent of serde (map ordering would make a JSON digest unstable, the
/// same reason the audit ledger frames by hand). Prompt/dataset digests are over
/// raw bytes; a single part is the same as hashing those bytes directly.
pub fn frame(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().to_hex().to_string()
}

/// All records for a `(kind, name)` group.
pub fn records_for<'a>(
    kind: RegistryKind,
    name: &str,
    all: &'a [RegistryRecord],
) -> Vec<&'a RegistryRecord> {
    all.iter()
        .filter(|r| r.kind == kind && r.name == name)
        .collect()
}

/// The newest non-superseded, audit-bound promotion out of a set.
fn newest_binding(promotions: &[&PromotionEvent]) -> Option<usize> {
    // Build the superseded set ONLY from audit-bound promotions: an empty-audit
    // (forged) row is inert on read, so its `supersedes` must not be able to
    // knock a legitimate audited promotion out of contention.
    let superseded: std::collections::HashSet<&str> = promotions
        .iter()
        .filter(|e| !e.audit_id.is_empty())
        .filter_map(|e| e.supersedes.as_deref())
        .collect();
    promotions
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.audit_id.is_empty() && !superseded.contains(e.promotion_id.as_str()))
        .max_by(|(_, a), (_, b)| {
            a.at.cmp(&b.at)
                .then_with(|| a.promotion_id.cmp(&b.promotion_id))
        })
        .map(|(i, _)| i)
}

/// The effective approval state of a specific record version: the newest
/// audit-bound, non-superseded promotion whose `target_digest` matches this
/// record's `content_digest`; else the record's birth `approval`.
pub fn effective_state(rec: &RegistryRecord, promotions: &[PromotionEvent]) -> ApprovalState {
    let matching: Vec<&PromotionEvent> = promotions
        .iter()
        .filter(|e| {
            e.kind == rec.kind && e.name == rec.name && e.target_digest == rec.content_digest
        })
        .collect();
    match newest_binding(&matching) {
        Some(i) => matching[i].to_state,
        None => rec.approval,
    }
}

/// The active (live) record for a `(kind, name, channel)`: the target of the
/// newest audit-bound, non-superseded promotion that is a `Promote` to
/// `Approved`, whose `target_digest` matches a present record's `content_digest`.
/// Ignores any promotion with an empty `audit_id` (a forged row is inert).
pub fn active<'a>(
    kind: RegistryKind,
    name: &str,
    channel: &str,
    records: &'a [RegistryRecord],
    promotions: &[PromotionEvent],
) -> Option<&'a RegistryRecord> {
    // Only channel-pointer ops move what is live; per-version governance
    // (Reject/Deprecate) sets a version's effective_state but never the pointer.
    let pointer: Vec<&PromotionEvent> = promotions
        .iter()
        .filter(|e| {
            e.kind == kind
                && e.name == name
                && e.channel == channel
                && matches!(
                    e.op,
                    PromotionOp::Promote | PromotionOp::Rollback | PromotionOp::Retire
                )
        })
        .collect();
    let ev = pointer[newest_binding(&pointer)?];
    if ev.op == PromotionOp::Retire || ev.to_state != ApprovalState::Approved {
        return None; // retired, or promoted to a non-approved state
    }
    records
        .iter()
        .find(|r| r.kind == kind && r.name == name && r.content_digest == ev.target_digest)
}

/// A registry integrity finding — a stored-data violation of the promotion
/// invariants. Well-formed writes never produce one; a non-empty list means the
/// registry rows were tampered with (or a bug wrote an inconsistent row).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryFinding {
    /// Category slug, e.g. `unaudited-promotion`, `dangling-promotion`.
    pub category: String,
    /// The offending coordinate — a promotion id.
    pub coord: String,
    pub detail: String,
}

/// Check the registry's stored data upholds the promotion invariants:
///
///   * every PROMOTION carries a non-empty audit id (an empty one is inert on
///     read — a forged or unaudited row), and
///   * every pointer promotion (Promote/Rollback) targets a digest that a
///     present record actually has (no dangling pointer to a missing record).
///
/// Returns the findings; an empty vec means the registry is sound. Pure and
/// I/O-free, so it is trivially testable and runs offline against a store dump.
pub fn verify_registry(
    records: &[RegistryRecord],
    promotions: &[PromotionEvent],
) -> Vec<RegistryFinding> {
    let mut out = Vec::new();
    for e in promotions {
        if e.audit_id.is_empty() {
            out.push(RegistryFinding {
                category: "unaudited-promotion".to_string(),
                coord: e.promotion_id.clone(),
                detail: format!(
                    "{:?} of {}/{} has an empty audit_id — inert on read",
                    e.op,
                    e.kind.tag(),
                    e.name
                ),
            });
        }
        if matches!(e.op, PromotionOp::Promote | PromotionOp::Rollback) {
            let resolves = records.iter().any(|r| {
                r.kind == e.kind && r.name == e.name && r.content_digest == e.target_digest
            });
            if !resolves {
                out.push(RegistryFinding {
                    category: "dangling-promotion".to_string(),
                    coord: e.promotion_id.clone(),
                    detail: format!(
                        "{:?} of {}/{} targets digest {} with no matching record",
                        e.op,
                        e.kind.tag(),
                        e.name,
                        // A tampered row's target_digest is arbitrary bytes, not
                        // guaranteed hex — `str::get` returns None at a non-char
                        // boundary (or when short) instead of panicking the check.
                        e.target_digest.get(..12).unwrap_or(&e.target_digest)
                    ),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_tag_round_trips_including_the_governed_domains() {
        // Every non-Unknown kind's tag parses back to itself — so a record's
        // stored tag and the CLI/API tag are one vocabulary, and the Phase-A
        // governed domains join it.
        for k in [
            RegistryKind::Model,
            RegistryKind::Prompt,
            RegistryKind::Lesson,
            RegistryKind::Policy,
            RegistryKind::Catalog,
            RegistryKind::Application,
            RegistryKind::Resource,
            RegistryKind::Monitoring,
        ] {
            assert_eq!(RegistryKind::from_tag(k.tag()), Some(k), "{:?}", k);
        }
        // The governed tags are distinct (no accidental collision).
        assert_eq!(RegistryKind::from_tag("policy"), Some(RegistryKind::Policy));
        assert_eq!(
            RegistryKind::from_tag("monitoring"),
            Some(RegistryKind::Monitoring)
        );
        assert_eq!(RegistryKind::from_tag("nope"), None);
    }

    fn rec(kind: RegistryKind, name: &str, digest: &str) -> RegistryRecord {
        let mut r: RegistryRecord = serde_json::from_str("{}").unwrap();
        r.id = format!("{}-{digest}", kind.tag());
        r.kind = kind;
        r.name = name.into();
        r.version = digest.into();
        r.content_digest = digest.into();
        r.approval = ApprovalState::Draft;
        r
    }

    fn promo(
        name: &str,
        digest: &str,
        op: PromotionOp,
        state: ApprovalState,
        audit: &str,
    ) -> PromotionEvent {
        let mut e: PromotionEvent = serde_json::from_str("{}").unwrap();
        e.promotion_id = format!("p-{digest}-{}", e.at.timestamp_nanos_opt().unwrap_or(0));
        e.kind = RegistryKind::Prompt;
        e.name = name.into();
        e.op = op;
        e.to_state = state;
        e.channel = "production".into();
        e.target_digest = digest.into();
        e.audit_id = audit.into();
        e
    }

    #[test]
    fn everything_decodes_from_empty_object() {
        let _r: RegistryRecord = serde_json::from_str("{}").unwrap();
        let _e: PromotionEvent = serde_json::from_str("{}").unwrap();
        let _m: ModelSpec = serde_json::from_str("{}").unwrap();
        let _p: PromptSpec = serde_json::from_str("{}").unwrap();
        let _d: DetectorConfigSpec = serde_json::from_str("{}").unwrap();
        // Unknown kind/state tolerance (a newer writer's value).
        let k: RegistryKind = serde_json::from_str("\"some_future_kind\"").unwrap();
        assert_eq!(k, RegistryKind::Unknown);
        let s: ApprovalState = serde_json::from_str("\"quantum\"").unwrap();
        assert_eq!(s, ApprovalState::Unknown);
    }

    #[test]
    fn verify_flags_unaudited_and_dangling_promotions() {
        let records = vec![rec(RegistryKind::Prompt, "system", "d1")];
        // Sound: audited promote of a present digest.
        let ok = promo(
            "system",
            "d1",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a1",
        );
        assert!(verify_registry(&records, std::slice::from_ref(&ok)).is_empty());

        // Unaudited: empty audit id.
        let mut forged = promo(
            "system",
            "d1",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "",
        );
        forged.promotion_id = "forged".into();
        // Dangling: audited but targets a digest no record has.
        let dangling = promo(
            "system",
            "d-missing",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a2",
        );

        let findings = verify_registry(&records, &[ok, forged, dangling]);
        let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(
            cats.contains(&"unaudited-promotion"),
            "flags empty audit_id"
        );
        assert!(cats.contains(&"dangling-promotion"), "flags missing target");
        assert_eq!(findings.len(), 2, "the sound promotion is not flagged");
    }

    #[test]
    fn verify_does_not_panic_on_a_tampered_non_hex_digest() {
        // A forged row's target_digest is arbitrary bytes; byte 12 falling inside
        // a multi-byte char must not panic the integrity checker (it exists to
        // run over exactly this kind of tampered input).
        let records = vec![rec(RegistryKind::Prompt, "system", "d1")];
        let mut tampered = promo(
            "system",
            "aaaaaaaaaaa\u{20ac}", // 11 ASCII bytes + a 3-byte '€' → byte 12 mid-char
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a1",
        );
        tampered.promotion_id = "tampered".into();
        let findings = verify_registry(&records, std::slice::from_ref(&tampered));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "dangling-promotion");
    }

    #[test]
    fn frame_is_deterministic_and_length_framed() {
        assert_eq!(frame(&[b"abc"]), frame(&[b"abc"]));
        // Length framing: ["a","bc"] must differ from ["ab","c"].
        assert_ne!(frame(&[b"a", b"bc"]), frame(&[b"ab", b"c"]));
        // A single part equals hashing the raw bytes with the length prefix.
        assert_eq!(frame(&[b"hello"]).len(), 64); // blake3 hex
    }

    #[test]
    fn active_picks_newest_approved_and_ignores_forged_and_retired() {
        let records = vec![
            rec(RegistryKind::Prompt, "system", "d1"),
            rec(RegistryKind::Prompt, "system", "d2"),
        ];
        // Promote d1 (audited), then d2 (audited) superseding d1.
        let mut p1 = promo(
            "system",
            "d1",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a1",
        );
        let mut p2 = promo(
            "system",
            "d2",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a2",
        );
        p1.promotion_id = "p1".into();
        p2.promotion_id = "p2".into();
        p2.supersedes = Some("p1".into());
        p2.at = p1.at + chrono::Duration::seconds(1);
        let promos = vec![p1, p2];
        let a = active(
            RegistryKind::Prompt,
            "system",
            "production",
            &records,
            &promos,
        )
        .unwrap();
        assert_eq!(a.content_digest, "d2");

        // A forged (audit-less) promotion of d1 must NOT flip active back.
        let mut forged = promo(
            "system",
            "d1",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "",
        );
        forged.promotion_id = "forged".into();
        forged.at = promos[1].at + chrono::Duration::seconds(10);
        let mut with_forged = promos.clone();
        with_forged.push(forged);
        assert_eq!(
            active(
                RegistryKind::Prompt,
                "system",
                "production",
                &records,
                &with_forged
            )
            .unwrap()
            .content_digest,
            "d2",
            "a forged audit-less promotion is inert"
        );

        // A Retire supersedes → no active record.
        let mut retire = promo(
            "system",
            "d2",
            PromotionOp::Retire,
            ApprovalState::Deprecated,
            "a3",
        );
        retire.promotion_id = "p3".into();
        retire.supersedes = Some("p2".into());
        retire.at = promos[1].at + chrono::Duration::seconds(5);
        let mut with_retire = promos.clone();
        with_retire.push(retire);
        assert!(active(
            RegistryKind::Prompt,
            "system",
            "production",
            &records,
            &with_retire
        )
        .is_none());
    }

    #[test]
    fn effective_state_folds_promotions_per_version() {
        let r = rec(RegistryKind::Prompt, "system", "d1");
        assert_eq!(effective_state(&r, &[]), ApprovalState::Draft); // birth
        let approved = promo(
            "system",
            "d1",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a1",
        );
        assert_eq!(effective_state(&r, &[approved]), ApprovalState::Approved);
        // A different version's promotion doesn't affect this one.
        let other = promo(
            "system",
            "d2",
            PromotionOp::Promote,
            ApprovalState::Approved,
            "a2",
        );
        assert_eq!(effective_state(&r, &[other]), ApprovalState::Draft);
    }
}
