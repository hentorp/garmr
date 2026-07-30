// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 10 — the pure model-routing POLICY (no I/O), next to [`crate::egress`].
//!
//! Chooses among the configured models by DATA CLASSIFICATION + air-gap +
//! availability, in operator order. Two hard, non-removable floors:
//!
//! * **Restricted/confidential data never reaches an EXTERNAL model.** The
//!   external ceiling is [`EXTERNAL_CEILING`] (`Internal`); config may only
//!   TIGHTEN a model's ceiling, never loosen it. Locality is DERIVED from the
//!   endpoint host (not a config flag), so a mislabeled entry can't bypass.
//! * **No silent fallback.** [`decide`] returns exactly one model or `Degraded`
//!   with a reason; the runtime turns a degrade into the existing `NeedsHuman`
//!   state — it never re-routes to an egressing model.
//!
//! The MLP guarantee is scoped to the trigger event's canonical access fields +
//! the explicit `data_classification` tag; PII arriving in a free-text message
//! body or pulled in by the tool loop is NOT auto-classified — the operator's
//! `default_classification` floor is the mitigation (set it to `confidential` for
//! a register/PII deployment).

use serde::{Deserialize, Serialize};

use crate::egress::{host_of, is_local};
use crate::{AccessProjection, Event, LlmBackend};

/// Data sensitivity, low→high. Declaration order IS the lattice (`Ord`). Mirrors
/// `garmr_audit::DataClassification`; a test pins the tags + order so the two
/// (garmr-core must not depend on garmr-audit) never drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    #[default]
    Internal,
    Confidential,
    Restricted,
    Secret,
}

impl DataClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            DataClassification::Public => "public",
            DataClassification::Internal => "internal",
            DataClassification::Confidential => "confidential",
            DataClassification::Restricted => "restricted",
            DataClassification::Secret => "secret",
        }
    }

    /// Parse a tag; unknown → `None` (so an unrecognized tag never LOWERS the
    /// computed classification — it is simply ignored).
    pub fn from_tag(s: &str) -> Option<DataClassification> {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" => Some(DataClassification::Public),
            "internal" => Some(DataClassification::Internal),
            "confidential" => Some(DataClassification::Confidential),
            "restricted" => Some(DataClassification::Restricted),
            "secret" => Some(DataClassification::Secret),
            _ => None,
        }
    }
}

/// The highest sensitivity an EXTERNAL model may ever handle. A non-removable
/// code floor — config can only tighten a model's ceiling below this.
pub const EXTERNAL_CEILING: DataClassification = DataClassification::Internal;

/// One configured model (a `[route.router] models` entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub backend: LlmBackend,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub openai_base_url: Option<String>,
    /// The operator's per-model ceiling. May only TIGHTEN the derived ceiling.
    #[serde(default)]
    pub max_sensitivity: Option<DataClassification>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// A free-form role label (e.g. `triage`, `prefilter`) — provenance only.
    #[serde(default)]
    pub role: String,
}

fn default_true() -> bool {
    true
}

/// The OpenAI-compat base default (shared with `build_backend_provider`) — used
/// ONLY for the locality decision, never for the descriptor digest.
pub const DEFAULT_OPENAI_BASE: &str = "http://localhost:11434/v1";

impl ModelEntry {
    /// Is this model LOCAL? Derived from the endpoint host, never configured, so
    /// a mislabeled entry can't bypass the sensitivity floor.
    pub fn is_local(&self) -> bool {
        match self.backend {
            LlmBackend::Anthropic => false,
            LlmBackend::OpenAiCompat => {
                let base = self
                    .openai_base_url
                    .as_deref()
                    .unwrap_or(DEFAULT_OPENAI_BASE);
                is_local(host_of(base).unwrap_or(""))
            }
        }
    }

    /// The effective sensitivity ceiling: an external model is capped at
    /// `EXTERNAL_CEILING` and config may only tighten; a local model defaults to
    /// `Secret` and config may only tighten.
    pub fn ceiling(&self) -> DataClassification {
        if self.is_local() {
            self.max_sensitivity.unwrap_or(DataClassification::Secret)
        } else {
            let cfg = self.max_sensitivity.unwrap_or(EXTERNAL_CEILING);
            EXTERNAL_CEILING.min(cfg)
        }
    }

    /// The model's identity descriptor — byte-identical to `registry_observe`'s
    /// formula, over the RAW base (empty when `None`), so a routed model's stamp
    /// resolves to its observed registry record.
    pub fn descriptor(&self) -> String {
        model_descriptor(
            self.backend,
            &self.model,
            self.openai_base_url.as_deref().unwrap_or(""),
        )
    }

    pub fn descriptor_digest(&self) -> String {
        model_descriptor_digest(
            self.backend,
            &self.model,
            self.openai_base_url.as_deref().unwrap_or(""),
        )
    }
}

/// `[route.router]` config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub models: Vec<ModelEntry>,
    /// The classification FLOOR for every case (raise to `confidential` for a
    /// register/PII deployment). Default `Internal`.
    #[serde(default)]
    pub default_classification: DataClassification,
}

/// The routing inputs.
#[derive(Debug, Clone, Copy)]
pub struct RouteInput {
    pub classification: DataClassification,
    pub airgap: bool,
}

/// The routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Use the catalog entry at this index.
    Use(usize),
    /// No permitted model; the reason (for the NeedsHuman record).
    Degraded(String),
}

/// The pure routing decision over a catalog, in operator order: skip disabled
/// models, skip a model whose ceiling is below the data classification (the
/// sensitivity floor, fail-closed), skip an external model under air-gap; return
/// the first survivor, else `Degraded`.
pub fn decide(catalog: &[ModelEntry], input: RouteInput) -> RouteDecision {
    if catalog.is_empty() {
        return RouteDecision::Degraded("no models configured".into());
    }
    let mut reasons = Vec::new();
    for (i, e) in catalog.iter().enumerate() {
        if !e.enabled {
            reasons.push(format!("{}: disabled", e.name));
            continue;
        }
        if input.classification > e.ceiling() {
            reasons.push(format!(
                "{}: ceiling {} < {} data",
                e.name,
                e.ceiling().as_str(),
                input.classification.as_str()
            ));
            continue;
        }
        if !e.is_local() && input.airgap {
            reasons.push(format!("{}: external, denied by air-gap", e.name));
            continue;
        }
        return RouteDecision::Use(i);
    }
    RouteDecision::Degraded(format!("no permitted model ({})", reasons.join("; ")))
}

/// Classify a triggering event: the monotonic-up MAX of the operator floor, the
/// canonical register-access PII lift (a data subject ⇒ Confidential, a watched
/// subject ⇒ Restricted — domain-neutral, no register branch), and the explicit
/// `data_classification` tag. An attacker-influenced tag can only RAISE the
/// classification (never lower it below the computed floor), and an unknown tag
/// is ignored.
pub fn classify_event(ev: &Event, floor: DataClassification) -> DataClassification {
    let mut c = floor;
    if let Some(proj) = AccessProjection::from_event(ev) {
        if proj.subject.is_some() {
            c = c.max(DataClassification::Confidential);
        }
        if proj.watched {
            c = c.max(DataClassification::Restricted);
        }
    }
    if let Some(tag) = ev
        .field("data_classification")
        .and_then(DataClassification::from_tag)
    {
        c = c.max(tag);
    }
    c
}

/// The model identity descriptor: `"{backend:?}|{model}|{base}"` — byte-identical
/// to `registry_observe`'s formula. `base` is the RAW configured base (empty when
/// unset), NOT the localhost default.
pub fn model_descriptor(backend: LlmBackend, model: &str, base: &str) -> String {
    format!("{backend:?}|{model}|{base}")
}

/// The BLAKE3-hex digest of [`model_descriptor`] (raw blake3, matching the
/// existing `registry_observe` digest — not the length-framed `frame`).
pub fn model_descriptor_digest(backend: LlmBackend, model: &str, base: &str) -> String {
    blake3::hash(model_descriptor(backend, model, base).as_bytes())
        .to_hex()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ev(fields: &[(&str, &str)]) -> Event {
        let mut f = BTreeMap::new();
        for (k, v) in fields {
            f.insert(k.to_string(), v.to_string());
        }
        Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            service: "s".into(),
            source: "src".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: "m".into(),
            fields: f,
        }
    }

    fn entry(name: &str, backend: LlmBackend, base: Option<&str>) -> ModelEntry {
        ModelEntry {
            name: name.into(),
            backend,
            model: "m".into(),
            openai_base_url: base.map(|s| s.into()),
            max_sensitivity: None,
            enabled: true,
            role: String::new(),
        }
    }

    #[test]
    fn classification_ordering_and_tags_mirror_the_audit_ledger() {
        // Order (the lattice) + the snake_case tags must match garmr_audit.
        assert!(DataClassification::Public < DataClassification::Internal);
        assert!(DataClassification::Internal < DataClassification::Confidential);
        assert!(DataClassification::Confidential < DataClassification::Restricted);
        assert!(DataClassification::Restricted < DataClassification::Secret);
        for (c, t) in [
            (DataClassification::Public, "public"),
            (DataClassification::Internal, "internal"),
            (DataClassification::Confidential, "confidential"),
            (DataClassification::Restricted, "restricted"),
            (DataClassification::Secret, "secret"),
        ] {
            assert_eq!(c.as_str(), t);
            assert_eq!(DataClassification::from_tag(t), Some(c));
        }
    }

    #[test]
    fn external_ceiling_denies_confidential_even_when_not_airgapped() {
        let anthropic = entry("cloud", LlmBackend::Anthropic, None);
        let cat = vec![anthropic];
        // Internal is allowed externally...
        assert_eq!(
            decide(
                &cat,
                RouteInput {
                    classification: DataClassification::Internal,
                    airgap: false
                }
            ),
            RouteDecision::Use(0)
        );
        // ...but Confidential is NOT, air-gap or not.
        assert!(matches!(
            decide(
                &cat,
                RouteInput {
                    classification: DataClassification::Confidential,
                    airgap: false
                }
            ),
            RouteDecision::Degraded(_)
        ));
    }

    #[test]
    fn airgap_denies_external_but_allows_local() {
        let cat = vec![
            entry("cloud", LlmBackend::Anthropic, None),
            entry(
                "local",
                LlmBackend::OpenAiCompat,
                Some("http://127.0.0.1:11434/v1"),
            ),
        ];
        // Air-gap skips the external cloud and picks the local model.
        assert_eq!(
            decide(
                &cat,
                RouteInput {
                    classification: DataClassification::Internal,
                    airgap: true
                }
            ),
            RouteDecision::Use(1)
        );
    }

    #[test]
    fn a_local_model_handles_confidential_and_secret() {
        let cat = vec![entry(
            "local",
            LlmBackend::OpenAiCompat,
            Some("http://10.0.0.5:11434/v1"),
        )];
        assert_eq!(
            decide(
                &cat,
                RouteInput {
                    classification: DataClassification::Secret,
                    airgap: true
                }
            ),
            RouteDecision::Use(0)
        );
    }

    #[test]
    fn max_sensitivity_only_tightens() {
        let mut e = entry(
            "local",
            LlmBackend::OpenAiCompat,
            Some("http://127.0.0.1:11434/v1"),
        );
        e.max_sensitivity = Some(DataClassification::Internal); // tighten a local model
        assert!(matches!(
            decide(
                &[e],
                RouteInput {
                    classification: DataClassification::Confidential,
                    airgap: true
                }
            ),
            RouteDecision::Degraded(_)
        ));
    }

    #[test]
    fn catalog_order_is_operator_preference() {
        let cat = vec![
            entry(
                "first",
                LlmBackend::OpenAiCompat,
                Some("http://127.0.0.1:1/v1"),
            ),
            entry(
                "second",
                LlmBackend::OpenAiCompat,
                Some("http://127.0.0.1:2/v1"),
            ),
        ];
        assert_eq!(
            decide(
                &cat,
                RouteInput {
                    classification: DataClassification::Internal,
                    airgap: false
                }
            ),
            RouteDecision::Use(0)
        );
    }

    #[test]
    fn empty_and_none_permitted_degrade() {
        assert!(matches!(
            decide(
                &[],
                RouteInput {
                    classification: DataClassification::Internal,
                    airgap: false
                }
            ),
            RouteDecision::Degraded(_)
        ));
        let disabled = ModelEntry {
            enabled: false,
            ..entry(
                "x",
                LlmBackend::OpenAiCompat,
                Some("http://127.0.0.1:11434/v1"),
            )
        };
        assert!(matches!(
            decide(
                &[disabled],
                RouteInput {
                    classification: DataClassification::Internal,
                    airgap: false
                }
            ),
            RouteDecision::Degraded(_)
        ));
    }

    #[test]
    fn classify_is_monotonic_up_over_pii_and_tag() {
        // A register-access event (db_user + target_person) → Confidential.
        let c = classify_event(
            &ev(&[("db_user", "sa"), ("target_person", "p")]),
            DataClassification::Internal,
        );
        assert_eq!(c, DataClassification::Confidential);
        // watched → Restricted.
        let w = classify_event(
            &ev(&[
                ("db_user", "sa"),
                ("target_person", "p"),
                ("watched", "true"),
            ]),
            DataClassification::Internal,
        );
        assert_eq!(w, DataClassification::Restricted);
        // explicit tag raises; an unknown tag is ignored (stays at floor).
        assert_eq!(
            classify_event(
                &ev(&[("data_classification", "secret")]),
                DataClassification::Internal
            ),
            DataClassification::Secret
        );
        assert_eq!(
            classify_event(
                &ev(&[("data_classification", "nonsense")]),
                DataClassification::Internal
            ),
            DataClassification::Internal
        );
        // a tag can never LOWER below the computed floor.
        assert_eq!(
            classify_event(
                &ev(&[
                    ("db_user", "sa"),
                    ("target_person", "p"),
                    ("data_classification", "public")
                ]),
                DataClassification::Internal
            ),
            DataClassification::Confidential
        );
    }

    #[test]
    fn descriptor_uses_the_raw_base_not_the_localhost_default() {
        // A no-base OpenAiCompat entry: is_local() uses the localhost default (so
        // it's local), but the descriptor hashes the RAW empty base — matching
        // registry_observe, so the stamp resolves to the record.
        let e = entry("local", LlmBackend::OpenAiCompat, None);
        assert!(e.is_local());
        assert_eq!(
            e.descriptor(),
            model_descriptor(LlmBackend::OpenAiCompat, "m", "")
        );
        assert_ne!(
            e.descriptor(),
            model_descriptor(LlmBackend::OpenAiCompat, "m", DEFAULT_OPENAI_BASE)
        );
    }
}
