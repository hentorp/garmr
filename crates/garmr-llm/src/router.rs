// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 10 — the `ModelRouter` runtime: the execution layer over the pure
//! [`garmr_core`] routing policy. It selects EXACTLY ONE model per case and
//! builds it through the ONE egress chokepoint (the independent second
//! enforcement). There is NO silent fallback — a denial or a degrade is terminal
//! (the agent turns it into `NeedsHuman`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use garmr_core::{
    classify_event, decide, AgentConfig, DataClassification, EgressPolicy, Event, LlmBackend,
    ModelEntry, RouteDecision, RouteInput, RouterConfig,
};

use crate::{build_backend_provider, LlmHttpConfig, LlmProvider};

/// A resolved routing decision: the provider to use + the provenance of the model
/// that will answer.
#[derive(Clone)]
pub struct Resolved {
    pub provider: Arc<dyn LlmProvider>,
    pub model: String,
    pub backend: LlmBackend,
    pub descriptor_digest: String,
    pub classification: DataClassification,
    pub local: bool,
    /// True when the model came from the configured catalog (vs the default).
    pub from_catalog: bool,
}

/// Why routing produced no usable model.
#[derive(Debug, Clone)]
pub enum RouteError {
    /// No permitted model for this classification (the safe NeedsHuman path).
    Degraded {
        reason: String,
        classification: DataClassification,
    },
    /// The chosen model failed to build (egress-denied or missing key). NO retry
    /// against another model — that would be a silent fallback.
    Build(String),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::Degraded { reason, .. } => write!(f, "no model routed: {reason}"),
            RouteError::Build(e) => write!(f, "model build failed: {e}"),
        }
    }
}

fn entry_from_agent(agent: &AgentConfig) -> ModelEntry {
    ModelEntry {
        name: "agent".into(),
        backend: agent.backend,
        model: agent.model.clone(),
        openai_base_url: agent.openai_base_url.clone(),
        max_sensitivity: None,
        enabled: true,
        role: "agent".into(),
    }
}

/// Owns the providers + the routing policy for triage.
pub struct ModelRouter {
    default_provider: Arc<dyn LlmProvider>,
    default_entry: ModelEntry,
    catalog: Vec<ModelEntry>,
    default_classification: DataClassification,
    egress: EgressPolicy,
    http: LlmHttpConfig,
    cache: Mutex<HashMap<String, Arc<dyn LlmProvider>>>,
}

impl ModelRouter {
    /// Build from the pre-constructed default provider + config. The default
    /// provider must already be policy-constructible (serve builds it first — a
    /// denied `cfg.agent` under air-gap fails startup; point it at a local
    /// endpoint in an air-gapped deployment).
    pub fn new(
        default_provider: Arc<dyn LlmProvider>,
        agent: &AgentConfig,
        cfg: &RouterConfig,
        egress: EgressPolicy,
    ) -> Self {
        Self {
            default_provider,
            default_entry: entry_from_agent(agent),
            catalog: cfg.models.clone(),
            default_classification: cfg.default_classification,
            egress,
            http: LlmHttpConfig::from_env(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// A permissive, catalog-less router over a single provider — for eval /
    /// one-shot paths (the mock provider drives the loop unchanged).
    pub fn for_default(default_provider: Arc<dyn LlmProvider>, agent: &AgentConfig) -> Self {
        Self {
            default_provider,
            default_entry: entry_from_agent(agent),
            catalog: Vec::new(),
            default_classification: DataClassification::Internal,
            egress: EgressPolicy::permissive(),
            http: LlmHttpConfig::from_env(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Classify a case's triggering event against the operator floor.
    pub fn classify(&self, ev: &Event) -> DataClassification {
        classify_event(ev, self.default_classification)
    }

    /// Resolve exactly one model for a classification. A non-empty catalog is
    /// AUTHORITATIVE (the default is NOT auto-appended); an empty catalog routes
    /// to the pre-built default (today's single shared client), still gated by
    /// the sensitivity ceiling + air-gap via `decide`.
    pub fn resolve(&self, class: DataClassification) -> Result<Resolved, RouteError> {
        let from_catalog = !self.catalog.is_empty();
        let candidates: &[ModelEntry] = if from_catalog {
            &self.catalog
        } else {
            std::slice::from_ref(&self.default_entry)
        };
        let input = RouteInput {
            classification: class,
            airgap: self.egress.is_airgap(),
        };
        let idx = match decide(candidates, input) {
            RouteDecision::Use(i) => i,
            RouteDecision::Degraded(reason) => {
                return Err(RouteError::Degraded {
                    reason,
                    classification: class,
                })
            }
        };
        let entry = &candidates[idx];
        let provider = if from_catalog {
            self.build_or_cache(entry)?
        } else {
            self.default_provider.clone()
        };
        Ok(Resolved {
            provider,
            model: entry.model.clone(),
            backend: entry.backend,
            descriptor_digest: entry.descriptor_digest(),
            classification: class,
            local: entry.is_local(),
            from_catalog,
        })
    }

    fn build_or_cache(&self, entry: &ModelEntry) -> Result<Arc<dyn LlmProvider>, RouteError> {
        let digest = entry.descriptor_digest();
        // A poisoned lock must never wedge triage.
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = cache.get(&digest) {
            return Ok(p.clone());
        }
        let p = build_backend_provider(
            entry.backend,
            entry.openai_base_url.as_deref(),
            &self.egress,
            self.http,
        )
        .map_err(|e| RouteError::Build(e.to_string()))?;
        cache.insert(digest, p.clone());
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LlmRequest, LlmResponse, StopReason, Usage};
    use async_trait::async_trait;

    struct Mock;
    #[async_trait]
    impl LlmProvider for Mock {
        async fn complete(&self, _req: &LlmRequest) -> garmr_core::Result<LlmResponse> {
            Ok(LlmResponse {
                text: String::new(),
                tool_calls: Vec::new(),
                assistant_blocks: Vec::new(),
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn agent(backend: &str, base: Option<&str>) -> AgentConfig {
        serde_json::from_value(serde_json::json!({
            "backend": backend, "model": "m", "openai_base_url": base,
        }))
        .unwrap()
    }

    fn router_cfg(models: serde_json::Value, default_class: &str) -> RouterConfig {
        serde_json::from_value(serde_json::json!({
            "models": models, "default_classification": default_class,
        }))
        .unwrap()
    }

    #[test]
    fn empty_catalog_uses_the_prebuilt_default() {
        let r = ModelRouter::new(
            Arc::new(Mock),
            &agent("anthropic", None),
            &router_cfg(serde_json::json!([]), "internal"),
            EgressPolicy::permissive(),
        );
        let res = r.resolve(DataClassification::Internal).unwrap();
        assert!(!res.from_catalog);
    }

    #[test]
    fn confidential_case_with_only_external_default_degrades() {
        // External default + Confidential data → no permitted model → Degraded
        // (the agent turns this into NeedsHuman); the default provider is NOT used.
        let r = ModelRouter::new(
            Arc::new(Mock),
            &agent("anthropic", None),
            &router_cfg(serde_json::json!([]), "internal"),
            EgressPolicy::permissive(),
        );
        assert!(matches!(
            r.resolve(DataClassification::Confidential),
            Err(RouteError::Degraded { .. })
        ));
    }

    #[test]
    fn airgap_only_external_catalog_confidential_degrades_and_builds_nothing() {
        let r = ModelRouter::new(
            Arc::new(Mock),
            &agent("open_ai_compat", Some("http://127.0.0.1:11434/v1")),
            &router_cfg(
                serde_json::json!([{"name": "cloud", "backend": "anthropic", "model": "c"}]),
                "internal",
            ),
            EgressPolicy::airgap(),
        );
        // The only catalog model is external → air-gap denies it → Degraded, no
        // build attempt, no fallback to the local default.
        assert!(matches!(
            r.resolve(DataClassification::Internal),
            Err(RouteError::Degraded { .. })
        ));
    }

    #[test]
    fn for_default_is_permissive_and_catalogless() {
        let r = ModelRouter::for_default(Arc::new(Mock), &agent("anthropic", None));
        // Internal routes to the default; classify delegates to core (tested there).
        assert!(
            !r.resolve(DataClassification::Internal)
                .unwrap()
                .from_catalog
        );
    }
}
