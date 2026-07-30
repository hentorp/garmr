// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-llm` — one [`LlmProvider`] trait over two backends: the Anthropic
//! Messages API (hand-rolled, rustls) and any OpenAI-compatible endpoint
//! (Ollama / llama.cpp). The neutral request/response [`types`] keep the
//! agent's tool loop backend-agnostic, so garmr can triage on cloud Claude or
//! a fully offline local model behind the same code.

mod anthropic;
mod openai_compat;
mod provider;
mod retry;
mod router;
pub mod types;

pub use router::{ModelRouter, Resolved, RouteError};

use std::sync::Arc;

use garmr_core::{AgentConfig, Error, LlmBackend, Result};

pub use anthropic::AnthropicProvider;
pub use openai_compat::OpenAiCompatProvider;
pub use provider::LlmProvider;
pub use retry::LlmHttpConfig;

/// Approximate USD-per-million-token prices (input, output) for the budget
/// ledger. Only the models garmr targets are listed; local models cost nothing.
pub fn price_per_mtok(model: &str) -> (f64, f64) {
    match model {
        m if m.starts_with("claude-opus") => (5.0, 25.0),
        m if m.starts_with("claude-sonnet") => (3.0, 15.0),
        m if m.starts_with("claude-haiku") => (1.0, 5.0),
        m if m.starts_with("claude-fable") => (10.0, 50.0),
        // Local / unknown models cost nothing.
        _ => (0.0, 0.0),
    }
}

/// Build the configured provider. Reads secrets from the environment:
/// `ANTHROPIC_API_KEY` for the Anthropic backend, `GARMR_OPENAI_API_KEY`
/// (optional) for an authenticated OpenAI-compatible endpoint.
pub fn build_provider(cfg: &AgentConfig) -> Result<Arc<dyn LlmProvider>> {
    build_provider_with(cfg, garmr_core::egress::global())
}

/// The egress-gated build, parameterized on the policy so airgap-deny tests use
/// an explicit policy and never touch the process-global `OnceLock`.
fn build_provider_with(
    cfg: &AgentConfig,
    egress: &garmr_core::EgressPolicy,
) -> Result<Arc<dyn LlmProvider>> {
    build_backend_provider(
        cfg.backend,
        cfg.openai_base_url.as_deref(),
        egress,
        LlmHttpConfig::from_env(),
    )
}

/// Build a provider for a `(backend, base_url)` — the ONE egress-gated
/// construction path, reused by `build_provider` and the Phase-10 model router.
/// The backend is checked FIRST, before its env-key read, so an airgapped
/// external backend errors loudly (no silent fallback) while a loopback/LAN local
/// model still builds (invariant #6).
pub fn build_backend_provider(
    backend: LlmBackend,
    base_url: Option<&str>,
    egress: &garmr_core::EgressPolicy,
    http: LlmHttpConfig,
) -> Result<Arc<dyn LlmProvider>> {
    use garmr_core::EgressClass;
    let denied = |e: garmr_core::EgressDenied| Error::Llm(format!("egress denied by policy: {e}"));
    match backend {
        LlmBackend::Anthropic => {
            egress
                .check(EgressClass::LlmExternal, anthropic::API_URL)
                .map_err(denied)?;
            let key = std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| Error::Llm("ANTHROPIC_API_KEY is not set".into()))?;
            Ok(Arc::new(AnthropicProvider::new(key, http)))
        }
        LlmBackend::OpenAiCompat => {
            let base = base_url
                .map(|s| s.to_string())
                .unwrap_or_else(|| "http://localhost:11434/v1".to_string());
            let class = if garmr_core::is_local(garmr_core::host_of(&base).unwrap_or("")) {
                EgressClass::LlmLocal
            } else {
                EgressClass::LlmExternal
            };
            egress.check(class, &base).map_err(denied)?;
            let key = std::env::var("GARMR_OPENAI_API_KEY").ok();
            Ok(Arc::new(OpenAiCompatProvider::new(base, key, http)))
        }
    }
}

/// Build the default provider for a NON-triage surface (ask / hunt / rule
/// proposals) that carries a known data classification, enforcing the external
/// sensitivity ceiling (FIX#2). Refuses when the surface's classification exceeds
/// `EXTERNAL_CEILING` and `cfg.agent` would resolve to an EXTERNAL model — so
/// confidential operator-composed content can never reach a cloud model. Triage
/// routes per case through [`ModelRouter`] instead.
pub fn build_provider_for(
    cfg: &AgentConfig,
    class: garmr_core::DataClassification,
) -> Result<Arc<dyn LlmProvider>> {
    let entry = garmr_core::ModelEntry {
        name: "agent".into(),
        backend: cfg.backend,
        model: cfg.model.clone(),
        openai_base_url: cfg.openai_base_url.clone(),
        max_sensitivity: None,
        enabled: true,
        role: "agent".into(),
    };
    if class > garmr_core::EXTERNAL_CEILING && !entry.is_local() {
        return Err(Error::Llm(format!(
            "sensitivity policy: {} data may not be sent to an external model",
            class.as_str()
        )));
    }
    build_provider(cfg)
}

#[cfg(test)]
mod egress_tests {
    use super::*;
    use garmr_core::EgressPolicy;

    fn cfg(backend: &str, base: Option<&str>) -> AgentConfig {
        serde_json::from_value(serde_json::json!({
            "backend": backend,
            "model": "m",
            "openai_base_url": base,
        }))
        .unwrap()
    }

    fn assert_egress_denied(r: Result<Arc<dyn LlmProvider>>) {
        match r {
            Err(e) => assert!(
                e.to_string().contains("egress denied"),
                "expected an egress denial, got: {e}"
            ),
            Ok(_) => panic!("expected an egress denial, got a provider"),
        }
    }

    #[test]
    fn airgap_denies_the_external_anthropic_backend() {
        assert_egress_denied(build_provider_with(
            &cfg("anthropic", None),
            &EgressPolicy::airgap(),
        ));
    }

    #[test]
    fn airgap_allows_a_loopback_local_model() {
        // A loopback OpenAI-compat endpoint still builds under airgap (invariant #6).
        assert!(build_provider_with(
            &cfg("open_ai_compat", Some("http://127.0.0.1:11434/v1")),
            &EgressPolicy::airgap(),
        )
        .is_ok());
    }

    #[test]
    fn airgap_denies_an_external_openai_endpoint() {
        assert_egress_denied(build_provider_with(
            &cfg("open_ai_compat", Some("https://api.openai.com/v1")),
            &EgressPolicy::airgap(),
        ));
    }

    #[test]
    fn permissive_lets_anthropic_past_egress_to_the_key_check() {
        // Not an egress denial — it reaches the ANTHROPIC_API_KEY read (which may
        // fail if the key is unset, but NEVER with an egress error).
        if let Err(e) = build_provider_with(&cfg("anthropic", None), &EgressPolicy::permissive()) {
            assert!(!e.to_string().contains("egress denied"));
        }
    }
}
