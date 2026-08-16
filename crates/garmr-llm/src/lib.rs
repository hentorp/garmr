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
pub use provider::{DisabledProvider, LlmProvider};
pub use retry::LlmHttpConfig;

/// Operator-supplied prices, installed once at startup from `agent.pricing`.
/// Consulted before the built-in table so a deployment can price any endpoint.
static PRICING: std::sync::OnceLock<std::collections::BTreeMap<String, [f64; 2]>> =
    std::sync::OnceLock::new();

/// Install the configured price overlay. Idempotent-by-first-call (the process
/// has one agent config); a second call is ignored rather than racing.
pub fn set_pricing(pricing: std::collections::BTreeMap<String, [f64; 2]>) {
    let _ = PRICING.set(pricing);
}

/// USD per million tokens (input, output), or `None` when nothing prices this
/// model.
///
/// `None` is the load-bearing case: it means "we do not know what this costs",
/// which is NOT the same as free. [`price_per_mtok`] flattens it to zero for the
/// ledger's arithmetic, so [`ensure_priced`] must refuse an unpriced model on a
/// paid endpoint BEFORE any call is made — otherwise the budget silently bounds
/// nothing.
pub fn lookup_price(model: &str) -> Option<(f64, f64)> {
    resolve_price(model, PRICING.get())
}

/// The pure resolution, parameterized on the overlay so tests never touch the
/// process-global `OnceLock` (which one test could otherwise set for all of
/// them) — the same shape as `build_provider_with` for the egress policy.
fn resolve_price(
    model: &str,
    overlay: Option<&std::collections::BTreeMap<String, [f64; 2]>>,
) -> Option<(f64, f64)> {
    // Operator overlay first, longest key wins, so `gpt-4o-mini` can be priced
    // separately from the `gpt-4o` prefix it also matches.
    if let Some(map) = overlay {
        if let Some(p) = map.get(model) {
            return Some((p[0], p[1]));
        }
        if let Some((_, p)) = map
            .iter()
            .filter(|(k, _)| model.starts_with(k.as_str()))
            .max_by_key(|(k, _)| k.len())
        {
            return Some((p[0], p[1]));
        }
    }
    match model {
        m if m.starts_with("claude-opus") => Some((5.0, 25.0)),
        m if m.starts_with("claude-sonnet") => Some((3.0, 15.0)),
        m if m.starts_with("claude-haiku") => Some((1.0, 5.0)),
        m if m.starts_with("claude-fable") => Some((10.0, 50.0)),
        _ => None,
    }
}

/// Approximate USD-per-million-token prices (input, output) for the budget
/// ledger. An unpriced model yields `(0.0, 0.0)` — the ledger needs a number —
/// which is safe ONLY because [`ensure_priced`] has already refused to build a
/// provider for an unpriced model on a paid endpoint.
pub fn price_per_mtok(model: &str) -> (f64, f64) {
    lookup_price(model).unwrap_or((0.0, 0.0))
}

/// Refuse to run a paid endpoint whose model has no price.
///
/// Before this check, any model outside the built-in Claude table priced to
/// zero, so an OpenAI-compatible backend pointed at a PAID service (OpenAI,
/// Azure, Together, Groq, …) recorded $0 for every call and `daily_budget_usd`
/// bounded nothing at all — the operator believed they had a $5/day cap and had
/// none. Failing at startup is the whole point: an unmetered spend that only
/// shows up on an invoice is exactly the failure a budget exists to prevent.
///
/// A LOCAL endpoint (loopback/LAN — Ollama, llama.cpp, vLLM on the box) is
/// genuinely free, so an unpriced model there is fine and stays fine.
pub fn ensure_priced(cfg: &AgentConfig) -> Result<()> {
    ensure_priced_with(cfg, PRICING.get())
}

/// [`ensure_priced`] against an explicit overlay (see [`resolve_price`]).
fn ensure_priced_with(
    cfg: &AgentConfig,
    overlay: Option<&std::collections::BTreeMap<String, [f64; 2]>>,
) -> Result<()> {
    // The prefilter model spends from the same ledger, so it needs the same
    // guarantee: an unpriced prefilter on a paid endpoint would bill $0 per
    // call and quietly unbind the budget for the cheapest, highest-volume tier.
    let unpriced = std::iter::once(cfg.model.as_str())
        .chain(cfg.prefilter_model.as_deref())
        .find(|m| resolve_price(m, overlay).is_none());
    let Some(unpriced_model) = unpriced else {
        return Ok(());
    };
    let local = match cfg.backend {
        // Anthropic is never local; an unpriced Claude-family model means the
        // built-in table has fallen behind a new model name.
        LlmBackend::Anthropic => false,
        LlmBackend::OpenAiCompat => {
            let base = cfg
                .openai_base_url
                .clone()
                .unwrap_or_else(|| "http://localhost:11434/v1".to_string());
            garmr_core::is_local(garmr_core::host_of(&base).unwrap_or(""))
        }
    };
    if local {
        return Ok(());
    }
    Err(Error::Llm(format!(
        "no price is known for model {:?} on a non-local endpoint, so daily_budget_usd \
         cannot bound its spend. Set it under [agent.pricing] as USD per million tokens, \
         e.g. pricing = {{ {:?} = [2.5, 10.0] }} (input, output).",
        unpriced_model, unpriced_model
    )))
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
    // Egress FIRST: it is the security boundary, and a destination the policy
    // forbids must report as an egress denial whatever its price situation is —
    // there is no point discussing the cost of a call that may not leave the box.
    // The cost check then refuses a permitted-but-unmetered endpoint.
    let provider = build_backend_provider(
        cfg.backend,
        cfg.openai_base_url.as_deref(),
        egress,
        LlmHttpConfig::from_env(),
    )?;
    ensure_priced(cfg)?;
    Ok(provider)
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

#[cfg(test)]
mod pricing_tests {
    use super::*;

    fn cfg(backend: &str, model: &str, base: Option<&str>) -> AgentConfig {
        serde_json::from_value(serde_json::json!({
            "backend": backend,
            "model": model,
            "openai_base_url": base,
        }))
        .unwrap()
    }

    /// The tests drive the pure `_with` forms: the global overlay is a
    /// `OnceLock`, so one test setting it would silently decide the answers for
    /// every other test in the process.
    fn overlay(pairs: &[(&str, [f64; 2])]) -> std::collections::BTreeMap<String, [f64; 2]> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn the_builtin_table_prices_the_claude_family() {
        assert_eq!(resolve_price("claude-opus-5", None), Some((5.0, 25.0)));
        assert_eq!(
            resolve_price("claude-haiku-4-5-20251001", None),
            Some((1.0, 5.0))
        );
        // An unknown model is None — "we do not know", NOT "free".
        assert_eq!(resolve_price("gpt-4o", None), None);
    }

    #[test]
    fn an_unpriced_model_on_a_paid_endpoint_is_refused() {
        // The bug this closes: before pricing existed, this configuration
        // recorded $0 per call, so daily_budget_usd bounded nothing and the
        // operator learned the real number from an invoice.
        let err = ensure_priced_with(
            &cfg(
                "open_ai_compat",
                "gpt-4o",
                Some("https://api.openai.com/v1"),
            ),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no price is known"), "{err}");
        // The message must carry the fix, not just the complaint.
        assert!(err.contains("agent.pricing"), "{err}");
    }

    #[test]
    fn a_local_endpoint_stays_free_without_a_price() {
        // A model on the box costs nothing to call; requiring a price there
        // would be a tax on the airgap-friendly configuration garmr recommends.
        for base in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:8000/v1",
            "http://192.168.1.50:11434/v1",
        ] {
            assert!(
                ensure_priced_with(&cfg("open_ai_compat", "llama-3.3-70b", Some(base)), None)
                    .is_ok(),
                "{base} should not require a price"
            );
        }
        // Default base URL (unset) is loopback Ollama — also free.
        assert!(ensure_priced_with(&cfg("open_ai_compat", "qwen2.5", None), None).is_ok());
    }

    #[test]
    fn a_priced_model_passes_and_the_overlay_beats_the_builtin() {
        // Config-supplied pricing is what makes any paid endpoint usable.
        let map = overlay(&[("gpt-4o", [2.5, 10.0]), ("gpt-4o-mini", [0.15, 0.6])]);
        assert_eq!(resolve_price("gpt-4o", Some(&map)), Some((2.5, 10.0)));
        // Longest prefix wins, so the mini variant is not billed at the big
        // model's rate — an over-charge would be as wrong as an under-charge.
        assert_eq!(
            resolve_price("gpt-4o-mini-2026-01", Some(&map)),
            Some((0.15, 0.6))
        );
        assert!(ensure_priced_with(
            &cfg(
                "open_ai_compat",
                "gpt-4o",
                Some("https://api.openai.com/v1")
            ),
            Some(&map),
        )
        .is_ok());
    }

    #[test]
    fn an_unpriced_prefilter_model_is_refused_too() {
        // The prefilter is the CHEAPEST, HIGHEST-VOLUME tier — precisely where
        // a $0 price would quietly unbind the budget at the greatest scale. The
        // gate must name the offending model, not the main one.
        let mut c = cfg(
            "open_ai_compat",
            "claude-sonnet-5",
            Some("https://api.openai.com/v1"),
        );
        c.prefilter_model = Some("some-unpriced-mini".into());
        let overlay = [("claude-sonnet-5".to_string(), [3.0, 15.0])]
            .into_iter()
            .collect();
        let err = ensure_priced_with(&c, Some(&overlay))
            .unwrap_err()
            .to_string();
        assert!(err.contains("some-unpriced-mini"), "{err}");

        // Priced prefilter passes.
        let overlay = [
            ("claude-sonnet-5".to_string(), [3.0, 15.0]),
            ("some-unpriced-mini".to_string(), [0.1, 0.4]),
        ]
        .into_iter()
        .collect();
        assert!(ensure_priced_with(&c, Some(&overlay)).is_ok());
    }
}
