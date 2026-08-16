// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The one trait every LLM backend implements.

use async_trait::async_trait;
use garmr_core::Result;

use crate::types::{LlmRequest, LlmResponse};

/// A pluggable LLM backend. The agent drives the tool loop; a provider is a
/// single stateless round-trip: request in, response out.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse>;
}

/// The provider for deployments whose LLM plane is deliberately off
/// (`daily_budget_usd = 0.0`) and whose backend credential is absent.
/// Construction touches nothing — no environment reads, no network — and every
/// call fails closed with the recorded reason. It exists so `serve` can start
/// in the paused-LLM mode: the agent's budget gate (`spent >= budget`, so 0.0
/// blocks the very first call) queues every case as NeedsHuman before any
/// `complete` is reached, and the non-triage surfaces (ask / hunts / rule
/// proposals) build their own provider per request and surface this same
/// error to the caller instead of taking the daemon down at boot.
pub struct DisabledProvider {
    reason: String,
}

impl DisabledProvider {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl LlmProvider for DisabledProvider {
    async fn complete(&self, _req: &LlmRequest) -> Result<LlmResponse> {
        Err(garmr_core::Error::Llm(format!(
            "llm plane disabled: {}",
            self.reason
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_provider_fails_closed_with_the_reason() {
        let p = DisabledProvider::new("ANTHROPIC_API_KEY is not set");
        let req = LlmRequest {
            model: "any".into(),
            system: String::new(),
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens: 1,
        };
        let err = p.complete(&req).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("disabled"), "got: {msg}");
        assert!(msg.contains("ANTHROPIC_API_KEY is not set"), "got: {msg}");
    }
}
