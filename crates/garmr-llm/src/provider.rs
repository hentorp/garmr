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