// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The Anthropic Messages API provider — hand-rolled over `reqwest` + rustls.
//!
//! There is no official Anthropic Rust SDK, so this speaks the wire format
//! directly (the documented, current shape): `POST /v1/messages` with
//! `x-api-key` + `anthropic-version: 2023-06-01`, `tools` / `tool_use` /
//! `tool_result` blocks, and adaptive thinking. rustls keeps the shipped
//! binary free of a system OpenSSL dependency, matching the warehouse.

use async_trait::async_trait;
use garmr_core::{Error, Result};
use serde_json::{json, Value};

use crate::provider::LlmProvider;
use crate::retry::{send_with_retry, LlmHttpConfig};
use crate::types::{Block, LlmRequest, LlmResponse, Role, StopReason, ToolCall, Usage};

pub(crate) const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    http: LlmHttpConfig,
}

impl AnthropicProvider {
    pub fn new(api_key: impl Into<String>, http: LlmHttpConfig) -> Self {
        Self {
            // The client refuses redirects (a 3xx must not re-POST the possibly
            // confidential prompt to an un-egress-checked host, bypassing the
            // Phase-10 sensitivity fence #1/#6) AND bounds connect + request time.
            client: http.client(),
            api_key: api_key.into(),
            http,
        }
    }

    fn message_json(m: &crate::types::Message) -> Value {
        let role = match m.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        };
        let content: Vec<Value> = m.content.iter().map(block_to_json).collect();
        json!({ "role": role, "content": content })
    }
}

fn block_to_json(b: &Block) -> Value {
    match b {
        Block::Text(t) => json!({ "type": "text", "text": t }),
        Block::ToolUse { id, name, input } => {
            json!({ "type": "tool_use", "id": id, "name": name, "input": input })
        }
        Block::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => json!({
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": content,
            "is_error": is_error,
        }),
        Block::Thinking { text, signature } => {
            json!({ "type": "thinking", "thinking": text, "signature": signature })
        }
        Block::RedactedThinking { data } => json!({ "type": "redacted_thinking", "data": data }),
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| json!({ "name": t.name, "description": t.description, "input_schema": t.input_schema }))
            .collect();
        let messages: Vec<Value> = req
            .messages
            .iter()
            .map(AnthropicProvider::message_json)
            .collect();

        let body = json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "system": req.system,
            "thinking": { "type": "adaptive" },
            "tools": tools,
            "messages": messages,
        });

        let req = self
            .client
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&body);
        let resp = send_with_retry(req, self.http.max_retries, "anthropic").await?;

        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .map_err(|e| Error::Llm(format!("anthropic decode: {e}")))?;
        if !status.is_success() {
            return Err(Error::Llm(format!("anthropic {status}: {v}")));
        }

        parse_response(&v)
    }
}

fn parse_response(v: &Value) -> Result<LlmResponse> {
    let stop_reason = match v.get("stop_reason").and_then(Value::as_str) {
        Some("tool_use") => StopReason::ToolUse,
        Some("end_turn") => StopReason::EndTurn,
        Some("refusal") => StopReason::Refusal,
        Some("max_tokens") => StopReason::MaxTokens,
        _ => StopReason::Other,
    };

    let mut text = String::new();
    let mut tool_calls = Vec::new();
    let mut assistant_blocks = Vec::new();

    if let Some(blocks) = v.get("content").and_then(Value::as_array) {
        for b in blocks {
            match b.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = b.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(t);
                        assistant_blocks.push(Block::Text(t.to_string()));
                    }
                }
                Some("tool_use") => {
                    let id = b
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let name = b
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let input = b.get("input").cloned().unwrap_or(Value::Null);
                    tool_calls.push(ToolCall {
                        id: id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                    });
                    assistant_blocks.push(Block::ToolUse { id, name, input });
                }
                // Thinking blocks MUST be captured and echoed back verbatim on
                // the next turn, or the API rejects an assistant turn that
                // leads with tool_use. Preserve text + signature exactly (text
                // is empty under display:"omitted" — echo it anyway).
                Some("thinking") => assistant_blocks.push(Block::Thinking {
                    text: b
                        .get("thinking")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    signature: b
                        .get("signature")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                }),
                Some("redacted_thinking") => assistant_blocks.push(Block::RedactedThinking {
                    data: b
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                }),
                _ => {}
            }
        }
    }

    let usage = v
        .get("usage")
        .map(|u| Usage {
            input_tokens: u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0),
            output_tokens: u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
        })
        .unwrap_or_default();

    Ok(LlmResponse {
        text,
        tool_calls,
        assistant_blocks,
        stop_reason,
        usage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The critical regression: a turn-1 response with a thinking block ahead
    /// of a tool_use must be captured (thinking first, verbatim with signature)
    /// and re-serialize to the exact wire shape, so echoing `assistant_blocks`
    /// on turn 2 doesn't produce an assistant turn that leads with tool_use
    /// (which the Messages API rejects with a 400).
    #[test]
    fn thinking_block_round_trips_before_tool_use() {
        let resp = json!({
            "stop_reason": "tool_use",
            "content": [
                {"type": "thinking", "thinking": "let me check the logs", "signature": "sig-abc"},
                {"type": "tool_use", "id": "toolu_1", "name": "query_events", "input": {"sql": "SELECT 1"}}
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let parsed = parse_response(&resp).unwrap();
        assert_eq!(parsed.stop_reason, StopReason::ToolUse);
        // Thinking captured FIRST, then the tool_use — order preserved.
        assert!(matches!(parsed.assistant_blocks[0], Block::Thinking { .. }));
        assert!(matches!(parsed.assistant_blocks[1], Block::ToolUse { .. }));

        // The thinking block re-serializes to the exact wire shape (text + signature).
        let wire = block_to_json(&parsed.assistant_blocks[0]);
        assert_eq!(wire["type"], "thinking");
        assert_eq!(wire["thinking"], "let me check the logs");
        assert_eq!(wire["signature"], "sig-abc");

        assert_eq!(parsed.tool_calls.len(), 1);
        assert_eq!(parsed.usage.input_tokens, 10);
    }

    #[test]
    fn refusal_and_max_tokens_mapped() {
        let refusal = json!({"stop_reason": "refusal", "content": []});
        assert_eq!(
            parse_response(&refusal).unwrap().stop_reason,
            StopReason::Refusal
        );
        let maxed = json!({"stop_reason": "max_tokens", "content": [{"type":"text","text":"..."}]});
        assert_eq!(
            parse_response(&maxed).unwrap().stop_reason,
            StopReason::MaxTokens
        );
    }
}