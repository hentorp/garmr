// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! An OpenAI-compatible chat-completions provider — Ollama, llama.cpp server,
//! vLLM, and anything else exposing `POST /v1/chat/completions` with the
//! `tools` / `tool_calls` shape. This is the offline / zero-cost / private tier
//! and the path the OSS community validates garmr on without an Anthropic key.

use async_trait::async_trait;
use garmr_core::{Error, Result};
use serde_json::{json, Value};

use crate::provider::LlmProvider;
use crate::retry::{send_with_retry, LlmHttpConfig};
use crate::types::{Block, LlmRequest, LlmResponse, Role, StopReason, ToolCall, Usage};

pub struct OpenAiCompatProvider {
    client: reqwest::Client,
    base_url: String,
    /// Optional bearer token (Ollama needs none; hosted endpoints may).
    api_key: Option<String>,
    http: LlmHttpConfig,
}

impl OpenAiCompatProvider {
    /// `base_url` is the root, e.g. `http://localhost:11434/v1`.
    pub fn new(base_url: impl Into<String>, api_key: Option<String>, http: LlmHttpConfig) -> Self {
        Self {
            // The client refuses redirects (a 3xx must not re-POST the possibly
            // confidential prompt to an un-egress-checked host, bypassing the
            // Phase-10 sensitivity fence #1/#6) AND bounds connect + request time.
            client: http.client(),
            base_url: base_url.into(),
            api_key,
            http,
        }
    }
}

/// Flatten neutral messages into OpenAI chat messages. Tool results become
/// `role: "tool"` messages; an assistant tool call becomes an assistant message
/// carrying `tool_calls`.
fn to_openai_messages(system: &str, messages: &[crate::types::Message]) -> Vec<Value> {
    let mut out = vec![json!({ "role": "system", "content": system })];
    for m in messages {
        match m.role {
            Role::User => {
                // A user turn is either plain text or tool results.
                let mut text = String::new();
                for b in &m.content {
                    match b {
                        Block::Text(t) => text.push_str(t),
                        Block::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } => {
                            out.push(json!({
                                "role": "tool",
                                "tool_call_id": tool_use_id,
                                "content": content,
                            }));
                        }
                        // No OpenAI equivalent for tool_use in a user turn, or
                        // for thinking blocks — skip.
                        Block::ToolUse { .. }
                        | Block::Thinking { .. }
                        | Block::RedactedThinking { .. } => {}
                    }
                }
                if !text.is_empty() {
                    out.push(json!({ "role": "user", "content": text }));
                }
            }
            Role::Assistant => {
                let mut text = String::new();
                let mut tool_calls = Vec::new();
                for b in &m.content {
                    match b {
                        Block::Text(t) => text.push_str(t),
                        Block::ToolUse { id, name, input } => tool_calls.push(json!({
                            "id": id,
                            "type": "function",
                            "function": { "name": name, "arguments": input.to_string() },
                        })),
                        // Thinking blocks and stray tool results have no place
                        // in an OpenAI assistant message — skip.
                        Block::ToolResult { .. }
                        | Block::Thinking { .. }
                        | Block::RedactedThinking { .. } => {}
                    }
                }
                // Emit null (not "") for a tool-call-only turn — strict
                // servers (vLLM/llama.cpp) reject an empty content string.
                let content = if text.is_empty() {
                    Value::Null
                } else {
                    Value::String(text)
                };
                let mut msg = json!({ "role": "assistant", "content": content });
                if !tool_calls.is_empty() {
                    msg["tool_calls"] = Value::Array(tool_calls);
                }
                out.push(msg);
            }
        }
    }
    out
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    async fn complete(&self, req: &LlmRequest) -> Result<LlmResponse> {
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                })
            })
            .collect();

        let body = json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": to_openai_messages(&req.system, &req.messages),
            "tools": tools,
        });

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut r = self
            .client
            .post(&url)
            .header("content-type", "application/json");
        if let Some(k) = &self.api_key {
            r = r.header("authorization", format!("Bearer {k}"));
        }
        let resp = send_with_retry(r.json(&body), self.http.max_retries, "openai-compat").await?;

        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .map_err(|e| Error::Llm(format!("openai-compat decode: {e}")))?;
        if !status.is_success() {
            return Err(Error::Llm(format!("openai-compat {status}: {v}")));
        }

        parse_response(&v)
    }
}

fn parse_response(v: &Value) -> Result<LlmResponse> {
    let choice = v
        .get("choices")
        .and_then(|c| c.get(0))
        .ok_or_else(|| Error::Llm("openai-compat: no choices".into()))?;
    let msg = choice.get("message").unwrap_or(&Value::Null);

    let text = msg
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut tool_calls = Vec::new();
    let mut assistant_blocks = Vec::new();
    if !text.is_empty() {
        assistant_blocks.push(Block::Text(text.clone()));
    }
    if let Some(calls) = msg.get("tool_calls").and_then(Value::as_array) {
        for c in calls {
            let id = c
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let f = c.get("function").unwrap_or(&Value::Null);
            let name = f
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            // Arguments arrive as a JSON string; parse to a value.
            let input = f
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(Value::Null);
            tool_calls.push(ToolCall {
                id: id.clone(),
                name: name.clone(),
                input: input.clone(),
            });
            assistant_blocks.push(Block::ToolUse { id, name, input });
        }
    }

    let finish = choice.get("finish_reason").and_then(Value::as_str);
    let stop_reason = if !tool_calls.is_empty() || finish == Some("tool_calls") {
        StopReason::ToolUse
    } else if finish == Some("length") {
        StopReason::MaxTokens
    } else {
        StopReason::EndTurn
    };

    let usage = v
        .get("usage")
        .map(|u| Usage {
            input_tokens: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
            output_tokens: u
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
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