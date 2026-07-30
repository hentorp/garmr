// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Provider-neutral request/response types.
//!
//! The agent builds these once; each provider adapts them to its wire format
//! (Anthropic `input_schema` vs OpenAI `parameters`, `tool_use` blocks vs
//! `tool_calls`, etc.). Keeping the neutral shape here means the agent's tool
//! loop is identical regardless of backend.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Conversation role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

/// A content block within a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Block {
    /// Plain text.
    Text(String),
    /// A tool call the model requested (assistant turns).
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    /// The result of executing a tool (user turns).
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
    /// An Anthropic extended-thinking block. Must be echoed back verbatim —
    /// text AND signature — on the next turn of the same conversation, or the
    /// Messages API rejects an assistant turn that leads with `tool_use`. The
    /// text may be empty (display: "omitted"); echo it anyway.
    Thinking { text: String, signature: String },
    /// A redacted-thinking block (opaque `data`); echoed back verbatim.
    RedactedThinking { data: String },
}

/// One conversation turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<Block>,
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Message {
            role: Role::User,
            content: vec![Block::Text(text.into())],
        }
    }
}

/// A provider-neutral tool declaration (JSON Schema for the input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    /// JSON Schema object for the tool's input.
    pub input_schema: Value,
}

/// A request to the LLM.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSchema>,
    pub max_tokens: u32,
}

/// A tool call parsed out of the model's response.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// Why the model stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The model wants to call one or more tools.
    ToolUse,
    /// The model finished its turn.
    EndTurn,
    /// The model declined the request.
    Refusal,
    /// Hit the output token cap.
    MaxTokens,
    /// Anything else the provider reported.
    Other,
}

/// Token usage for the budget ledger.
#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// A response from the LLM.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// Assistant text (may be empty when the turn is only tool calls).
    pub text: String,
    /// Tool calls the model requested.
    pub tool_calls: Vec<ToolCall>,
    /// The raw assistant content blocks, to echo back into history verbatim.
    pub assistant_blocks: Vec<Block>,
    pub stop_reason: StopReason,
    pub usage: Usage,
}
