// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-agent` — the agentic triage layer, garmr's reason for existing.
//!
//! A detection becomes a [`Case`](garmr_core::Case); [`Agent`] investigates it
//! with a bounded LLM tool-use loop over the read-only [`tools`], records an
//! audited [`Verdict`](garmr_core::Verdict), and escalates via [`notify`] to
//! Matrix. All state changes go through `garmr-store`; the daily budget ledger
//! and the capability boundary (agent proposes, never acts) are enforced here.

mod agent;
pub mod ask;
pub mod author;
mod baseline;
pub mod entity;
pub mod eval;
pub mod executor;
pub mod hunt;
pub mod injection;
mod mcp_client;
mod notify;
mod prompt;
mod sink;
mod tools;
mod validate;

pub use agent::{system_prompt_digest, toolset_digest, Agent, RegistryIdentities};
pub use ask::{ask, AskAnswer};
pub use author::{approve_proposal, propose_rule};
pub use eval::{run_eval, EvalReport, GoldenSet};
pub use executor::{Executor, Outcome};
pub use hunt::{findings_to_detections, load_hunts, run_hunt, HuntDef};
pub use mcp_client::McpClients;
pub use notify::Matrix;
pub use prompt::SYSTEM_PROMPT;
pub use sink::{AlertSink, EmailSink, Notification, Notifier, WebhookSink};
pub use tools::{format_batches, reject_non_readonly, tool_schemas, ToolBox};
pub use validate::validate_arg;
