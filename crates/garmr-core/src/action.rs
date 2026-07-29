// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Response actions — the propose≠act boundary, made executable (M3's SOAR).
//!
//! This is the ONLY part of garmr that can change system state, and it is
//! built so the agent never holds that capability. The agent (read-only)
//! writes an [`ActionProposal`] in state `Proposed`; a HUMAN moves it to
//! `Approved` (an authenticated, out-of-band action — admin bearer or the
//! local CLI, never chat text the agent can forge); a SEPARATE executor
//! process re-validates it independently and only then acts, recording
//! `Executed`/`Failed`. Compromising the agent (prompt injection in a log
//! line) can at most write a proposal — the same thing a malicious log line
//! could already trick it into suggesting in prose.
//!
//! Safety invariants (enforced in `garmr-agent::executor`, tested there):
//! - **Allowlist.** Only [`ActionKind`] variants are representable, and each
//!   has a strict argument validator.
//! - **Reversibility bias.** Only reversible, well-bounded actions exist here.
//!   An irreversible action is never added to this enum.
//! - **Independent re-validation.** The executor re-checks the argument shape
//!   AND that the linked evidence (the case) still supports the action, before
//!   acting — it never trusts the stored proposal blindly.
//! - **No built-in capability.** garmr ships no firewall/service-control code.
//!   The executor runs an operator-configured command template; with none set
//!   it REFUSES and records the exact manual command for the human to run.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The allowlisted action types. Adding a variant is a deliberate security
/// decision: it must be reversible and have a strict validator + a documented
/// rollback. Irreversible actions (delete, rotate, wipe) are never added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Block a single source IP at the network edge. Reversible (unblock).
    /// Argument: one public, non-loopback IP address.
    BlockIp,
    /// Isolate a host from the network (e.g. quarantine VLAN). Reversible.
    /// Argument: a host name known to the event store.
    IsolateHost,
}

impl ActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionKind::BlockIp => "block_ip",
            ActionKind::IsolateHost => "isolate_host",
        }
    }

    /// The rollback the operator would run to undo this (documented, not
    /// executed here) — surfaced in the proposal for the reviewing human.
    pub fn reversal_hint(&self) -> &'static str {
        match self {
            ActionKind::BlockIp => "unblock the IP (e.g. remove the ipset/nft rule)",
            ActionKind::IsolateHost => "restore the host's network VLAN",
        }
    }
}

/// Lifecycle of an action proposal. Terminal states (`Denied`, `Executed`,
/// `Failed`) are immutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    /// Written by the agent; awaiting a human decision.
    Proposed,
    /// A human approved it; awaiting the executor.
    Approved,
    /// A human denied it (before OR after approval — an approval made in error
    /// can be recalled while still `Approved`). Terminal.
    Denied,
    /// The executor has CLAIMED it and is about to run the command. Persisted
    /// BEFORE the side effect, so a crash mid-command leaves the action here —
    /// never silently re-run — for a human to reconcile. Not terminal, but the
    /// executor never re-picks it (it polls `Approved` only).
    Executing,
    /// The executor performed it. Terminal.
    Executed,
    /// The executor tried and failed, or refused (re-validation, no capability
    /// configured, irreversible). Terminal — a new proposal is required.
    Failed,
}

/// One state transition, for the immutable audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvent {
    pub at: DateTime<Utc>,
    /// Who/what: `agent`, `human`, `executor`.
    pub actor: String,
    pub detail: String,
}

/// A proposed response action with its full audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    pub id: String,
    pub kind: ActionKind,
    /// The validated argument (an IP for block_ip, a host for isolate_host).
    pub arg: String,
    /// The case whose evidence motivates this action — the executor re-checks
    /// that this case still exists and still supports acting.
    pub case_id: String,
    /// The agent's grounded rationale.
    pub rationale: String,
    pub state: ActionState,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub executed_at: Option<DateTime<Utc>>,
    /// Executor output (stdout/stderr summary) or refusal reason.
    #[serde(default)]
    pub result: Option<String>,
    /// The immutable transition log.
    pub audit: Vec<ActionEvent>,
}

impl ActionProposal {
    pub fn record(&mut self, actor: &str, detail: impl Into<String>, at: DateTime<Utc>) {
        self.audit.push(ActionEvent {
            at,
            actor: actor.into(),
            detail: detail.into(),
        });
    }
}