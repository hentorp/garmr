// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-core` — the shared vocabulary of garmr: the normalised [`Event`], a
//! [`Detection`], a [`Case`] and its [`Verdict`], and the [`Config`]. No I/O
//! lives here, so every other crate can depend on it without pulling a runtime.

mod action;
pub mod app_audit;
mod auth;
pub mod backup;
mod bundle;
mod case;
mod collector;
mod config;
mod dataset;
mod decision;
mod detection;
mod domain;
pub mod egress;
mod environment;
mod event;
pub mod explain;
mod finding;
mod hunt;
mod injection;
mod label;
mod lesson;
mod proposal;
mod registry;
mod retention;
mod router;
mod silence;

pub use action::{ActionEvent, ActionKind, ActionProposal, ActionState};
pub use app_audit::{
    ActorType, AuditAction, AuditActor, AuditClassification, AuditContext, AuditJustification,
    AuditRecord, Outcome, QueryType, AUDIT_LOG_TYPE,
};
pub use auth::{AuthRegistry, Principal, Role, UserToken};
pub use bundle::{
    canonical_manifest_body, diff_entries, is_safe_relative_path, manifest_digest, release_digest,
    verify_manifest_digest, verify_release_binding, BundleEntry, BundleEntryKind, BundleFinding,
    BundleManifest, ModelNote, SignedBundle, BUNDLE_FORMAT,
};
pub use case::{Case, CaseState, Disposition, TranscriptEntry, Verdict};
pub use collector::{Collector, CollectorRegistry};
pub use config::{
    AgentConfig, AuditConfig, ColdArchiverKind, Config, DetectConfig, EnvDetectConfig,
    EnvironmentConfig, ExecutorConfig, HaConfig, HaRole, IngestConfig, LlmBackend, MatrixConfig,
    McpServerConfig, RetentionConfig, RouteConfig, StoreConfig,
};
pub use dataset::*;
pub use decision::*;
pub use detection::Detection;
pub use domain::*;
pub use egress::{
    airgap_from_env, host_of, is_local, EgressAudit, EgressClass, EgressConfig, EgressDecision,
    EgressDenied, EgressPolicy,
};
pub use environment::*;
pub use event::Event;
pub use finding::*;
pub use hunt::{HuntFinding, HuntOutcome, HuntReport};
pub use injection::{scan_text, INJECTION_MARKERS};
pub use label::{intern, Label};
pub use lesson::{
    category_guidance, category_tag, validate_lesson_set, Lesson, LessonCaps, LessonFinding,
    LessonSet, LessonSetSpec, LESSON_CAPS,
};
pub use proposal::{Backtest, BacktestHealth, ProposalKind, ProposalStatus, RuleProposal};
pub use registry::*;
pub use retention::ColdArchive;
pub use router::{
    classify_event, decide, model_descriptor, model_descriptor_digest, DataClassification,
    ModelEntry, RouteDecision, RouteInput, RouterConfig, EXTERNAL_CEILING,
};
pub use silence::Silence;

/// The crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("storage error: {0}")]
    Store(String),
    #[error("ingest error: {0}")]
    Ingest(String),
    #[error("detection error: {0}")]
    Detect(String),
    #[error("llm error: {0}")]
    Llm(String),
    #[error("agent error: {0}")]
    Agent(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    pub fn store(msg: impl std::fmt::Display) -> Self {
        Error::Store(msg.to_string())
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
