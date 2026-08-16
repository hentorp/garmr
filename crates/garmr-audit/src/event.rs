// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The audit envelope and its value types.
//!
//! [`AuditRecord`] is the on-disk envelope. Callers build one with the fluent
//! constructor ([`AuditRecord::new`] + setters) and hand it to the ledger, which
//! stamps the fields it owns (sequence, hashes, signature, node/process id,
//! `recorded_at`, `audit_id`) on append. The stamped fields are left empty by the
//! builder; the ledger fills them (see `ledger.rs`).
//!
//! Hashing and signing operate over a deterministic canonical encoding of this
//! envelope (see `canonical.rs`), never over its JSON serialization — JSON map
//! order, whitespace, and number formatting are not stable enough to hash.

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte BLAKE3 digest. Serializes as a lowercase hex string.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The all-zero digest — the `previous_hash` of the genesis record.
    pub const ZERO: Digest = Digest([0u8; 32]);

    /// Hex encoding (64 lowercase chars).
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-char hex string.
    pub fn from_hex(s: &str) -> Result<Digest, String> {
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "digest must be 32 bytes".to_string())?;
        Ok(Digest(arr))
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::from_hex(&s).map_err(D::Error::custom)
    }
}

/// A detached signature (ed25519 = 64 bytes). Serializes as lowercase hex.
#[derive(Clone, PartialEq, Eq)]
pub struct Sig(pub Vec<u8>);

impl Sig {
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn from_hex(s: &str) -> Result<Sig, String> {
        Ok(Sig(hex::decode(s).map_err(|e| e.to_string())?))
    }
}

impl std::fmt::Debug for Sig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sig({}…)", &self.to_hex()[..self.0.len().min(8) * 2])
    }
}

impl Serialize for Sig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Sig::from_hex(&s).map_err(D::Error::custom)
    }
}

/// Who performed the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A human principal (analyst/operator) via an authenticated session.
    Human,
    /// The LLM triage/hunt agent (read-only; can only propose).
    Agent,
    /// The response executor (the only code that changes external state).
    Executor,
    /// An internal automatic process (ingest, detection, retention).
    System,
    /// A log collector / data source.
    Collector,
    /// An external service (e.g. an MCP server).
    Service,
    /// Provenance not established.
    Unknown,
}

/// The result of the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    /// Refused by authorization or policy.
    Denied,
    /// Failed with an internal error.
    Error,
    /// Recorded intent; the effect has not completed (outbox pattern).
    Pending,
}

/// The policy verdict for the action (egress, RBAC, ABAC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allowed,
    Denied,
    NotApplicable,
}

/// Data-handling classification of the object touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    Secret,
}

/// How much record content the ledger persists (invariant: default is
/// digest-only + immutable evidence references, never raw sensitive content).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentMode {
    /// No content field at all.
    Off,
    /// Only digests + evidence refs (default).
    #[default]
    DigestOnly,
    /// A redaction-profile-filtered copy of the content.
    Redacted,
    /// Ciphertext (operator-held key); integrity still covers it.
    Encrypted,
    /// Full plaintext content (opt-in, per policy).
    Full,
}

/// Stable action identifiers. Free-form strings (open vocabulary across phases),
/// but the common ones are named here so call sites do not drift.
pub mod action {
    pub const AUTH_LOGIN: &str = "auth.login";
    pub const AUTH_LOGIN_FAILED: &str = "auth.login_failed";
    pub const AUTH_LOGOUT: &str = "auth.logout";
    pub const PASSKEY_REGISTER: &str = "auth.passkey_register";
    pub const PASSKEY_REVOKE: &str = "auth.passkey_revoke";
    pub const PASSKEY_RENAME: &str = "auth.passkey_rename";
    pub const SESSION_REVOKE_ALL: &str = "auth.session_revoke_all";
    pub const CREDENTIAL_ISSUE: &str = "auth.credential_issue";
    pub const CREDENTIAL_ROTATE: &str = "auth.credential_rotate";
    pub const CREDENTIAL_REVOKE: &str = "auth.credential_revoke";
    pub const SECRET_SET: &str = "secret.set";
    pub const SECRET_ROTATE: &str = "secret.rotate";
    pub const SECRET_REMOVE: &str = "secret.remove";
    pub const CONFIG_APPLY: &str = "config.apply";
    pub const CONFIG_ROLLBACK: &str = "config.rollback";
    pub const RECOVERY_ADMIN: &str = "recovery.admin_issued";
    pub const AUTHZ_DENIED: &str = "authz.denied";
    pub const QUERY: &str = "data.query";
    pub const SEARCH_SENSITIVE: &str = "data.search_sensitive";
    pub const EXPORT: &str = "data.export";
    /// A cold archive was deleted by a retention run. Deliberately its own
    /// action rather than a generic delete: this is the one operation that
    /// destroys evidence, so it must be greppable in the ledger on its own, and
    /// an auditor asking "what was erased, when, and under which policy" needs
    /// to find it without knowing what else shares a name.
    pub const RETENTION_EXPIRE: &str = "retention.expire";
    /// A legal hold was placed on or cleared from a cold archive.
    pub const RETENTION_LEGAL_HOLD: &str = "retention.legal_hold";
    /// A targeted erasure was executed: a persistent tombstone placed and the
    /// matching rows removed. Its own action for the same reason as
    /// RETENTION_EXPIRE — destroying data must be findable on its own, and
    /// "prove what you erased" starts from this record.
    pub const DATA_ERASE: &str = "data.erase";
    /// Case ownership changed (assign/unassign).
    pub const CASE_ASSIGN: &str = "case.assign";
    /// An analyst note was added to a case transcript.
    pub const CASE_COMMENT: &str = "case.comment";
    /// Case tags changed.
    pub const CASE_TAG: &str = "case.tag";
    /// Two cases were linked.
    pub const CASE_LINK: &str = "case.link";
    pub const RULE_PROPOSE: &str = "rule.propose";
    pub const RULE_DECIDE: &str = "rule.decide";
    pub const THRESHOLD_PROPOSE: &str = "threshold.propose";
    pub const THRESHOLD_DECIDE: &str = "threshold.decide";
    pub const PROMPT_PROPOSE: &str = "prompt.propose";
    pub const PROMPT_DECIDE: &str = "prompt.decide";
    pub const MODEL_REGISTER: &str = "model.register";
    pub const MODEL_PROMOTE: &str = "model.promote";
    // Phase 4 registries — the remaining kinds (model/prompt/rule/threshold/
    // dataset/eval consts already exist above).
    pub const TOOLSET_REGISTER: &str = "toolset.register";
    pub const TOOLSET_PROMOTE: &str = "toolset.promote";
    pub const DATASET_PROMOTE: &str = "dataset.promote";
    pub const RELEASE_REGISTER: &str = "release.register";
    pub const RELEASE_PROMOTE: &str = "release.promote";
    pub const FEATURE_REGISTER: &str = "feature.register";
    pub const FEATURE_PROMOTE: &str = "feature.promote";
    // Phase A: the governed application-audit catalog domains, registered +
    // promoted through the versioned registry like any other artifact.
    pub const POLICY_REGISTER: &str = "policy.register";
    pub const POLICY_PROMOTE: &str = "policy.promote";
    pub const CATALOG_REGISTER: &str = "catalog.register";
    pub const CATALOG_PROMOTE: &str = "catalog.promote";
    pub const APPLICATION_REGISTER: &str = "application.register";
    pub const APPLICATION_PROMOTE: &str = "application.promote";
    pub const RESOURCE_REGISTER: &str = "resource.register";
    pub const RESOURCE_PROMOTE: &str = "resource.promote";
    pub const MONITORING_REGISTER: &str = "monitoring.register";
    pub const MONITORING_PROMOTE: &str = "monitoring.promote";
    /// Hot-reload of the enforced app-audit config (policies/catalog/monitoring).
    pub const CONFIG_RELOAD: &str = "appaudit.config_reload";
    pub const FEEDBACK: &str = "feedback.record";
    /// An immutable agent prediction was recorded (Phase 3).
    pub const PREDICTION: &str = "prediction.record";
    /// A human analyst decision was recorded (Phase 3).
    pub const DECISION: &str = "decision.record";
    /// A post-incident outcome was recorded (Phase 3).
    pub const OUTCOME: &str = "incident.outcome";
    /// A false negative was registered from a post-incident review (Phase 3).
    pub const FALSE_NEGATIVE: &str = "feedback.false_negative";
    /// An agent mistake was recorded for offline reflection (Phase 3/9).
    pub const MISTAKE: &str = "mistake.record";
    pub const DATASET_CREATE: &str = "dataset.create";
    pub const TRAIN_RUN: &str = "learning.train";
    pub const EVAL_RUN: &str = "learning.eval";
    /// An ingest request presented an unrecognized collector token (Phase 12,
    /// rate-limited/aggregated — never one row per failed request).
    pub const INGEST_AUTH_DENIED: &str = "ingest.auth_denied";
    /// An AUTHENTICATED collector asserted a source outside its allowlist — the
    /// source-spoofing attempt Phase 12 defends against. Distinct from
    /// [`INGEST_AUTH_DENIED`] and separately rate-limited, so it is never
    /// mislabeled as unauthenticated nor suppressed by bad-token flooding.
    pub const INGEST_SOURCE_DENIED: &str = "ingest.source_denied";
    /// A per-collector sequence gap was confirmed (Phase 12, windowed/aggregated).
    pub const INGEST_SEQ_ANOMALY: &str = "ingest.seq_anomaly";
    /// A reflection job drafted a Draft procedural-memory LessonSet (Phase 9).
    pub const LESSON_PROPOSE: &str = "lesson.propose";
    /// An approved LessonSet was promoted/rolled back on a channel (Phase 9).
    pub const LESSON_PROMOTE: &str = "lesson.promote";
    pub const ACTION_PROPOSE: &str = "response.propose";
    pub const ACTION_DECIDE: &str = "response.decide";
    pub const ACTION_EXECUTE: &str = "response.execute";
    pub const SILENCE: &str = "alert.silence";
    pub const CONFIG_CHANGE: &str = "config.change";
    pub const BUNDLE_IMPORT: &str = "bundle.import";
    pub const BACKUP: &str = "ha.backup";
    pub const RESTORE: &str = "ha.restore";
    pub const HA_PROMOTE: &str = "ha.promote";
    pub const MCP_REGISTER: &str = "mcp.register";
    pub const MCP_CALL: &str = "mcp.call";
    pub const EGRESS_DECISION: &str = "egress.decision";
    pub const AUDIT_VERIFY_FAILED: &str = "audit.verify_failed";
    // --- Phase 5: the temporal environment model ---
    /// A candidate observation was learned from the event stream (best-effort).
    pub const ENV_OBSERVE: &str = "env.observe";
    /// A fact was promoted to Trusted (fail-closed).
    pub const ENV_PROMOTE: &str = "env.promote";
    /// An analyst approved a high-impact fact's promotion (fail-closed).
    pub const ENV_APPROVE: &str = "env.approve";
    /// A fact was demoted to Suspicious/KnownMalicious (fail-closed).
    pub const ENV_DEMOTE: &str = "env.demote";
    /// A fact was retired (fail-closed).
    pub const ENV_RETIRE: &str = "env.retire";
    /// A batch of asserted facts was imported from an inventory file.
    pub const ENV_IMPORT: &str = "env.import";
    /// A maintenance/change window was recorded (excuses quarantine within it).
    pub const ENV_CHANGE_WINDOW: &str = "env.change_window";
    /// A promotion attempt was refused by an inviolable anti-poisoning block.
    pub const ENV_PROMOTE_DENIED: &str = "env.promote_denied";
    /// A security finding was recorded by the detection ensemble (Phase 7).
    pub const FINDING: &str = "finding.record";
    // --- Phase 7/8: application-audit behavioral baselines ---
    /// An entity's behavioral baseline was promoted to Trusted (fail-closed).
    pub const BASELINE_PROMOTE: &str = "baseline.promote";
    /// A baseline promotion was refused by a hard block (best-effort audited).
    pub const BASELINE_PROMOTE_DENIED: &str = "baseline.promote_denied";
    /// A behavioral baseline was marked Suspicious (fail-closed).
    pub const BASELINE_SUSPECT: &str = "baseline.suspect";
    /// A Suspicious baseline was cleared for re-learning after review (fail-closed).
    pub const BASELINE_CLEAR: &str = "baseline.clear";
}

/// The audit envelope. Caller-set fields are filled via the builder; the fields
/// the ledger owns are stamped on `append` and are left at their empty defaults
/// by the builder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    // ---- ledger-stamped identity/ordering ----
    pub audit_id: String,
    pub global_sequence: u64,
    pub occurred_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub node_id: String,
    pub process_id: String,

    // ---- actor ----
    pub actor_type: ActorType,
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_method: Option<String>,

    // ---- what happened ----
    pub action: String,
    pub object_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    // ---- correlation ----
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub policy_decision: PolicyDecision,

    // ---- content digests (never raw content by default) ----
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_digest: Option<Digest>,

    // ---- immutable references into the data plane ----
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub case_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolset_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_ref: Option<String>,

    // ---- classification ----
    pub data_classification: DataClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile: Option<String>,
    pub content_mode: ContentMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    // ---- integrity (stamped) ----
    pub previous_hash: Digest,
    pub record_hash: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Sig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
}

impl AuditRecord {
    /// Start a new record for `action` on an object of `object_type`. Timestamps
    /// default to now; identity/ordering/integrity fields stay empty until the
    /// ledger stamps them.
    pub fn new(action: impl Into<String>, object_type: impl Into<String>) -> Self {
        let now = Utc::now();
        AuditRecord {
            audit_id: String::new(),
            global_sequence: 0,
            occurred_at: now,
            recorded_at: now,
            node_id: String::new(),
            process_id: String::new(),
            actor_type: ActorType::System,
            actor_id: String::new(),
            actor_role: None,
            authentication_method: None,
            action: action.into(),
            object_type: object_type.into(),
            object_id: None,
            outcome: Outcome::Success,
            reason: None,
            correlation_id: None,
            causation_id: None,
            trace_id: None,
            policy_decision: PolicyDecision::NotApplicable,
            input_digest: None,
            output_digest: None,
            before_digest: None,
            after_digest: None,
            evidence_refs: Vec::new(),
            event_refs: Vec::new(),
            case_refs: Vec::new(),
            query_ref: None,
            model_ref: None,
            prompt_ref: None,
            toolset_ref: None,
            detector_ref: None,
            parser_ref: None,
            data_classification: DataClassification::Internal,
            redaction_profile: None,
            content_mode: ContentMode::DigestOnly,
            content: None,
            previous_hash: Digest::ZERO,
            record_hash: Digest::ZERO,
            signature: None,
            signing_key_id: None,
        }
    }

    /// Set the actor (type, id, and optional role).
    pub fn actor(
        mut self,
        actor_type: ActorType,
        actor_id: impl Into<String>,
        role: Option<&str>,
    ) -> Self {
        self.actor_type = actor_type;
        self.actor_id = actor_id.into();
        self.actor_role = role.map(str::to_string);
        self
    }

    /// Set the authentication method (e.g. `passkey`, `bearer_token`).
    pub fn auth_method(mut self, m: impl Into<String>) -> Self {
        self.authentication_method = Some(m.into());
        self
    }

    /// Set the object id (the specific thing acted on).
    pub fn object_id(mut self, id: impl Into<String>) -> Self {
        self.object_id = Some(id.into());
        self
    }

    /// Set the outcome.
    pub fn outcome(mut self, o: Outcome) -> Self {
        self.outcome = o;
        self
    }

    /// Set a human-readable reason/justification.
    pub fn reason(mut self, r: impl Into<String>) -> Self {
        self.reason = Some(r.into());
        self
    }

    /// Set the policy decision.
    pub fn policy(mut self, d: PolicyDecision) -> Self {
        self.policy_decision = d;
        self
    }

    /// Set the data classification.
    pub fn classification(mut self, c: DataClassification) -> Self {
        self.data_classification = c;
        self
    }

    /// Set the correlation id (groups related actions).
    pub fn correlation(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the causation id (the action that caused this one).
    pub fn causation(mut self, id: impl Into<String>) -> Self {
        self.causation_id = Some(id.into());
        self
    }

    /// Attach case references.
    pub fn cases(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.case_refs = refs.into_iter().collect();
        self
    }

    /// Attach event references.
    pub fn events(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.event_refs = refs.into_iter().collect();
        self
    }

    /// Attach evidence references.
    pub fn evidence(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.evidence_refs = refs.into_iter().collect();
        self
    }

    /// Reference a versioned model artifact.
    pub fn model(mut self, r: impl Into<String>) -> Self {
        self.model_ref = Some(r.into());
        self
    }

    /// Reference a versioned prompt.
    pub fn prompt(mut self, r: impl Into<String>) -> Self {
        self.prompt_ref = Some(r.into());
        self
    }

    /// Reference a versioned toolset.
    pub fn toolset(mut self, r: impl Into<String>) -> Self {
        self.toolset_ref = Some(r.into());
        self
    }

    /// Reference a versioned detector.
    pub fn detector(mut self, r: impl Into<String>) -> Self {
        self.detector_ref = Some(r.into());
        self
    }

    /// Reference a versioned parser.
    pub fn parser(mut self, r: impl Into<String>) -> Self {
        self.parser_ref = Some(r.into());
        self
    }

    /// Reference a stored query.
    pub fn query(mut self, r: impl Into<String>) -> Self {
        self.query_ref = Some(r.into());
        self
    }

    /// Set the input digest (of a request/prompt/argument).
    pub fn input_digest(mut self, d: Digest) -> Self {
        self.input_digest = Some(d);
        self
    }

    /// Set the output digest (of a response/answer).
    pub fn output_digest(mut self, d: Digest) -> Self {
        self.output_digest = Some(d);
        self
    }

    /// Set the before/after digests (of a changed object).
    pub fn change_digests(mut self, before: Option<Digest>, after: Option<Digest>) -> Self {
        self.before_digest = before;
        self.after_digest = after;
        self
    }

    /// Attach raw/redacted/encrypted content. The ledger applies the configured
    /// [`ContentMode`] on append, so this is dropped in digest-only mode.
    pub fn content(mut self, c: impl Into<String>) -> Self {
        self.content = Some(c.into());
        self
    }

    /// Override the occurrence time (defaults to now).
    pub fn occurred_at(mut self, t: DateTime<Utc>) -> Self {
        self.occurred_at = t;
        self
    }
}

/// Convenience: the BLAKE3 digest of arbitrary bytes, for `*_digest` fields.
pub fn digest_of(bytes: &[u8]) -> Digest {
    Digest(*blake3::hash(bytes).as_bytes())
}
