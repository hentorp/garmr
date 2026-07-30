// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 1 — the canonical, domain-neutral **application audit** record.
//!
//! [`AuditRecord`] is the first-class, typed model of a single application-audit
//! event: who did what, to which resource, under which justification, and how
//! sensitive it was. It is the audit-first successor to the narrower
//! [`crate::AccessProjection`] — where that view carries six fields for the
//! register flagship, this carries the full actor / application-context / action
//! / justification / security-classification vocabulary the platform reasons
//! over (policy, baselines, detectors, search).
//!
//! ## It is a LENS, not a second event type
//!
//! garmr keeps ONE stored event ([`Event`]) — a thin log line plus a
//! `fields: BTreeMap` of ingest-normalized keys. [`AuditRecord::from_event`]
//! reads those already-canonical keys DIRECTLY; it performs no alias folding of
//! its own (that is `garmr-ingest`'s single job, exactly as documented on
//! [`AccessProjection`]). A pgAudit/Postgres adapter (Phase 2) populates the
//! same keys, so the typed model and the raw store never diverge.
//!
//! ## Backward compatibility is a hard requirement
//!
//! The register/access-audit capability already shipped keys its whole pipeline
//! (the `correlations/reg-*.toml` SQL over the `fields` JSON column, per-actor
//! RBA, the staff/person entity pivots, the Matrix/webhook alert bodies) off a
//! fixed vocabulary: `db_user`, `target_person`, `object_table`, `action`,
//! `statement`, `ticket_ref`, `client_addr`, `watched`, `is_self`. Those remain
//! the STORAGE canonical keys ([`keys`]). [`AuditRecord::to_fields`] writes them,
//! and [`AuditRecord::from_event`] reads them (plus the newer, richer keys and a
//! generous alias set), so nothing downstream breaks and
//! [`AccessProjection::from_event`] keeps yielding an identical view.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Event;

/// The storage-canonical field keys an [`AuditRecord`] reads and writes. These
/// are the keys `garmr-ingest` folds source aliases onto and that the correlation
/// SQL / RBA / entity pivots already depend on — never rename the legacy ones.
pub mod keys {
    // --- legacy canonical keys (the access-audit vocabulary; DO NOT rename) ---
    /// The actor / acting principal ("who").
    pub const ACTOR: &str = "db_user";
    /// The data subject accessed ("whom") — an opaque id.
    pub const SUBJECT: &str = "target_person";
    /// The kind/class of object accessed (a table, collection, resource type).
    pub const OBJECT_TYPE: &str = "object_table";
    /// The operation verb.
    pub const ACTION: &str = "action";
    /// The full statement / SQL text.
    pub const STATEMENT: &str = "statement";
    /// The stated justification (ticket / case / purpose reference).
    pub const TICKET: &str = "ticket_ref";
    /// The client origin (host or address; deliberately not IP-guarded).
    pub const CLIENT: &str = "client_addr";
    /// App flag: the subject is watchlisted.
    pub const WATCHED: &str = "watched";
    /// App flag: the actor accessed their own record.
    pub const IS_SELF: &str = "is_self";

    // --- richer canonical keys introduced by the audit-first model (Phase 1) ---
    pub const ACTOR_NAME: &str = "actor_name";
    pub const ACTOR_TYPE: &str = "actor_type";
    pub const ACTOR_ROLE: &str = "actor_role";
    pub const ACTOR_GROUPS: &str = "actor_groups";
    pub const SERVICE_ACCOUNT: &str = "service_account";
    pub const AUTHENTICATED_IDENTITY: &str = "authenticated_identity";
    pub const EFFECTIVE_IDENTITY: &str = "effective_identity";
    pub const DELEGATED_IDENTITY: &str = "delegated_identity";
    pub const IMPERSONATED_IDENTITY: &str = "impersonated_identity";

    pub const APPLICATION_ID: &str = "application_id";
    pub const APPLICATION_NAME: &str = "application_name";
    pub const APPLICATION_INSTANCE: &str = "application_instance";
    pub const SITE: &str = "site";
    pub const SECURITY_ZONE: &str = "security_zone";
    pub const TENANT: &str = "tenant";
    pub const DATABASE: &str = "database";
    pub const DATABASE_SCHEMA: &str = "database_schema";
    pub const CLIENT_HOST: &str = "client_host";
    pub const CLIENT_IP: &str = "client_ip";
    pub const CLIENT_APPLICATION: &str = "client_application";
    pub const SESSION_ID: &str = "session_id";
    pub const TRANSACTION_ID: &str = "transaction_id";
    pub const REQUEST_ID: &str = "request_id";
    pub const TRACE_ID: &str = "trace_id";

    pub const OPERATION: &str = "operation";
    pub const OUTCOME: &str = "outcome";
    pub const ERROR_CODE: &str = "error_code";
    pub const OBJECT_NAME: &str = "object_name";
    pub const RESOURCE_PATH: &str = "resource_path";
    pub const RECORD_ID: &str = "record_id";
    pub const SUBJECT_TYPE: &str = "subject_type";
    pub const STATEMENT_FINGERPRINT: &str = "statement_fingerprint";
    pub const QUERY_TYPE: &str = "query_type";
    pub const ROWS_READ: &str = "rows_read";
    pub const ROWS_WRITTEN: &str = "rows_written";
    pub const BYTES_READ: &str = "bytes_read";
    pub const BYTES_WRITTEN: &str = "bytes_written";
    pub const DURATION_MS: &str = "duration_ms";
    pub const BULK_OPERATION: &str = "bulk_operation";
    pub const EXPORT_OPERATION: &str = "export_operation";
    pub const PRIVILEGE_OPERATION: &str = "privilege_operation";
    pub const ADMINISTRATIVE_OPERATION: &str = "administrative_operation";

    pub const CASE_REF: &str = "case_ref";
    pub const PROJECT_REF: &str = "project_ref";
    pub const PURPOSE: &str = "purpose";
    pub const JUSTIFICATION: &str = "justification";
    pub const APPROVAL_REF: &str = "approval_ref";
    pub const MAINTENANCE_WINDOW: &str = "maintenance_window";
    pub const CHANGE_REF: &str = "change_ref";

    pub const DATA_CLASSIFICATION: &str = "data_classification";
    pub const SENSITIVE_RESOURCE: &str = "sensitive_resource";
    pub const PEER_ACCESS: &str = "peer_access";
    pub const PRIVILEGED_ACCESS: &str = "privileged_access";
    pub const POLICY_SCOPE: &str = "policy_scope";
    pub const SOURCE_TRUST: &str = "source_trust";
    pub const PARSER_VERSION: &str = "parser_version";
    pub const SCHEMA_VERSION: &str = "schema_version";
}

/// The `log_type` label that marks an event as an application-audit record. The
/// correlation rules key on this, so the canonical model uses it too.
pub const AUDIT_LOG_TYPE: &str = "audit";

// --------------------------------------------------------------------------
// enums
// --------------------------------------------------------------------------

/// What kind of principal acted. `Unknown` is the forward-compatible default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Human,
    ServiceAccount,
    System,
    #[default]
    #[serde(other)]
    Unknown,
}

impl ActorType {
    /// Parse the `actor_type` field value (case-insensitive, tolerant of common
    /// spellings). Unrecognized → `Unknown`.
    pub fn parse(s: &str) -> ActorType {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "human" | "person" | "interactive" | "user" => ActorType::Human,
            "service_account" | "service" | "svc" | "machine" | "robot" | "bot" => {
                ActorType::ServiceAccount
            }
            "system" | "internal" | "daemon" => ActorType::System,
            _ => ActorType::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ActorType::Human => "human",
            ActorType::ServiceAccount => "service_account",
            ActorType::System => "system",
            ActorType::Unknown => "unknown",
        }
    }
}

/// The result of the audited action. `Unknown` is the forward-compatible default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Denied,
    Error,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Outcome {
    pub fn parse(s: &str) -> Outcome {
        match s.trim().to_ascii_lowercase().as_str() {
            "success" | "ok" | "allowed" | "allow" | "granted" | "0" | "00000" => Outcome::Success,
            "failure" | "fail" | "failed" => Outcome::Failure,
            "denied" | "deny" | "permission_denied" | "forbidden" | "42501" => Outcome::Denied,
            "error" | "err" => Outcome::Error,
            _ => Outcome::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
            Outcome::Unknown => "unknown",
        }
    }

    /// A denied or failed access — the security-relevant negative outcomes.
    pub fn is_negative(self) -> bool {
        matches!(self, Outcome::Denied | Outcome::Failure | Outcome::Error)
    }
}

/// The coarse operation class. This is the Phase-1 lightweight classification;
/// Phase 3's SQL analyzer produces the authoritative `statement_type`. `Other`
/// is the forward-compatible catch-all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    Select,
    Insert,
    Update,
    Delete,
    Copy,
    Create,
    Alter,
    Drop,
    Truncate,
    Grant,
    Revoke,
    SetRole,
    Call,
    #[default]
    #[serde(other)]
    Other,
}

impl QueryType {
    pub fn parse(s: &str) -> QueryType {
        match s
            .trim()
            .to_ascii_uppercase()
            .replace(['-', '_'], " ")
            .as_str()
        {
            "SELECT" | "READ" | "VIEW" => QueryType::Select,
            "INSERT" | "WRITE" => QueryType::Insert,
            "UPDATE" => QueryType::Update,
            "DELETE" => QueryType::Delete,
            "COPY" | "EXPORT" | "UNLOAD" => QueryType::Copy,
            "CREATE" => QueryType::Create,
            "ALTER" => QueryType::Alter,
            "DROP" => QueryType::Drop,
            "TRUNCATE" => QueryType::Truncate,
            "GRANT" => QueryType::Grant,
            "REVOKE" => QueryType::Revoke,
            "SET ROLE" | "SETROLE" | "SET_ROLE" => QueryType::SetRole,
            "CALL" | "EXECUTE" | "DO" => QueryType::Call,
            _ => QueryType::Other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            QueryType::Select => "select",
            QueryType::Insert => "insert",
            QueryType::Update => "update",
            QueryType::Delete => "delete",
            QueryType::Copy => "copy",
            QueryType::Create => "create",
            QueryType::Alter => "alter",
            QueryType::Drop => "drop",
            QueryType::Truncate => "truncate",
            QueryType::Grant => "grant",
            QueryType::Revoke => "revoke",
            QueryType::SetRole => "set_role",
            QueryType::Call => "call",
            QueryType::Other => "other",
        }
    }

    /// A privilege / access-control changing operation (GRANT/REVOKE/SET ROLE).
    pub fn is_privilege(self) -> bool {
        matches!(
            self,
            QueryType::Grant | QueryType::Revoke | QueryType::SetRole
        )
    }

    /// A schema-changing DDL operation.
    pub fn is_ddl(self) -> bool {
        matches!(
            self,
            QueryType::Create | QueryType::Alter | QueryType::Drop | QueryType::Truncate
        )
    }
}

// --------------------------------------------------------------------------
// field groups
// --------------------------------------------------------------------------

/// Identity and actor — who acted, and under which effective/delegated identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActor {
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_name: Option<String>,
    #[serde(default)]
    pub actor_type: ActorType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_groups: Vec<String>,
    #[serde(default)]
    pub service_account: bool,
    /// The authenticated login identity (PostgreSQL `session_user`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_identity: Option<String>,
    /// The effective identity after any role switch (PostgreSQL `current_user`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_identity: Option<String>,
}

/// Application and environment — where the access happened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_instance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

/// Action — what was done and how much data moved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditAction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default)]
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_type: Option<QueryType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_read: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_written: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_read: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    #[serde(default)]
    pub bulk_operation: bool,
    #[serde(default)]
    pub export_operation: bool,
    #[serde(default)]
    pub privilege_operation: bool,
    #[serde(default)]
    pub administrative_operation: bool,
}

/// Business justification — why the access was (claimed to be) legitimate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditJustification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ref: Option<String>,
}

impl AuditJustification {
    /// True if ANY justification reference is present. Used by the
    /// missing-justification detector and the policy engine's
    /// require-justification effect.
    pub fn is_present(&self) -> bool {
        // A present-but-blank reference does not count — a whitespace-only ticket
        // must not satisfy a require-justification policy.
        [
            &self.ticket_ref,
            &self.case_ref,
            &self.project_ref,
            &self.purpose,
            &self.justification,
            &self.approval_ref,
            &self.change_ref,
        ]
        .iter()
        .any(|o| o.as_deref().is_some_and(|s| !s.trim().is_empty()))
    }
}

/// Security classification — how sensitive this access is, and provenance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditClassification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
    #[serde(default)]
    pub sensitive_resource: bool,
    #[serde(default)]
    pub watched_subject: bool,
    #[serde(default)]
    pub self_access: bool,
    #[serde(default)]
    pub peer_access: bool,
    #[serde(default)]
    pub privileged_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
}

// --------------------------------------------------------------------------
// the canonical record
// --------------------------------------------------------------------------

/// The canonical, domain-neutral application-audit record — a typed lens over an
/// [`Event`]'s already-normalized fields. See the module docs for the
/// lens-not-a-second-event-type and backward-compatibility contracts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub actor: AuditActor,
    pub context: AuditContext,
    pub action: AuditAction,
    pub justification: AuditJustification,
    pub classification: AuditClassification,
}

/// Read the first non-empty value among a list of candidate keys, in order.
/// This is the ONLY alias resolution `AuditRecord` performs, and it exists so a
/// record can be built either from an ingest-normalized `Event` (canonical keys
/// present) or from a raw adapter map that still uses source spellings.
fn first<'a>(fields: &'a BTreeMap<String, String>, candidates: &[&str]) -> Option<&'a str> {
    candidates
        .iter()
        .filter_map(|k| fields.get(*k))
        .map(String::as_str)
        // Reject whitespace-only values: a blank ticket_ref must not count as a
        // present justification (it would otherwise satisfy a policy requirement).
        .find(|v| !v.trim().is_empty())
}

/// Parse a boolean-ish field value the same way the rest of garmr does
/// (`AccessProjection` uses the identical truth set).
fn flag(fields: &BTreeMap<String, String>, candidates: &[&str]) -> bool {
    matches!(first(fields, candidates), Some("true" | "1" | "yes" | "t"))
}

fn num<T: std::str::FromStr>(fields: &BTreeMap<String, String>, candidates: &[&str]) -> Option<T> {
    first(fields, candidates).and_then(|v| v.trim().parse::<T>().ok())
}

fn split_groups(raw: &str) -> Vec<String> {
    raw.split([',', ';', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl AuditRecord {
    /// True if an [`Event`] should be interpreted as an application-audit record:
    /// either it carries the `log_type=audit` marker, or it has an actor plus at
    /// least one access dimension (subject / object / statement). This is the
    /// same predicate ingest and the detectors use to route audit events.
    pub fn is_audit_event(ev: &Event) -> bool {
        if ev.log_type.eq_ignore_ascii_case(AUDIT_LOG_TYPE) {
            return true;
        }
        let has_actor = first(&ev.fields, ACTOR_ALIASES).is_some();
        let has_access = first(&ev.fields, SUBJECT_ALIASES).is_some()
            || first(&ev.fields, OBJECT_TYPE_ALIASES).is_some()
            || ev.fields.contains_key(keys::STATEMENT);
        has_actor && has_access
    }

    /// Project a typed record from an event, if it is an audit event; otherwise
    /// `None`. Mirrors [`crate::AccessProjection::from_event`]'s "no actor → not
    /// an access event" contract but over the richer field set.
    pub fn from_event_opt(ev: &Event) -> Option<AuditRecord> {
        if !Self::is_audit_event(ev) {
            return None;
        }
        Some(Self::from_event(ev))
    }

    /// Project a typed record from an event's fields. Always returns a record;
    /// absent fields stay `None`/default. Environment and host fall back to the
    /// event's own labels when the fields map does not override them.
    pub fn from_event(ev: &Event) -> AuditRecord {
        let f = &ev.fields;

        let service_account = flag(f, &[keys::SERVICE_ACCOUNT])
            || matches!(
                first(f, &[keys::ACTOR_TYPE]).map(ActorType::parse),
                Some(ActorType::ServiceAccount)
            );
        let actor_type = match first(f, &[keys::ACTOR_TYPE]) {
            Some(v) => ActorType::parse(v),
            None if service_account => ActorType::ServiceAccount,
            None => ActorType::Unknown,
        };

        let actor = AuditActor {
            actor_id: first(f, ACTOR_ALIASES).unwrap_or_default().to_string(),
            actor_name: first(f, &[keys::ACTOR_NAME]).map(str::to_string),
            actor_type,
            actor_role: first(f, &[keys::ACTOR_ROLE, "role"]).map(str::to_string),
            actor_groups: first(f, &[keys::ACTOR_GROUPS, "groups"])
                .map(split_groups)
                .unwrap_or_default(),
            service_account,
            authenticated_identity: first(f, &[keys::AUTHENTICATED_IDENTITY, "session_user"])
                .map(str::to_string),
            effective_identity: first(f, &[keys::EFFECTIVE_IDENTITY, "current_user"])
                .map(str::to_string),
            delegated_identity: first(f, &[keys::DELEGATED_IDENTITY]).map(str::to_string),
            impersonated_identity: first(f, &[keys::IMPERSONATED_IDENTITY]).map(str::to_string),
        };

        let context = AuditContext {
            application_id: first(f, &[keys::APPLICATION_ID]).map(str::to_string),
            application_name: first(f, &[keys::APPLICATION_NAME, "application_name", "appname"])
                .map(str::to_string),
            application_instance: first(f, &[keys::APPLICATION_INSTANCE]).map(str::to_string),
            environment: first(f, &["environment", "env"])
                .map(str::to_string)
                .or_else(|| Some(ev.environment.to_string()).filter(|s| !s.is_empty())),
            site: first(f, &[keys::SITE]).map(str::to_string),
            security_zone: first(f, &[keys::SECURITY_ZONE]).map(str::to_string),
            tenant: first(f, &[keys::TENANT]).map(str::to_string),
            database: first(f, &[keys::DATABASE, "datname", "dbname"]).map(str::to_string),
            database_schema: first(f, &[keys::DATABASE_SCHEMA, "schema"]).map(str::to_string),
            host: first(f, &["host"])
                .map(str::to_string)
                .or_else(|| Some(ev.host.to_string()).filter(|s| !s.is_empty())),
            client_host: first(f, &[keys::CLIENT_HOST, keys::CLIENT, "remote_host"])
                .map(str::to_string),
            client_ip: first(f, &[keys::CLIENT_IP, "src_ip", "remote_addr"]).map(str::to_string),
            client_application: first(f, &[keys::CLIENT_APPLICATION]).map(str::to_string),
            session_id: first(f, &[keys::SESSION_ID]).map(str::to_string),
            transaction_id: first(f, &[keys::TRANSACTION_ID, "txid", "xid"]).map(str::to_string),
            request_id: first(f, &[keys::REQUEST_ID]).map(str::to_string),
            trace_id: first(f, &[keys::TRACE_ID]).map(str::to_string),
        };

        let query_type = first(f, &[keys::QUERY_TYPE])
            .map(QueryType::parse)
            .or_else(|| first(f, &[keys::ACTION]).map(QueryType::parse));

        let action = AuditAction {
            action: first(f, &[keys::ACTION]).map(str::to_string),
            operation: first(f, &[keys::OPERATION]).map(str::to_string),
            outcome: first(f, &[keys::OUTCOME, "result", "status"])
                .map(Outcome::parse)
                .unwrap_or_default(),
            error_code: first(f, &[keys::ERROR_CODE, "sqlstate"]).map(str::to_string),
            object_type: first(f, OBJECT_TYPE_ALIASES).map(str::to_string),
            object_name: first(f, &[keys::OBJECT_NAME, "relation"]).map(str::to_string),
            resource_path: first(f, &[keys::RESOURCE_PATH, "path"]).map(str::to_string),
            record_id: first(f, &[keys::RECORD_ID]).map(str::to_string),
            subject_id: first(f, SUBJECT_ALIASES).map(str::to_string),
            subject_type: first(f, &[keys::SUBJECT_TYPE]).map(str::to_string),
            statement: first(f, &[keys::STATEMENT]).map(str::to_string),
            statement_fingerprint: first(f, &[keys::STATEMENT_FINGERPRINT]).map(str::to_string),
            query_type,
            rows_read: num(f, &[keys::ROWS_READ, "rows"]),
            rows_written: num(f, &[keys::ROWS_WRITTEN]),
            bytes_read: num(f, &[keys::BYTES_READ]),
            bytes_written: num(f, &[keys::BYTES_WRITTEN]),
            duration_ms: num(f, &[keys::DURATION_MS, "duration"]),
            bulk_operation: flag(f, &[keys::BULK_OPERATION]),
            export_operation: flag(f, &[keys::EXPORT_OPERATION]),
            privilege_operation: flag(f, &[keys::PRIVILEGE_OPERATION])
                || query_type.is_some_and(QueryType::is_privilege),
            administrative_operation: flag(f, &[keys::ADMINISTRATIVE_OPERATION]),
        };

        let justification = AuditJustification {
            ticket_ref: first(f, &[keys::TICKET]).map(str::to_string),
            case_ref: first(f, &[keys::CASE_REF]).map(str::to_string),
            project_ref: first(f, &[keys::PROJECT_REF]).map(str::to_string),
            purpose: first(f, &[keys::PURPOSE]).map(str::to_string),
            justification: first(f, &[keys::JUSTIFICATION]).map(str::to_string),
            approval_ref: first(f, &[keys::APPROVAL_REF]).map(str::to_string),
            maintenance_window: first(f, &[keys::MAINTENANCE_WINDOW]).map(str::to_string),
            change_ref: first(f, &[keys::CHANGE_REF]).map(str::to_string),
        };

        let classification = AuditClassification {
            data_classification: first(f, &[keys::DATA_CLASSIFICATION]).map(str::to_string),
            sensitive_resource: flag(f, &[keys::SENSITIVE_RESOURCE]),
            watched_subject: flag(f, &[keys::WATCHED]),
            self_access: flag(f, &[keys::IS_SELF]),
            peer_access: flag(f, &[keys::PEER_ACCESS]),
            privileged_access: flag(f, &[keys::PRIVILEGED_ACCESS]) || action.privilege_operation,
            policy_scope: first(f, &[keys::POLICY_SCOPE]).map(str::to_string),
            source_trust: first(f, &[keys::SOURCE_TRUST]).map(str::to_string),
            parser_version: first(f, &[keys::PARSER_VERSION]).map(str::to_string),
            schema_version: first(f, &[keys::SCHEMA_VERSION]).map(str::to_string),
        };

        AuditRecord {
            actor,
            context,
            action,
            justification,
            classification,
        }
    }

    /// Serialize back to a canonical `fields` map, using the STORAGE-canonical
    /// keys (legacy names preserved) so a synthesized event round-trips through
    /// [`AuditRecord::from_event`] AND stays readable by
    /// [`crate::AccessProjection`], the correlation SQL, and the entity pivots.
    /// Only set fields are written.
    pub fn to_fields(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: &str| {
            if !v.is_empty() {
                m.insert(k.to_string(), v.to_string());
            }
        };
        let put_opt = |m: &mut BTreeMap<String, String>, k: &str, v: &Option<String>| {
            if let Some(v) = v {
                if !v.is_empty() {
                    m.insert(k.to_string(), v.clone());
                }
            }
        };
        let put_bool = |m: &mut BTreeMap<String, String>, k: &str, v: bool| {
            if v {
                m.insert(k.to_string(), "true".to_string());
            }
        };
        let put_num = |m: &mut BTreeMap<String, String>, k: &str, v: &Option<u64>| {
            if let Some(v) = v {
                m.insert(k.to_string(), v.to_string());
            }
        };

        // actor
        put(keys::ACTOR, &self.actor.actor_id);
        put_opt(&mut m, keys::ACTOR_NAME, &self.actor.actor_name);
        if self.actor.actor_type != ActorType::Unknown {
            m.insert(
                keys::ACTOR_TYPE.to_string(),
                self.actor.actor_type.as_str().to_string(),
            );
        }
        put_opt(&mut m, keys::ACTOR_ROLE, &self.actor.actor_role);
        if !self.actor.actor_groups.is_empty() {
            m.insert(
                keys::ACTOR_GROUPS.to_string(),
                self.actor.actor_groups.join(","),
            );
        }
        put_bool(&mut m, keys::SERVICE_ACCOUNT, self.actor.service_account);
        put_opt(
            &mut m,
            keys::AUTHENTICATED_IDENTITY,
            &self.actor.authenticated_identity,
        );
        put_opt(
            &mut m,
            keys::EFFECTIVE_IDENTITY,
            &self.actor.effective_identity,
        );
        put_opt(
            &mut m,
            keys::DELEGATED_IDENTITY,
            &self.actor.delegated_identity,
        );
        put_opt(
            &mut m,
            keys::IMPERSONATED_IDENTITY,
            &self.actor.impersonated_identity,
        );

        // context
        put_opt(&mut m, keys::APPLICATION_ID, &self.context.application_id);
        put_opt(
            &mut m,
            keys::APPLICATION_NAME,
            &self.context.application_name,
        );
        put_opt(
            &mut m,
            keys::APPLICATION_INSTANCE,
            &self.context.application_instance,
        );
        put_opt(&mut m, keys::SITE, &self.context.site);
        put_opt(&mut m, keys::SECURITY_ZONE, &self.context.security_zone);
        put_opt(&mut m, keys::TENANT, &self.context.tenant);
        put_opt(&mut m, keys::DATABASE, &self.context.database);
        put_opt(&mut m, keys::DATABASE_SCHEMA, &self.context.database_schema);
        put_opt(&mut m, keys::CLIENT_HOST, &self.context.client_host);
        put_opt(&mut m, keys::CLIENT_IP, &self.context.client_ip);
        put_opt(
            &mut m,
            keys::CLIENT_APPLICATION,
            &self.context.client_application,
        );
        put_opt(&mut m, keys::SESSION_ID, &self.context.session_id);
        put_opt(&mut m, keys::TRANSACTION_ID, &self.context.transaction_id);
        put_opt(&mut m, keys::REQUEST_ID, &self.context.request_id);
        put_opt(&mut m, keys::TRACE_ID, &self.context.trace_id);

        // action
        put_opt(&mut m, keys::ACTION, &self.action.action);
        put_opt(&mut m, keys::OPERATION, &self.action.operation);
        if self.action.outcome != Outcome::Unknown {
            m.insert(
                keys::OUTCOME.to_string(),
                self.action.outcome.as_str().to_string(),
            );
        }
        put_opt(&mut m, keys::ERROR_CODE, &self.action.error_code);
        put_opt(&mut m, keys::OBJECT_TYPE, &self.action.object_type);
        put_opt(&mut m, keys::OBJECT_NAME, &self.action.object_name);
        put_opt(&mut m, keys::RESOURCE_PATH, &self.action.resource_path);
        put_opt(&mut m, keys::RECORD_ID, &self.action.record_id);
        put_opt(&mut m, keys::SUBJECT, &self.action.subject_id);
        put_opt(&mut m, keys::SUBJECT_TYPE, &self.action.subject_type);
        put_opt(&mut m, keys::STATEMENT, &self.action.statement);
        put_opt(
            &mut m,
            keys::STATEMENT_FINGERPRINT,
            &self.action.statement_fingerprint,
        );
        if let Some(qt) = self.action.query_type {
            m.insert(keys::QUERY_TYPE.to_string(), qt.as_str().to_string());
        }
        put_num(&mut m, keys::ROWS_READ, &self.action.rows_read);
        put_num(&mut m, keys::ROWS_WRITTEN, &self.action.rows_written);
        put_num(&mut m, keys::BYTES_READ, &self.action.bytes_read);
        put_num(&mut m, keys::BYTES_WRITTEN, &self.action.bytes_written);
        if let Some(d) = self.action.duration_ms {
            m.insert(keys::DURATION_MS.to_string(), format!("{d}"));
        }
        put_bool(&mut m, keys::BULK_OPERATION, self.action.bulk_operation);
        put_bool(&mut m, keys::EXPORT_OPERATION, self.action.export_operation);
        put_bool(
            &mut m,
            keys::PRIVILEGE_OPERATION,
            self.action.privilege_operation,
        );
        put_bool(
            &mut m,
            keys::ADMINISTRATIVE_OPERATION,
            self.action.administrative_operation,
        );

        // justification
        put_opt(&mut m, keys::TICKET, &self.justification.ticket_ref);
        put_opt(&mut m, keys::CASE_REF, &self.justification.case_ref);
        put_opt(&mut m, keys::PROJECT_REF, &self.justification.project_ref);
        put_opt(&mut m, keys::PURPOSE, &self.justification.purpose);
        put_opt(
            &mut m,
            keys::JUSTIFICATION,
            &self.justification.justification,
        );
        put_opt(&mut m, keys::APPROVAL_REF, &self.justification.approval_ref);
        put_opt(
            &mut m,
            keys::MAINTENANCE_WINDOW,
            &self.justification.maintenance_window,
        );
        put_opt(&mut m, keys::CHANGE_REF, &self.justification.change_ref);

        // classification
        put_opt(
            &mut m,
            keys::DATA_CLASSIFICATION,
            &self.classification.data_classification,
        );
        put_bool(
            &mut m,
            keys::SENSITIVE_RESOURCE,
            self.classification.sensitive_resource,
        );
        put_bool(&mut m, keys::WATCHED, self.classification.watched_subject);
        put_bool(&mut m, keys::IS_SELF, self.classification.self_access);
        put_bool(&mut m, keys::PEER_ACCESS, self.classification.peer_access);
        put_bool(
            &mut m,
            keys::PRIVILEGED_ACCESS,
            self.classification.privileged_access,
        );
        put_opt(
            &mut m,
            keys::POLICY_SCOPE,
            &self.classification.policy_scope,
        );
        put_opt(
            &mut m,
            keys::SOURCE_TRUST,
            &self.classification.source_trust,
        );
        put_opt(
            &mut m,
            keys::PARSER_VERSION,
            &self.classification.parser_version,
        );
        put_opt(
            &mut m,
            keys::SCHEMA_VERSION,
            &self.classification.schema_version,
        );

        m
    }

    /// The actor id, empty string if unknown — the single most-used dimension
    /// (per-actor RBA, user pages, monitoring).
    pub fn actor_id(&self) -> &str {
        &self.actor.actor_id
    }

    /// True if this access lacks any justification reference — the raw condition
    /// the Phase-8 missing-justification detector and the Phase-5 policy
    /// require-justification effect build on.
    pub fn missing_justification(&self) -> bool {
        !self.justification.is_present()
    }
}

// --------------------------------------------------------------------------
// alias tables (shared by is_audit_event + from_event; match ingest's classifier
// so a record can be built pre- or post-normalization)
// --------------------------------------------------------------------------

/// Accepted input spellings for the actor. The first (`db_user`) is canonical.
const ACTOR_ALIASES: &[&str] = &[
    keys::ACTOR,
    "actor_id",
    "session_user",
    "actor",
    "principal",
    "acting_user",
    "performed_by",
    "accessed_by",
    "operator",
    "account",
    "user_id",
    "user",
];

/// Accepted input spellings for the data subject. The first (`target_person`) is
/// canonical.
const SUBJECT_ALIASES: &[&str] = &[
    keys::SUBJECT,
    "subject_id",
    "target",
    "subject",
    "target_id",
    "object_id",
    "entity_id",
];

/// Accepted input spellings for the object type/class. The first
/// (`object_table`) is canonical.
const OBJECT_TYPE_ALIASES: &[&str] = &[
    keys::OBJECT_TYPE,
    "object_type",
    "resource_type",
    "entity_type",
    "resource",
    "collection",
    "dataset",
    "endpoint",
    "relation",
    "table_name",
];

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn ev(log_type: &str, fields: &[(&str, &str)]) -> Event {
        Event {
            ts: Utc::now(),
            host: "db01".into(),
            service: "postgres".into(),
            source: "pgaudit".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: log_type.into(),
            message: String::new(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn register_profile_keys_project_into_the_canonical_model() {
        // The register flagship, in its shipped canonical keys.
        let e = ev(
            "audit",
            &[
                ("db_user", "caseworker7"),
                ("target_person", "pnr-abc"),
                ("object_table", "persons"),
                ("action", "select"),
                ("ticket_ref", "ARENDE-42"),
                ("client_addr", "10.0.0.5"),
                ("watched", "true"),
            ],
        );
        let r = AuditRecord::from_event(&e);
        assert_eq!(r.actor.actor_id, "caseworker7");
        assert_eq!(r.action.subject_id.as_deref(), Some("pnr-abc"));
        assert_eq!(r.action.object_type.as_deref(), Some("persons"));
        assert_eq!(r.action.action.as_deref(), Some("select"));
        assert_eq!(r.action.query_type, Some(QueryType::Select));
        assert_eq!(r.justification.ticket_ref.as_deref(), Some("ARENDE-42"));
        assert_eq!(r.context.client_host.as_deref(), Some("10.0.0.5"));
        assert!(r.classification.watched_subject);
        assert!(!r.classification.self_access);
        assert!(!r.missing_justification());
    }

    #[test]
    fn audit_view_stays_consistent_with_access_projection() {
        // Both lenses over the same event must agree on the shared dimensions —
        // that is the backward-compatibility contract.
        let e = ev(
            "audit",
            &[
                ("db_user", "u1"),
                ("target_person", "s1"),
                ("object_table", "accounts"),
                ("action", "read"),
                ("ticket_ref", "T-1"),
                ("client_addr", "host-x"),
                ("is_self", "true"),
            ],
        );
        let r = AuditRecord::from_event(&e);
        let p = crate::AccessProjection::from_event(&e).unwrap();
        assert_eq!(r.actor.actor_id, p.actor.id);
        assert_eq!(r.action.subject_id, p.subject.map(|s| s.id));
        assert_eq!(r.action.object_type, p.resource.map(|x| x.class));
        assert_eq!(
            r.justification.ticket_ref,
            p.justification.map(|j| j.reference)
        );
        assert_eq!(r.classification.self_access, p.is_self);
        assert_eq!(r.classification.watched_subject, p.watched);
    }

    #[test]
    fn round_trips_through_fields() {
        let r = AuditRecord {
            actor: AuditActor {
                actor_id: "svc-etl".into(),
                actor_type: ActorType::ServiceAccount,
                actor_role: Some("etl".into()),
                actor_groups: vec!["analytics".into(), "batch".into()],
                service_account: true,
                authenticated_identity: Some("etl_login".into()),
                effective_identity: Some("etl".into()),
                ..Default::default()
            },
            context: AuditContext {
                application_name: Some("warehouse".into()),
                database: Some("dwh".into()),
                database_schema: Some("public".into()),
                client_ip: Some("10.1.2.3".into()),
                session_id: Some("sess-9".into()),
                ..Default::default()
            },
            action: AuditAction {
                action: Some("select".into()),
                outcome: Outcome::Success,
                object_type: Some("table".into()),
                object_name: Some("customers".into()),
                subject_id: Some("cust-1".into()),
                statement: Some("SELECT * FROM customers".into()),
                statement_fingerprint: Some("fp-abc".into()),
                query_type: Some(QueryType::Select),
                rows_read: Some(4200),
                bulk_operation: true,
                export_operation: true,
                ..Default::default()
            },
            justification: AuditJustification {
                case_ref: Some("C-7".into()),
                ..Default::default()
            },
            classification: AuditClassification {
                data_classification: Some("restricted".into()),
                sensitive_resource: true,
                source_trust: Some("trusted".into()),
                ..Default::default()
            },
        };
        // Round-trip purely through the fields map: use a label-less event so the
        // `environment`/`host` fallbacks (which read the Event's own columns, not
        // the fields map — hence `to_fields` never writes them) don't inject a
        // difference. `environment`/`host` sourcing is covered separately below.
        let e = Event {
            ts: Utc::now(),
            host: "".into(),
            service: "postgres".into(),
            source: "pgaudit".into(),
            environment: "".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: String::new(),
            fields: r.to_fields(),
        };
        let back = AuditRecord::from_event(&e);
        assert_eq!(back, r, "AuditRecord must survive a fields round-trip");
    }

    #[test]
    fn environment_and_host_fall_back_to_event_labels() {
        // These two dimensions live on the Event's own columns, so a record with
        // neither in its fields map still resolves them from the event labels.
        let e = ev("audit", &[("db_user", "u1"), ("object_table", "t")]);
        let r = AuditRecord::from_event(&e);
        assert_eq!(r.context.environment.as_deref(), Some("prod"));
        assert_eq!(r.context.host.as_deref(), Some("db01"));
        // An explicit `environment` field overrides the label.
        let e2 = ev(
            "audit",
            &[
                ("db_user", "u1"),
                ("object_table", "t"),
                ("environment", "lab"),
            ],
        );
        assert_eq!(
            AuditRecord::from_event(&e2).context.environment.as_deref(),
            Some("lab")
        );
    }

    #[test]
    fn detects_audit_events_and_rejects_non_audit() {
        // Explicit marker.
        assert!(AuditRecord::is_audit_event(&ev("audit", &[])));
        // Actor + access dimension, no marker.
        assert!(AuditRecord::is_audit_event(&ev(
            "app",
            &[("db_user", "u1"), ("object_table", "t")]
        )));
        // Actor alone is not an access event.
        assert!(!AuditRecord::is_audit_event(&ev(
            "app",
            &[("db_user", "u1")]
        )));
        // Neither actor nor marker.
        assert!(!AuditRecord::is_audit_event(&ev(
            "system",
            &[("message", "x")]
        )));
        assert!(AuditRecord::from_event_opt(&ev("system", &[])).is_none());
    }

    #[test]
    fn privilege_and_service_account_are_inferred() {
        // GRANT via action → privilege_operation + privileged_access, no explicit flags.
        let e = ev(
            "audit",
            &[
                ("db_user", "dba"),
                ("action", "GRANT"),
                ("object_table", "roles"),
            ],
        );
        let r = AuditRecord::from_event(&e);
        assert_eq!(r.action.query_type, Some(QueryType::Grant));
        assert!(r.action.privilege_operation);
        assert!(r.classification.privileged_access);

        // service_account inferred from actor_type spelling.
        let e2 = ev(
            "audit",
            &[
                ("db_user", "svc"),
                ("actor_type", "service"),
                ("object_table", "t"),
            ],
        );
        let r2 = AuditRecord::from_event(&e2);
        assert_eq!(r2.actor.actor_type, ActorType::ServiceAccount);
        assert!(r2.actor.service_account);
    }

    #[test]
    fn reads_source_alias_spellings_before_normalization() {
        // A raw adapter map that still uses source spellings must also project.
        let e = ev(
            "app",
            &[
                ("session_user", "raw_actor"),
                ("subject_id", "raw_subject"),
                ("resource_type", "documents"),
                ("sqlstate", "42501"),
                ("result", "denied"),
            ],
        );
        let r = AuditRecord::from_event(&e);
        assert_eq!(r.actor.actor_id, "raw_actor");
        assert_eq!(r.action.subject_id.as_deref(), Some("raw_subject"));
        assert_eq!(r.action.object_type.as_deref(), Some("documents"));
        assert_eq!(r.action.outcome, Outcome::Denied);
        assert!(r.action.outcome.is_negative());
        assert_eq!(r.action.error_code.as_deref(), Some("42501"));
    }

    #[test]
    fn blank_justification_does_not_count_as_present() {
        // A whitespace-only ticket must NOT satisfy a require-justification check.
        let e = ev(
            "audit",
            &[
                ("db_user", "u1"),
                ("object_table", "t"),
                ("ticket_ref", "   "),
            ],
        );
        let r = AuditRecord::from_event(&e);
        assert!(
            r.justification.ticket_ref.is_none(),
            "blank field must resolve to None"
        );
        assert!(!r.justification.is_present());
        assert!(r.missing_justification());
        // A directly-built record with a blank field is also not present.
        let j = AuditJustification {
            approval_ref: Some("  ".into()),
            ..Default::default()
        };
        assert!(!j.is_present());
    }

    #[test]
    fn enum_parsing_is_tolerant() {
        assert_eq!(QueryType::parse("set role"), QueryType::SetRole);
        assert_eq!(QueryType::parse("UNLOAD"), QueryType::Copy);
        assert!(QueryType::Revoke.is_privilege());
        assert!(QueryType::Drop.is_ddl());
        assert_eq!(Outcome::parse("permission_denied"), Outcome::Denied);
        assert_eq!(ActorType::parse("Robot"), ActorType::ServiceAccount);
        assert_eq!(ActorType::parse("weird"), ActorType::Unknown);
    }
}
