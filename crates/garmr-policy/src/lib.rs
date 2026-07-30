// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 5 — the explicit access-policy engine.
//!
//! This is deliberately SEPARATE from anomaly detection. Anomaly detection asks
//! "is this unusual?"; the policy engine asks "is this *allowed*?" — a question
//! with a deterministic, explainable, human-authored answer. The two never
//! merge: a behavior that is common is still forbidden if a policy forbids it,
//! and [`evaluate`]'s explicit [`Effect::Deny`] is the strongest outcome there
//! is, so downstream risk scoring can raise attention on it but never suppress
//! it (the "explicit deny overrides learned-normal" invariant; enforced at the
//! ensemble boundary, guaranteed here by decision precedence).
//!
//! A [`Policy`] matches an access on three axes — [`SubjectMatch`] (who),
//! [`ResourceMatch`] (what), [`ConditionMatch`] (circumstances) — and carries an
//! [`Effect`]. [`evaluate`] returns an explainable [`PolicyDecision`]; [`simulate`]
//! replays one proposed policy over historical accesses so an author sees its
//! blast radius before it is approved.
//!
//! Pure, no I/O. Persistence (versioned, human-approved, reversible) rides the
//! existing registry-governance channel; this crate is the evaluation core.

use std::collections::BTreeSet;

use garmr_core::app_audit::keys;
use garmr_core::{AuditRecord, Event};
use serde::{Deserialize, Serialize};

// -------------------------------------------------------------------------
// effects
// -------------------------------------------------------------------------

/// What a matched policy does. Ranked so the strongest matched effect wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Explicitly permitted (documents an allow; the default when nothing matches).
    Allow,
    /// Add to the actor's risk (a weak signal), no hard outcome.
    IncreaseRisk,
    /// Raise an alert but do not block.
    Alert,
    /// Require a second analyst to review.
    StepUpReview,
    /// Permitted only if a justification (ticket/case/purpose) is present.
    RequireJustification,
    /// Permitted only if an approval reference is present.
    RequireApproval,
    /// Explicitly forbidden — the strongest outcome; overrides learned-normal.
    Deny,
}

impl Effect {
    /// Precedence rank (higher wins). Deny is always strongest.
    fn rank(self) -> u8 {
        match self {
            Effect::Allow => 0,
            Effect::IncreaseRisk => 1,
            Effect::Alert => 2,
            Effect::StepUpReview => 3,
            Effect::RequireJustification => 4,
            Effect::RequireApproval => 5,
            Effect::Deny => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::IncreaseRisk => "increase_risk",
            Effect::Alert => "alert",
            Effect::StepUpReview => "step_up_review",
            Effect::RequireJustification => "require_justification",
            Effect::RequireApproval => "require_approval",
            Effect::Deny => "deny",
        }
    }

    /// True for outcomes that restrict/flag an access (used by simulation to
    /// estimate false positives).
    pub fn is_restrictive(self) -> bool {
        !matches!(self, Effect::Allow | Effect::IncreaseRisk)
    }
}

// -------------------------------------------------------------------------
// matchers  (an empty selector means "any" — no constraint on that axis)
// -------------------------------------------------------------------------

fn sel_matches(sel: &[String], val: Option<&str>) -> bool {
    if sel.is_empty() {
        return true;
    }
    match val {
        Some(v) => sel.iter().any(|s| s.eq_ignore_ascii_case(v)),
        None => false,
    }
}

fn sel_matches_any(sel: &[String], vals: &[String]) -> bool {
    if sel.is_empty() {
        return true;
    }
    vals.iter()
        .any(|v| sel.iter().any(|s| object_pattern_matches(s, v)))
}

/// Match an object pattern against an accessed object name. Supports exact
/// (case-insensitive), an unqualified match (`persons` matches `public.persons`),
/// and a schema wildcard (`raw.*` matches `raw.anything`).
fn object_pattern_matches(pattern: &str, obj: &str) -> bool {
    let (p, o) = (pattern.to_ascii_lowercase(), obj.to_ascii_lowercase());
    if p == o {
        return true;
    }
    if let Some(prefix) = p.strip_suffix(".*") {
        return o == prefix || o.starts_with(&format!("{prefix}."));
    }
    // unqualified pattern matches the last dotted segment of the object.
    !p.contains('.') && o.rsplit('.').next() == Some(p.as_str())
}

/// Who the policy applies to. Empty fields impose no constraint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectMatch {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    /// `Some(true)` restricts to service accounts, `Some(false)` to humans.
    #[serde(default)]
    pub service_account: Option<bool>,
    #[serde(default)]
    pub applications: Vec<String>,
}

impl SubjectMatch {
    fn matches(&self, r: &AuditRecord) -> bool {
        sel_matches(&self.users, Some(r.actor.actor_id.as_str()))
            && sel_matches(&self.roles, r.actor.actor_role.as_deref())
            && (self.groups.is_empty() || sel_matches_any(&self.groups, &r.actor.actor_groups))
            && self
                .service_account
                .is_none_or(|b| b == r.actor.service_account)
            && sel_matches(&self.applications, r.context.application_name.as_deref())
    }

    /// True when no subject axis is constrained (matches every actor).
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
            && self.roles.is_empty()
            && self.groups.is_empty()
            && self.applications.is_empty()
            && self.service_account.is_none()
    }
}

/// What the policy applies to. Empty fields impose no constraint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMatch {
    #[serde(default)]
    pub databases: Vec<String>,
    #[serde(default)]
    pub schemas: Vec<String>,
    /// Table/view/object names (support `schema.*` and unqualified matches).
    #[serde(default)]
    pub objects: Vec<String>,
    #[serde(default)]
    pub object_types: Vec<String>,
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub data_classifications: Vec<String>,
    #[serde(default)]
    pub data_subject_categories: Vec<String>,
}

impl ResourceMatch {
    fn matches(&self, ctx: &AccessContext) -> bool {
        let r = ctx.record;
        sel_matches(&self.databases, r.context.database.as_deref())
            && sel_matches(&self.schemas, r.context.database_schema.as_deref())
            && (self.objects.is_empty()
                || sel_matches_any(&self.objects, &ctx.objects)
                || object_field_matches(&self.objects, r.action.object_name.as_deref()))
            && sel_matches(&self.object_types, r.action.object_type.as_deref())
            && (self.columns.is_empty() || sel_matches_any(&self.columns, &ctx.columns))
            && sel_matches(
                &self.data_classifications,
                r.classification.data_classification.as_deref(),
            )
            && sel_matches(
                &self.data_subject_categories,
                r.action.subject_type.as_deref(),
            )
    }

    /// True when no resource axis is constrained (matches every resource).
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
            && self.schemas.is_empty()
            && self.objects.is_empty()
            && self.object_types.is_empty()
            && self.columns.is_empty()
            && self.data_classifications.is_empty()
            && self.data_subject_categories.is_empty()
    }
}

fn object_field_matches(patterns: &[String], val: Option<&str>) -> bool {
    match val {
        Some(v) => patterns.iter().any(|p| object_pattern_matches(p, v)),
        None => false,
    }
}

/// An inclusive hour window `[start, end)` in the access's hour-of-day. `outside`
/// inverts it, so an off-hours policy is `{start:8, end:18, outside:true}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HourWindow {
    pub start: u8,
    pub end: u8,
    #[serde(default)]
    pub outside: bool,
}

impl HourWindow {
    fn contains(&self, hour: u8) -> bool {
        let inside = if self.start <= self.end {
            hour >= self.start && hour < self.end
        } else {
            // wrap past midnight
            hour >= self.start || hour < self.end
        };
        inside != self.outside
    }
}

/// The circumstances under which the policy applies. Empty/None impose no
/// constraint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionMatch {
    #[serde(default)]
    pub environments: Vec<String>,
    /// Weekdays the policy applies on: 0 = Monday … 6 = Sunday. Empty = any.
    #[serde(default)]
    pub weekdays: Vec<u8>,
    #[serde(default)]
    pub hours: Option<HourWindow>,
    /// Query operations (query_type: select/insert/…/copy/grant/set_role/…).
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub client_applications: Vec<String>,
    /// Client-IP prefixes (`10.0.` matches `10.0.x.y`). Empty = any.
    #[serde(default)]
    pub client_ip_prefixes: Vec<String>,
    #[serde(default)]
    pub export: Option<bool>,
    #[serde(default)]
    pub self_access: Option<bool>,
    #[serde(default)]
    pub watched_subject: Option<bool>,
    #[serde(default)]
    pub privileged: Option<bool>,
    #[serde(default)]
    pub sensitive_resource: Option<bool>,
    #[serde(default)]
    pub bulk_operation: Option<bool>,
    /// Applies only when at least this many rows were read.
    #[serde(default)]
    pub min_rows_read: Option<u64>,
    /// Applies only inside (Some(true)) / outside (Some(false)) a maintenance window.
    #[serde(default)]
    pub maintenance_window: Option<bool>,
}

impl ConditionMatch {
    fn matches(&self, ctx: &AccessContext) -> bool {
        let r = ctx.record;
        if !sel_matches(&self.environments, r.context.environment.as_deref()) {
            return false;
        }
        if !self.weekdays.is_empty() && !ctx.weekday.is_some_and(|w| self.weekdays.contains(&w)) {
            return false;
        }
        if let Some(win) = &self.hours {
            if !ctx.hour.is_some_and(|h| win.contains(h)) {
                return false;
            }
        }
        if !sel_matches(&self.operations, r.action.query_type.map(|q| q.as_str())) {
            return false;
        }
        if !sel_matches(
            &self.client_applications,
            r.context.client_application.as_deref(),
        ) {
            return false;
        }
        if !self.client_ip_prefixes.is_empty() {
            let ip = r
                .context
                .client_ip
                .as_deref()
                .or(r.context.client_host.as_deref());
            if !ip.is_some_and(|ip| {
                self.client_ip_prefixes
                    .iter()
                    .any(|p| ip.starts_with(p.as_str()))
            }) {
                return false;
            }
        }
        if !opt_bool_matches(self.export, r.action.export_operation)
            || !opt_bool_matches(self.self_access, r.classification.self_access)
            || !opt_bool_matches(self.watched_subject, r.classification.watched_subject)
            || !opt_bool_matches(self.privileged, r.classification.privileged_access)
            || !opt_bool_matches(self.sensitive_resource, r.classification.sensitive_resource)
            || !opt_bool_matches(self.bulk_operation, r.action.bulk_operation)
        {
            return false;
        }
        if let Some(min) = self.min_rows_read {
            if r.action.rows_read.is_none_or(|n| n < min) {
                return false;
            }
        }
        if let Some(want) = self.maintenance_window {
            if r.justification.maintenance_window.is_some() != want {
                return false;
            }
        }
        true
    }

    /// True when no condition axis is constrained (matches in every context).
    pub fn is_empty(&self) -> bool {
        self.environments.is_empty()
            && self.weekdays.is_empty()
            && self.hours.is_none()
            && self.operations.is_empty()
            && self.client_applications.is_empty()
            && self.client_ip_prefixes.is_empty()
            && self.export.is_none()
            && self.self_access.is_none()
            && self.watched_subject.is_none()
            && self.privileged.is_none()
            && self.sensitive_resource.is_none()
            && self.bulk_operation.is_none()
            && self.min_rows_read.is_none()
            && self.maintenance_window.is_none()
    }
}

fn opt_bool_matches(want: Option<bool>, actual: bool) -> bool {
    want.is_none_or(|b| b == actual)
}

// -------------------------------------------------------------------------
// policy
// -------------------------------------------------------------------------

/// One access policy. Precedence is by [`Effect`] rank first, then `priority`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Higher priority breaks ties between same-effect matches.
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub subject: SubjectMatch,
    #[serde(default)]
    pub resource: ResourceMatch,
    #[serde(default)]
    pub condition: ConditionMatch,
    pub effect: Effect,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub approved_by: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Policy {
    /// True if this policy applies to the access described by `ctx`.
    pub fn applies(&self, ctx: &AccessContext) -> bool {
        self.enabled
            && self.subject.matches(ctx.record)
            && self.resource.matches(ctx)
            && self.condition.matches(ctx)
    }

    /// Basic structural validation for the authoring/approval lifecycle.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("policy id must not be empty".into());
        }
        // A degenerate empty-string entry in a pattern list matches unpredictably
        // (an empty selector means "any", but an empty *entry* in a non-empty list
        // is almost always an editing slip). Reject it so the intent is explicit.
        let lists: &[(&str, &[String])] = &[
            ("subject.users", &self.subject.users),
            ("subject.roles", &self.subject.roles),
            ("subject.groups", &self.subject.groups),
            ("subject.applications", &self.subject.applications),
            ("resource.databases", &self.resource.databases),
            ("resource.schemas", &self.resource.schemas),
            ("resource.objects", &self.resource.objects),
            ("resource.object_types", &self.resource.object_types),
            ("resource.columns", &self.resource.columns),
            (
                "resource.data_classifications",
                &self.resource.data_classifications,
            ),
            (
                "resource.data_subject_categories",
                &self.resource.data_subject_categories,
            ),
            ("condition.environments", &self.condition.environments),
            ("condition.operations", &self.condition.operations),
            (
                "condition.client_applications",
                &self.condition.client_applications,
            ),
            (
                "condition.client_ip_prefixes",
                &self.condition.client_ip_prefixes,
            ),
        ];
        for (name, list) in lists {
            if list.iter().any(|s| s.trim().is_empty()) {
                return Err(format!(
                    "{name} contains an empty pattern — remove it or give it a value"
                ));
            }
        }
        // A restrictive policy (deny / require-* / step-up / alert) that constrains
        // NOTHING matches every access — it would deny or flag all traffic, almost
        // certainly a mistake. Require at least one scope axis.
        if self.effect.is_restrictive()
            && self.subject.is_empty()
            && self.resource.is_empty()
            && self.condition.is_empty()
        {
            return Err(format!(
                "policy {:?} has a restrictive effect ({:?}) but no subject, resource, or \
                 condition scope — it would match every access; scope it",
                self.id, self.effect
            ));
        }
        Ok(())
    }

    /// The effect this policy actually produces for an access, after resolving
    /// requirement satisfaction (a satisfied Require* does not fire).
    fn effective(&self, ctx: &AccessContext) -> (Effect, Option<&'static str>) {
        match self.effect {
            Effect::RequireJustification => {
                if ctx.record.justification.is_present() {
                    (Effect::Allow, None)
                } else {
                    (Effect::RequireJustification, Some("justification"))
                }
            }
            Effect::RequireApproval => {
                // A blank approval_ref does not satisfy the requirement.
                if ctx
                    .record
                    .justification
                    .approval_ref
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                {
                    (Effect::Allow, None)
                } else {
                    (Effect::RequireApproval, Some("approval"))
                }
            }
            e => (e, None),
        }
    }
}

/// The resolved context of one access, evaluated against policies.
#[derive(Debug, Clone)]
pub struct AccessContext<'a> {
    pub record: &'a AuditRecord,
    /// Resolved read+written object names (from SQL analysis / catalog).
    pub objects: Vec<String>,
    /// Resolved column references.
    pub columns: Vec<String>,
    /// Weekday: 0 = Monday … 6 = Sunday.
    pub weekday: Option<u8>,
    /// Hour of day (0–23) in the evaluation timezone.
    pub hour: Option<u8>,
    /// Immutable evidence id for the access (the event_id).
    pub evidence_id: Option<String>,
}

impl<'a> AccessContext<'a> {
    /// Build a context that carries the SQL-resolved objects/columns and the
    /// timezone-naive (UTC) weekday/hour. `record` is borrowed by the caller.
    pub fn new(record: &'a AuditRecord) -> Self {
        AccessContext {
            record,
            objects: Vec::new(),
            columns: Vec::new(),
            weekday: None,
            hour: None,
            evidence_id: None,
        }
    }

    pub fn with_objects(mut self, objects: Vec<String>) -> Self {
        self.objects = objects;
        self
    }
    pub fn with_columns(mut self, columns: Vec<String>) -> Self {
        self.columns = columns;
        self
    }
    pub fn with_time(mut self, weekday: u8, hour: u8) -> Self {
        self.weekday = Some(weekday);
        self.hour = Some(hour);
        self
    }
    pub fn with_evidence(mut self, id: impl Into<String>) -> Self {
        self.evidence_id = Some(id.into());
        self
    }
}

/// Read the SQL-resolved objects the Phase-2 pg parser stored on an event
/// (`sql_read_tables`, `sql_written_tables`) plus the pgAudit object name.
pub fn objects_from_event(ev: &Event) -> Vec<String> {
    let mut out = BTreeSet::new();
    for key in ["sql_read_tables", "sql_written_tables"] {
        if let Some(v) = ev.field(key) {
            out.extend(
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        }
    }
    if let Some(o) = ev.field(keys::OBJECT_NAME) {
        out.insert(o.to_string());
    }
    out.into_iter().collect()
}

/// Build a full [`AccessContext`] from an event: the canonical record, the
/// SQL-resolved objects/columns, the UTC weekday/hour, and the event_id when
/// present. `record` must be `AuditRecord::from_event(ev)` held by the caller.
pub fn context_from_event<'a>(ev: &Event, record: &'a AuditRecord) -> AccessContext<'a> {
    use chrono::{Datelike, Timelike};
    let columns = ev
        .field("sql_columns")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let mut ctx = AccessContext::new(record)
        .with_objects(objects_from_event(ev))
        .with_columns(columns)
        .with_time(
            ev.ts.weekday().num_days_from_monday() as u8,
            ev.ts.hour() as u8,
        );
    if let Some(id) = ev.field("event_id") {
        ctx = ctx.with_evidence(id);
    }
    ctx
}

// -------------------------------------------------------------------------
// decision
// -------------------------------------------------------------------------

/// The explainable result of evaluating an access against a policy set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Effect,
    /// Ids of every policy that matched.
    pub matched_policies: Vec<String>,
    /// The id of the policy whose effect determined the decision.
    pub strongest_rule: Option<String>,
    pub subject: String,
    pub resource: String,
    pub action: String,
    /// Requirements that were unmet (`justification`, `approval`).
    pub missing_requirements: Vec<String>,
    pub reason: String,
    pub evidence_references: Vec<String>,
    /// The version of the strongest matched policy.
    pub policy_version: u32,
}

/// Evaluate an access against a policy set. When nothing matches, the decision is
/// [`Effect::Allow`] (add a low-priority catch-all `Deny` policy for
/// default-deny). Explicit `Deny` is the strongest possible outcome.
pub fn evaluate(ctx: &AccessContext, policies: &[Policy]) -> PolicyDecision {
    let r = ctx.record;
    let mut matched: Vec<&Policy> = Vec::new();
    let mut best: Option<(&Policy, Effect)> = None;
    let mut missing = BTreeSet::new();

    for p in policies {
        if !p.applies(ctx) {
            continue;
        }
        matched.push(p);
        let (eff, miss) = p.effective(ctx);
        if let Some(m) = miss {
            missing.insert(m.to_string());
        }
        best = match best {
            None => Some((p, eff)),
            Some((bp, be)) => {
                if eff.rank() > be.rank() || (eff.rank() == be.rank() && p.priority > bp.priority) {
                    Some((p, eff))
                } else {
                    Some((bp, be))
                }
            }
        };
    }

    let (decision, strongest_rule, policy_version) = match best {
        Some((p, eff)) => (eff, Some(p.id.clone()), p.version),
        None => (Effect::Allow, None, 0),
    };

    let object = ctx
        .objects
        .first()
        .cloned()
        .or_else(|| r.action.object_name.clone())
        .unwrap_or_default();
    let action = r
        .action
        .query_type
        .map(|q| q.as_str().to_string())
        .or_else(|| r.action.action.clone())
        .unwrap_or_default();

    let reason = match (&decision, &strongest_rule) {
        (Effect::Allow, None) => "no policy matched; allowed by default".to_string(),
        (d, Some(id)) => format!("policy '{id}' → {}", d.as_str()),
        (d, None) => d.as_str().to_string(),
    };

    let mut evidence_references = Vec::new();
    if let Some(id) = &ctx.evidence_id {
        evidence_references.push(id.clone());
    }

    PolicyDecision {
        decision,
        matched_policies: matched.iter().map(|p| p.id.clone()).collect(),
        strongest_rule,
        subject: r.actor.actor_id.clone(),
        resource: object,
        action,
        missing_requirements: missing.into_iter().collect(),
        reason,
        evidence_references,
        policy_version,
    }
}

/// A content digest of the enabled policies — the version anchor for the set.
pub fn policy_set_digest(policies: &[Policy]) -> String {
    let mut enabled: Vec<&Policy> = policies.iter().filter(|p| p.enabled).collect();
    enabled.sort_by(|a, b| a.id.cmp(&b.id));
    let json = serde_json::to_vec(&enabled).unwrap_or_default();
    format!("pol1:{}", &blake3::hash(&json).to_hex()[..32])
}

/// A content digest of a SINGLE policy — ALL of its fields, including `enabled` —
/// for a governed registry record's `content_digest`. Distinct from
/// [`policy_set_digest`] (which fingerprints the enforced *set* and deliberately
/// drops disabled policies), so a `disabled` draft still gets a content-unique
/// digest rather than the constant hash of the empty set.
pub fn policy_digest(policy: &Policy) -> String {
    let json = serde_json::to_vec(policy).unwrap_or_default();
    format!("polr1:{}", &blake3::hash(&json).to_hex()[..32])
}

// -------------------------------------------------------------------------
// simulation
// -------------------------------------------------------------------------

/// The result of replaying one proposed policy over historical accesses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationReport {
    pub evaluated: usize,
    pub matched: usize,
    pub allow: usize,
    pub deny: usize,
    pub require_justification: usize,
    pub require_approval: usize,
    pub alert: usize,
    pub step_up_review: usize,
    pub increase_risk: usize,
    pub affected_users: Vec<String>,
    pub affected_objects: Vec<String>,
    pub sample_event_ids: Vec<String>,
    /// Matched accesses that were restricted/flagged despite carrying a
    /// justification — a rough estimate of likely false positives.
    pub likely_false_positives: usize,
}

/// Replay one proposed `policy` over `contexts` and summarize its blast radius —
/// how many accesses match, what they resolve to, who and what is affected, and
/// a rough false-positive estimate. Run before a policy is approved.
pub fn simulate(policy: &Policy, contexts: &[AccessContext]) -> SimulationReport {
    const MAX_SAMPLES: usize = 20;
    let mut rep = SimulationReport {
        evaluated: contexts.len(),
        ..Default::default()
    };
    let mut users = BTreeSet::new();
    let mut objects = BTreeSet::new();

    for ctx in contexts {
        if !policy.applies(ctx) {
            continue;
        }
        rep.matched += 1;
        let (eff, _) = policy.effective(ctx);
        match eff {
            Effect::Allow => rep.allow += 1,
            Effect::Deny => rep.deny += 1,
            Effect::RequireJustification => rep.require_justification += 1,
            Effect::RequireApproval => rep.require_approval += 1,
            Effect::Alert => rep.alert += 1,
            Effect::StepUpReview => rep.step_up_review += 1,
            Effect::IncreaseRisk => rep.increase_risk += 1,
        }
        if eff.is_restrictive() && ctx.record.justification.is_present() {
            rep.likely_false_positives += 1;
        }
        if !ctx.record.actor.actor_id.is_empty() {
            users.insert(ctx.record.actor.actor_id.clone());
        }
        objects.extend(ctx.objects.iter().cloned());
        if let Some(id) = &ctx.evidence_id {
            if rep.sample_event_ids.len() < MAX_SAMPLES {
                rep.sample_event_ids.push(id.clone());
            }
        }
    }
    rep.affected_users = users.into_iter().collect();
    rep.affected_objects = objects.into_iter().collect();
    rep
}

#[cfg(test)]
mod tests;
