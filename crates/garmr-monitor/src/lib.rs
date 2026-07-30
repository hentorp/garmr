// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 6 — user monitoring & watchlists.
//!
//! This crate answers a different question from either anomaly detection ("is
//! this unusual?") or the [policy engine](../garmr_policy) ("is this allowed?").
//! It answers "should we be paying *closer attention* to this actor right now?"
//! — a human-authored, time-bounded, fully attributable judgement recorded as a
//! [`UserMonitoringProfile`].
//!
//! ## Monitoring RAISES attention; it never declares guilt
//!
//! This is the load-bearing invariant of the whole crate. Placing someone under
//! monitoring must never, by itself, make an access look *malicious* — only
//! *more worth reviewing*. Concretely: [`sensitivity_multiplier`] returns a
//! factor that is **never below `1.0`** for any state. A watched actor's risk
//! score is scaled *up* (so their events surface sooner in triage) but a benign
//! access stays benign — the multiplier can amplify a signal, it can never
//! manufacture one from nothing, and it can never suppress attention either.
//! Being watched is an investigative posture, not a verdict.
//!
//! ## A profile watches a TARGET, not only a single user
//!
//! A [`MonitoringTarget`] lets one profile cover a single user, an entire role
//! or group, everyone using one application, or everyone touching one sensitive
//! resource. A profile [`applies`](UserMonitoringProfile::applies_to_access) to
//! an access when its target matches the access's actor / role / groups /
//! application / objects, and the access falls inside the profile's
//! `application_scope` / `resource_scope` (empty scope = no constraint).
//!
//! ## Every change is attributable and versioned
//!
//! There is no anonymous mutation. [`MonitoringRegistry::start_monitoring`],
//! [`update`](MonitoringRegistry::update),
//! [`stop_monitoring`](MonitoringRegistry::stop_monitoring) and
//! [`restrict_scope`](MonitoringRegistry::restrict_scope) each require a named
//! actor, bump the profile's `version`, and return an audited
//! [`MonitoringChange`] that links to the audit ledger via `audit_ref`.
//!
//! Pure, no I/O. Persistence (versioned, human-approved, reversible) rides the
//! existing registry-governance channel; this crate is the evaluation core.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use garmr_core::AuditRecord;
use serde::{Deserialize, Serialize};

// -------------------------------------------------------------------------
// monitoring state
// -------------------------------------------------------------------------

/// How closely an actor is being watched. States escalate in the attention they
/// warrant; the escalation is reflected by [`sensitivity_multiplier`], which is
/// always `>= 1.0` — monitoring only raises attention, it never declares guilt.
///
/// [`Retired`](MonitoringState::Retired) is the terminal, inactive state (the
/// monitoring has ended). [`Other`](MonitoringState::Other) is the
/// forward-compatible catch-all so a future, stronger state read from persisted
/// data deserializes cleanly instead of failing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitoringState {
    /// The default: no special attention.
    #[default]
    Normal,
    /// On a watchlist — surface this actor's events a little sooner.
    Watched,
    /// Heightened scrutiny, short of a formal investigation.
    ElevatedMonitoring,
    /// A formal investigation is open on this actor.
    Investigation,
    /// The actor's access is restricted; the strongest attention posture.
    Restricted,
    /// Monitoring has ended — inactive, retained for history.
    Retired,
    /// Forward-compatible catch-all for an unrecognized persisted state.
    #[serde(other)]
    Other,
}

impl MonitoringState {
    /// A rank where a higher value means "watch more closely". Used to select
    /// the strongest applicable profile. Inactive/unknown states rank `0`.
    fn rank(self) -> u8 {
        match self {
            MonitoringState::Normal | MonitoringState::Retired | MonitoringState::Other => 0,
            MonitoringState::Watched => 1,
            MonitoringState::ElevatedMonitoring => 2,
            MonitoringState::Investigation => 3,
            MonitoringState::Restricted => 4,
        }
    }

    /// The snake_case wire label for this state.
    pub fn as_str(self) -> &'static str {
        match self {
            MonitoringState::Normal => "normal",
            MonitoringState::Watched => "watched",
            MonitoringState::ElevatedMonitoring => "elevated_monitoring",
            MonitoringState::Investigation => "investigation",
            MonitoringState::Restricted => "restricted",
            MonitoringState::Retired => "retired",
            MonitoringState::Other => "other",
        }
    }

    /// True for states that keep a profile live (everything except the terminal
    /// [`Retired`](MonitoringState::Retired)). Note this is only the *state*
    /// half of activeness; time-window expiry is handled by
    /// [`UserMonitoringProfile::is_active`].
    pub fn is_active_state(self) -> bool {
        !matches!(self, MonitoringState::Retired)
    }

    /// The attention multiplier for this state — see the crate docs.
    ///
    /// **Never below `1.0`.** Monitoring raises attention; it does not declare
    /// guilt and must not be able to suppress it either.
    pub fn sensitivity_multiplier(self) -> f64 {
        sensitivity_multiplier(self)
    }
}

/// The attention multiplier for a monitoring state.
///
/// `Normal` (and the inactive `Retired` / unknown `Other`) yield exactly `1.0`;
/// the active watch states escalate strictly:
/// `Watched < ElevatedMonitoring < Investigation < Restricted`.
///
/// The return value is **guaranteed `>= 1.0`** for every state, present and
/// future — this is the "monitoring only RAISES attention, never declares
/// guilt" invariant that downstream risk scoring relies on: it may scale a
/// signal up, never down, and never below neutral.
pub fn sensitivity_multiplier(state: MonitoringState) -> f64 {
    match state {
        MonitoringState::Normal | MonitoringState::Retired | MonitoringState::Other => 1.0,
        MonitoringState::Watched => 1.25,
        MonitoringState::ElevatedMonitoring => 1.5,
        MonitoringState::Investigation => 2.0,
        MonitoringState::Restricted => 2.5,
    }
}

// -------------------------------------------------------------------------
// monitoring target
// -------------------------------------------------------------------------

/// What a profile watches. One profile can cover a single user, everyone in a
/// role or group, everyone using an application, or everyone touching a given
/// resource. Matching is case-insensitive; [`Resource`](MonitoringTarget::Resource)
/// additionally supports the same object patterns as the policy engine
/// (`schema.*` wildcard, and an unqualified name matching the last dotted
/// segment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitoringTarget {
    /// A single actor id.
    User(String),
    /// Everyone whose `actor_role` matches.
    Role(String),
    /// Everyone who is a member of this group.
    Group(String),
    /// Everyone acting through this application.
    Application(String),
    /// Everyone touching an object matching this resource pattern.
    Resource(String),
}

impl MonitoringTarget {
    /// The inner selector string.
    pub fn value(&self) -> &str {
        match self {
            MonitoringTarget::User(v)
            | MonitoringTarget::Role(v)
            | MonitoringTarget::Group(v)
            | MonitoringTarget::Application(v)
            | MonitoringTarget::Resource(v) => v,
        }
    }

    /// A stable label for the kind of target (used in digests and change logs).
    pub fn kind(&self) -> &'static str {
        match self {
            MonitoringTarget::User(_) => "user",
            MonitoringTarget::Role(_) => "role",
            MonitoringTarget::Group(_) => "group",
            MonitoringTarget::Application(_) => "application",
            MonitoringTarget::Resource(_) => "resource",
        }
    }

    /// Whether this target matches a bare user id. Only a
    /// [`User`](MonitoringTarget::User) target can be resolved from an id alone
    /// — role/group/application/resource targets need the full access context,
    /// so they never match a user-only lookup.
    pub fn matches_user(&self, user_id: &str) -> bool {
        match self {
            MonitoringTarget::User(u) => u.eq_ignore_ascii_case(user_id),
            _ => false,
        }
    }

    /// Whether this target matches an access. `objects` carries any SQL/catalog
    /// resolved object names for the access (pass `&[]` when none are known);
    /// the record's own `object_name` / `resource_path` are always considered
    /// too.
    pub fn matches_access(&self, r: &AuditRecord, objects: &[String]) -> bool {
        match self {
            MonitoringTarget::User(u) => u.eq_ignore_ascii_case(&r.actor.actor_id),
            MonitoringTarget::Role(role) => r
                .actor
                .actor_role
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case(role)),
            MonitoringTarget::Group(g) => r
                .actor
                .actor_groups
                .iter()
                .any(|m| m.eq_ignore_ascii_case(g)),
            MonitoringTarget::Application(app) => r
                .context
                .application_name
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case(app)),
            MonitoringTarget::Resource(pat) => access_touches(pat, r, objects),
        }
    }
}

/// True if any object the access touched matches the resource `pattern`.
fn access_touches(pattern: &str, r: &AuditRecord, objects: &[String]) -> bool {
    let hit = |obj: &str| object_pattern_matches(pattern, obj);
    objects.iter().any(|o| hit(o))
        || r.action.object_name.as_deref().is_some_and(hit)
        || r.action.resource_path.as_deref().is_some_and(hit)
}

/// Match an object pattern against an accessed object name — the same semantics
/// as the policy engine: exact (case-insensitive), a schema wildcard (`raw.*`
/// matches `raw.anything`), and an unqualified name matching the last dotted
/// segment (`persons` matches `public.persons`).
fn object_pattern_matches(pattern: &str, obj: &str) -> bool {
    let (p, o) = (pattern.to_ascii_lowercase(), obj.to_ascii_lowercase());
    if p == o {
        return true;
    }
    if let Some(prefix) = p.strip_suffix(".*") {
        return o == prefix || o.starts_with(&format!("{prefix}."));
    }
    !p.contains('.') && o.rsplit('.').next() == Some(p.as_str())
}

// -------------------------------------------------------------------------
// monitoring profile
// -------------------------------------------------------------------------

/// A human-authored, time-bounded, versioned decision to watch a target more
/// closely. See the crate docs for the "raises attention, never declares guilt"
/// and "no anonymous change" contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserMonitoringProfile {
    /// The primary human-facing subject of the profile. For a
    /// [`User`](MonitoringTarget::User) target this equals the target value; for
    /// broader targets it is a descriptive label (e.g. the role/group name).
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// What this profile watches. A profile is located by exact target for
    /// mutation, and matched fuzzily for evaluation.
    pub target: MonitoringTarget,
    pub state: MonitoringState,
    /// Why the target is being monitored (free text, human-authored).
    #[serde(default)]
    pub reason: String,
    /// A coarse risk band, kept as a free string so it can carry whatever
    /// vocabulary the deployment uses (`low`/`medium`/`high`, a tier name, …).
    #[serde(default)]
    pub risk_level: String,
    /// When the profile takes effect (inclusive).
    pub valid_from: DateTime<Utc>,
    /// When the profile expires (inclusive). `None` = open-ended. A profile with
    /// `valid_until < now` is inactive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Applications this profile is scoped to (empty = every application).
    #[serde(default)]
    pub application_scope: Vec<String>,
    /// Resource patterns this profile is scoped to (empty = every resource).
    #[serde(default)]
    pub resource_scope: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    /// Who created the profile — attribution is mandatory (no anonymous change).
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// Bumped on every mutation.
    #[serde(default)]
    pub version: u32,
    /// References into the audit ledger for every change to this profile.
    #[serde(default)]
    pub audit_refs: Vec<String>,
}

impl UserMonitoringProfile {
    /// Build a minimal profile for `target` in `state`, effective from
    /// `valid_from`, attributed to `created_by`. Optional fields default; refine
    /// with the `with_*` setters. Version starts at `1`.
    pub fn new(
        target: MonitoringTarget,
        state: MonitoringState,
        valid_from: DateTime<Utc>,
        created_by: impl Into<String>,
    ) -> Self {
        let user_id = target.value().to_string();
        UserMonitoringProfile {
            user_id,
            display_name: None,
            target,
            state,
            reason: String::new(),
            risk_level: String::new(),
            valid_from,
            valid_until: None,
            application_scope: Vec::new(),
            resource_scope: Vec::new(),
            tags: Vec::new(),
            notes: String::new(),
            created_by: created_by.into(),
            approved_by: None,
            version: 1,
            audit_refs: Vec::new(),
        }
    }

    /// Set the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
    /// Set the risk band.
    pub fn with_risk_level(mut self, risk_level: impl Into<String>) -> Self {
        self.risk_level = risk_level.into();
        self
    }
    /// Set an expiry.
    pub fn with_valid_until(mut self, valid_until: DateTime<Utc>) -> Self {
        self.valid_until = Some(valid_until);
        self
    }
    /// Constrain to a set of applications.
    pub fn with_application_scope(mut self, scope: Vec<String>) -> Self {
        self.application_scope = scope;
        self
    }
    /// Constrain to a set of resource patterns.
    pub fn with_resource_scope(mut self, scope: Vec<String>) -> Self {
        self.resource_scope = scope;
        self
    }
    /// Record who approved the profile.
    pub fn with_approved_by(mut self, approved_by: impl Into<String>) -> Self {
        self.approved_by = Some(approved_by.into());
        self
    }

    /// True if the profile is live at `now`: its state is not
    /// [`Retired`](MonitoringState::Retired), and `now` is within
    /// `[valid_from, valid_until]` (an unset `valid_until` is open-ended). A
    /// future-dated (`valid_from > now`) or expired (`valid_until < now`)
    /// profile is inactive.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.state.is_active_state()
            && self.valid_from <= now
            && self.valid_until.is_none_or(|until| now <= until)
    }

    /// The attention multiplier this profile currently contributes: its state's
    /// [`sensitivity_multiplier`] while active, else the neutral `1.0`.
    pub fn active_multiplier(&self, now: DateTime<Utc>) -> f64 {
        if self.is_active(now) {
            self.state.sensitivity_multiplier()
        } else {
            1.0
        }
    }

    /// True if this profile applies to a bare user lookup at `now`: it is active
    /// and its target matches the user id. Per-access scopes are not evaluated
    /// here (there is no access to scope against) — they apply in
    /// [`applies_to_access`](Self::applies_to_access).
    pub fn applies_to_user(&self, user_id: &str, now: DateTime<Utc>) -> bool {
        self.is_active(now) && self.target.matches_user(user_id)
    }

    /// True if this profile applies to an access at `now`: it is active, its
    /// target matches the access, and the access falls inside the profile's
    /// application/resource scope (empty scope = no constraint).
    pub fn applies_to_access(
        &self,
        r: &AuditRecord,
        objects: &[String],
        now: DateTime<Utc>,
    ) -> bool {
        self.is_active(now)
            && self.target.matches_access(r, objects)
            && application_in_scope(&self.application_scope, r)
            && resource_in_scope(&self.resource_scope, r, objects)
    }
}

/// True if the access's application is within `scope` (empty scope = any).
fn application_in_scope(scope: &[String], r: &AuditRecord) -> bool {
    if scope.is_empty() {
        return true;
    }
    r.context
        .application_name
        .as_deref()
        .is_some_and(|app| scope.iter().any(|s| s.eq_ignore_ascii_case(app)))
}

/// True if any object the access touched is within the resource `scope` (empty
/// scope = any).
fn resource_in_scope(scope: &[String], r: &AuditRecord, objects: &[String]) -> bool {
    if scope.is_empty() {
        return true;
    }
    scope.iter().any(|p| access_touches(p, r, objects))
}

// -------------------------------------------------------------------------
// change record
// -------------------------------------------------------------------------

/// An audited, attributable record of one monitoring-state change. Emitted by
/// every registry mutation; `audit_ref` links it to the audit ledger, and
/// `actor` names who made the change (never empty — there is no anonymous
/// change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringChange {
    /// Deterministic content id (`chg-` + a blake3 prefix over the change).
    pub change_id: String,
    pub target: MonitoringTarget,
    pub from_state: MonitoringState,
    pub to_state: MonitoringState,
    pub reason: String,
    /// Who made the change. Mandatory.
    pub actor: String,
    pub at: DateTime<Utc>,
    /// Reference into the audit ledger for this change.
    pub audit_ref: String,
}

impl MonitoringChange {
    /// Assemble a change and derive its deterministic `change_id` from its
    /// content, so the same change always carries the same id.
    fn new(
        target: MonitoringTarget,
        from_state: MonitoringState,
        to_state: MonitoringState,
        reason: String,
        actor: String,
        at: DateTime<Utc>,
        audit_ref: String,
    ) -> Self {
        let seed = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            target.kind(),
            target.value(),
            from_state.as_str(),
            to_state.as_str(),
            actor,
            at.to_rfc3339(),
            audit_ref,
        );
        let change_id = format!("chg-{}", &blake3::hash(seed.as_bytes()).to_hex()[..16]);
        MonitoringChange {
            change_id,
            target,
            from_state,
            to_state,
            reason,
            actor,
            at,
            audit_ref,
        }
    }
}

// -------------------------------------------------------------------------
// errors
// -------------------------------------------------------------------------

/// Why a monitoring mutation was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitoringError {
    /// The actor attribution was empty — no anonymous change is permitted.
    EmptyActor,
    /// The profile failed structural validation (message explains why).
    InvalidProfile(String),
    /// A profile already exists for the target (use `update` instead).
    AlreadyExists(String),
    /// No profile exists for the target.
    NotFound(String),
}

impl std::fmt::Display for MonitoringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitoringError::EmptyActor => {
                write!(
                    f,
                    "monitoring change requires a named actor (no anonymous change)"
                )
            }
            MonitoringError::InvalidProfile(msg) => write!(f, "invalid monitoring profile: {msg}"),
            MonitoringError::AlreadyExists(t) => {
                write!(f, "a monitoring profile already exists for target '{t}'")
            }
            MonitoringError::NotFound(t) => {
                write!(f, "no monitoring profile for target '{t}'")
            }
        }
    }
}

impl std::error::Error for MonitoringError {}

// -------------------------------------------------------------------------
// change metadata
// -------------------------------------------------------------------------

/// The attribution a mutation must carry: who made it (`actor`, never empty),
/// when (`at`), and the audit-ledger reference (`audit_ref`) the resulting
/// [`MonitoringChange`] links to. Bundling these keeps every mutation
/// attributable through one value — there is no anonymous change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeMeta {
    /// Who is making the change. Mandatory — an empty actor is rejected.
    pub actor: String,
    /// When the change is made.
    pub at: DateTime<Utc>,
    /// The audit-ledger reference for this change.
    pub audit_ref: String,
}

impl ChangeMeta {
    /// Assemble change metadata.
    pub fn new(actor: impl Into<String>, at: DateTime<Utc>, audit_ref: impl Into<String>) -> Self {
        ChangeMeta {
            actor: actor.into(),
            at,
            audit_ref: audit_ref.into(),
        }
    }

    fn require_actor(&self) -> Result<(), MonitoringError> {
        if self.actor.trim().is_empty() {
            Err(MonitoringError::EmptyActor)
        } else {
            Ok(())
        }
    }
}

// -------------------------------------------------------------------------
// registry
// -------------------------------------------------------------------------

/// A set of monitoring profiles plus the resolution and mutation logic over
/// them. The registry never watches by default: with no profile, every actor is
/// [`Normal`](MonitoringState::Normal) with a neutral `1.0` multiplier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringRegistry {
    profiles: Vec<UserMonitoringProfile>,
}

impl MonitoringRegistry {
    /// An empty registry — everyone is `Normal`.
    pub fn new() -> Self {
        MonitoringRegistry::default()
    }

    /// Build a registry from existing profiles (e.g. loaded from persistence).
    pub fn with_profiles(profiles: Vec<UserMonitoringProfile>) -> Self {
        MonitoringRegistry { profiles }
    }

    /// All profiles, in insertion order.
    pub fn profiles(&self) -> &[UserMonitoringProfile] {
        &self.profiles
    }

    /// The attention multiplier for a state — see [`sensitivity_multiplier`].
    /// Always `>= 1.0`: monitoring raises attention, it never declares guilt.
    pub fn sensitivity_multiplier(state: MonitoringState) -> f64 {
        sensitivity_multiplier(state)
    }

    /// The strongest active profile watching `user_id` at `now`, if any. "Bare
    /// user" resolution only considers [`User`](MonitoringTarget::User) targets;
    /// broader targets need an access. Scopes are not applied here.
    pub fn active_for_user(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Option<&UserMonitoringProfile> {
        self.strongest(
            self.profiles
                .iter()
                .filter(|p| p.applies_to_user(user_id, now)),
        )
    }

    /// The strongest active profile applying to an access at `now`, if any.
    /// `objects` carries any resolved object names for the access (pass `&[]`
    /// when none). Considers every target kind and honours per-profile scope.
    pub fn active_for_access(
        &self,
        r: &AuditRecord,
        objects: &[String],
        now: DateTime<Utc>,
    ) -> Option<&UserMonitoringProfile> {
        self.strongest(
            self.profiles
                .iter()
                .filter(|p| p.applies_to_access(r, objects, now)),
        )
    }

    /// The attention multiplier for `user_id` at `now`: the strongest active
    /// profile's, or the neutral `1.0` when none applies.
    pub fn multiplier_for_user(&self, user_id: &str, now: DateTime<Utc>) -> f64 {
        self.active_for_user(user_id, now)
            .map_or(1.0, |p| p.state.sensitivity_multiplier())
    }

    /// The attention multiplier for an access at `now`: the strongest active
    /// profile's, or the neutral `1.0` when none applies.
    pub fn multiplier_for_access(
        &self,
        r: &AuditRecord,
        objects: &[String],
        now: DateTime<Utc>,
    ) -> f64 {
        self.active_for_access(r, objects, now)
            .map_or(1.0, |p| p.state.sensitivity_multiplier())
    }

    /// Pick the strongest profile from a candidate iterator: highest state rank
    /// first, then most recently versioned, then most recently effective — a
    /// total, deterministic order.
    fn strongest<'a>(
        &self,
        candidates: impl Iterator<Item = &'a UserMonitoringProfile>,
    ) -> Option<&'a UserMonitoringProfile> {
        candidates.max_by(|a, b| {
            a.state
                .rank()
                .cmp(&b.state.rank())
                .then(a.version.cmp(&b.version))
                .then(a.valid_from.cmp(&b.valid_from))
        })
    }

    /// Locate the profile whose target exactly equals `target`.
    fn find_mut(&mut self, target: &MonitoringTarget) -> Option<&mut UserMonitoringProfile> {
        self.profiles.iter_mut().find(|p| &p.target == target)
    }

    // ---- mutations (each attributable, version-bumping, audited) ----

    /// Register a new monitoring profile. Fails if `created_by` is empty (no
    /// anonymous change) or a profile for the same target already exists. The
    /// profile's `version` is forced to at least `1`, `audit_ref` is appended to
    /// its `audit_refs`, and an audited [`MonitoringChange`] from
    /// [`Normal`](MonitoringState::Normal) to the profile's state is returned.
    pub fn start_monitoring(
        &mut self,
        mut profile: UserMonitoringProfile,
        at: DateTime<Utc>,
        audit_ref: impl Into<String>,
    ) -> Result<MonitoringChange, MonitoringError> {
        if profile.created_by.trim().is_empty() {
            return Err(MonitoringError::EmptyActor);
        }
        if profile.user_id.trim().is_empty() && profile.target.value().trim().is_empty() {
            return Err(MonitoringError::InvalidProfile(
                "target and user_id must not both be empty".into(),
            ));
        }
        if self.profiles.iter().any(|p| p.target == profile.target) {
            return Err(MonitoringError::AlreadyExists(
                profile.target.value().to_string(),
            ));
        }

        let audit_ref = audit_ref.into();
        profile.version = profile.version.max(1);
        profile.audit_refs.push(audit_ref.clone());

        let change = MonitoringChange::new(
            profile.target.clone(),
            MonitoringState::Normal,
            profile.state,
            profile.reason.clone(),
            profile.created_by.clone(),
            at,
            audit_ref,
        );
        self.profiles.push(profile);
        Ok(change)
    }

    /// Transition an existing profile to `new_state`. Fails if `meta.actor` is
    /// empty or no profile matches the target. Bumps `version`, updates
    /// `reason`, appends `meta.audit_ref`, and returns the audited change.
    pub fn update(
        &mut self,
        target: &MonitoringTarget,
        new_state: MonitoringState,
        reason: impl Into<String>,
        meta: ChangeMeta,
    ) -> Result<MonitoringChange, MonitoringError> {
        meta.require_actor()?;
        let reason = reason.into();
        let profile = self
            .find_mut(target)
            .ok_or_else(|| MonitoringError::NotFound(target.value().to_string()))?;

        let from_state = profile.state;
        profile.state = new_state;
        profile.reason = reason.clone();
        profile.version += 1;
        profile.audit_refs.push(meta.audit_ref.clone());

        Ok(MonitoringChange::new(
            target.clone(),
            from_state,
            new_state,
            reason,
            meta.actor,
            meta.at,
            meta.audit_ref,
        ))
    }

    /// End monitoring for a target: transition it to
    /// [`Retired`](MonitoringState::Retired) (which makes it inactive) while
    /// keeping the profile for history. Fails if `meta.actor` is empty or the
    /// target is unknown. Bumps `version`, appends `meta.audit_ref`, returns the
    /// change.
    pub fn stop_monitoring(
        &mut self,
        target: &MonitoringTarget,
        reason: impl Into<String>,
        meta: ChangeMeta,
    ) -> Result<MonitoringChange, MonitoringError> {
        self.update(target, MonitoringState::Retired, reason, meta)
    }

    /// Narrow *where* a profile's monitoring applies by adding application and/or
    /// resource scope constraints (this restricts the profile's reach; it does
    /// NOT change the monitoring *state* — that is what
    /// [`update`](Self::update) is for, including moving to
    /// [`Restricted`](MonitoringState::Restricted)). Fails if `meta.actor` is
    /// empty or the target is unknown. Bumps `version`, appends `meta.audit_ref`,
    /// and returns a change whose `from_state == to_state`.
    pub fn restrict_scope(
        &mut self,
        target: &MonitoringTarget,
        application_scope: Vec<String>,
        resource_scope: Vec<String>,
        reason: impl Into<String>,
        meta: ChangeMeta,
    ) -> Result<MonitoringChange, MonitoringError> {
        meta.require_actor()?;
        let reason = reason.into();
        let profile = self
            .find_mut(target)
            .ok_or_else(|| MonitoringError::NotFound(target.value().to_string()))?;

        extend_dedup(&mut profile.application_scope, application_scope);
        extend_dedup(&mut profile.resource_scope, resource_scope);
        profile.reason = reason.clone();
        profile.version += 1;
        profile.audit_refs.push(meta.audit_ref.clone());
        let state = profile.state;

        Ok(MonitoringChange::new(
            target.clone(),
            state,
            state,
            reason,
            meta.actor,
            meta.at,
            meta.audit_ref,
        ))
    }

    /// A content digest over the active (non-[`Retired`](MonitoringState::Retired))
    /// profiles — the version anchor for the watchlist set. Order-independent:
    /// profiles are sorted by a stable key before hashing. Because expiry is
    /// time-relative, the digest reflects state-activeness only, not the
    /// `valid_until` window.
    pub fn digest(&self) -> String {
        let mut active: Vec<&UserMonitoringProfile> = self
            .profiles
            .iter()
            .filter(|p| p.state.is_active_state())
            .collect();
        active.sort_by_key(|p| sort_key(p));
        let json = serde_json::to_vec(&active).unwrap_or_default();
        format!("mon1:{}", &blake3::hash(&json).to_hex()[..32])
    }
}

/// A stable sort key for a profile within a digest.
fn sort_key(p: &UserMonitoringProfile) -> (String, String, String, u32) {
    (
        p.target.kind().to_string(),
        p.target.value().to_ascii_lowercase(),
        p.user_id.to_ascii_lowercase(),
        p.version,
    )
}

/// Append the items of `add` to `into`, skipping case-insensitive duplicates.
fn extend_dedup(into: &mut Vec<String>, add: Vec<String>) {
    let mut seen: BTreeSet<String> = into.iter().map(|s| s.to_ascii_lowercase()).collect();
    for item in add {
        let key = item.to_ascii_lowercase();
        if seen.insert(key) {
            into.push(item);
        }
    }
}

#[cfg(test)]
mod tests;
