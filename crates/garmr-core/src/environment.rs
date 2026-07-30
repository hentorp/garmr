// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 5 — the temporal, bitemporal environment model.
//!
//! A learned, trustworthy model of "normal" for the monitored environment — the
//! entities (hosts, IPs, identities, services, …), the facts about them, and the
//! relations between them — WITHOUT letting an attacker (or an open case) teach
//! it. The model is governed exactly like the Phase 4 registry:
//!
//!   * facts are content-addressed by a stable [`fact_id`] that EXCLUDES the
//!     value (so competing values of one attribute — `role=router` vs
//!     `role=server` — share one id and conflict-resolution picks among them) and
//!     INCLUDES the relation target (so `host runs_on ip1` and `host runs_on ip2`
//!     are distinct facts that can both be true);
//!   * evidence is an APPEND-ONLY stream of [`FactObservation`]s (bitemporal:
//!     valid-time `valid_from`/`valid_to` × transaction-time `recorded_at`);
//!   * the promotion state ([`FactState`]) is a separate APPEND-ONLY stream of
//!     audit-bound [`FactTransition`]s folded to a current view — a rollback or a
//!     retirement is another append, never a mutation.
//!
//! The hard invariant (enforced in the CLI/API layer, which owns the audit
//! ledger, and defended on read here): **a fact becomes Trusted (or any other
//! PROTECTED state) only through a transition that carries a real audit event.**
//! A protected transition with an empty `audit_id` is inert on read (see
//! [`current_transition`]), and an unknown/garbage state string decodes to
//! [`FactState::Unknown`], never a spurious `Trusted` — so a hand-forged redb row
//! can never make a fact live.
//!
//! This module is pure (no I/O): the store persists the streams, the CLI mints
//! audit ids and appends, and these types + folds derive the current and
//! as-of-`T` views. The anti-poisoning gate ([`may_auto_promote`] /
//! [`may_analyst_promote`]) is likewise pure — its inputs (open cases,
//! compromised entities) are built by the store layer.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::frame;

/// The kind of entity a fact is about. `Unknown` is the forward-compat catch-all
/// (a newer writer's kind decodes to `Unknown`, never an error).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Asset,
    Host,
    Device,
    NetworkInterface,
    Ip,
    Mac,
    Identity,
    ServiceAccount,
    Group,
    Role,
    Process,
    Binary,
    Software,
    Service,
    Application,
    Database,
    Container,
    Cluster,
    Certificate,
    NetworkZone,
    DataSource,
    /// A maintenance/change window (used by the anti-poisoning discipline to tell
    /// expected change from anomaly).
    ChangeRecord,
    Owner,
    #[default]
    #[serde(other)]
    Unknown,
}

impl EntityKind {
    /// Stable lowercase tag used in fact ids, redb keys, and the CLI/API.
    pub fn tag(self) -> &'static str {
        match self {
            EntityKind::Asset => "asset",
            EntityKind::Host => "host",
            EntityKind::Device => "device",
            EntityKind::NetworkInterface => "network_interface",
            EntityKind::Ip => "ip",
            EntityKind::Mac => "mac",
            EntityKind::Identity => "identity",
            EntityKind::ServiceAccount => "service_account",
            EntityKind::Group => "group",
            EntityKind::Role => "role",
            EntityKind::Process => "process",
            EntityKind::Binary => "binary",
            EntityKind::Software => "software",
            EntityKind::Service => "service",
            EntityKind::Application => "application",
            EntityKind::Database => "database",
            EntityKind::Container => "container",
            EntityKind::Cluster => "cluster",
            EntityKind::Certificate => "certificate",
            EntityKind::NetworkZone => "network_zone",
            EntityKind::DataSource => "data_source",
            EntityKind::ChangeRecord => "change_record",
            EntityKind::Owner => "owner",
            EntityKind::Unknown => "unknown",
        }
    }

    /// Parse a CLI/API tag into a kind (`None` for an unrecognized tag).
    pub fn from_tag(s: &str) -> Option<EntityKind> {
        let k = match s.trim().to_ascii_lowercase().as_str() {
            "asset" => EntityKind::Asset,
            "host" => EntityKind::Host,
            "device" => EntityKind::Device,
            "network_interface" => EntityKind::NetworkInterface,
            "ip" => EntityKind::Ip,
            "mac" => EntityKind::Mac,
            "identity" => EntityKind::Identity,
            "service_account" => EntityKind::ServiceAccount,
            "group" => EntityKind::Group,
            "role" => EntityKind::Role,
            "process" => EntityKind::Process,
            "binary" => EntityKind::Binary,
            "software" => EntityKind::Software,
            "service" => EntityKind::Service,
            "application" => EntityKind::Application,
            "database" => EntityKind::Database,
            "container" => EntityKind::Container,
            "cluster" => EntityKind::Cluster,
            "certificate" => EntityKind::Certificate,
            "network_zone" => EntityKind::NetworkZone,
            "data_source" => EntityKind::DataSource,
            "change_record" => EntityKind::ChangeRecord,
            "owner" => EntityKind::Owner,
            _ => return None,
        };
        Some(k)
    }
}

/// A typed relation between two entities. `Unknown` is the forward-compat
/// catch-all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    RunsOn,
    ConnectsTo,
    AuthenticatesTo,
    Administers,
    MemberOf,
    BelongsToZone,
    DependsOn,
    UsesCertificate,
    OwnedBy,
    ObservedBy,
    ChangedBy,
    CommunicatesWith,
    #[default]
    #[serde(other)]
    Unknown,
}

impl RelationKind {
    /// Stable lowercase tag (used in the fact id and CLI/API).
    pub fn tag(self) -> &'static str {
        match self {
            RelationKind::RunsOn => "runs_on",
            RelationKind::ConnectsTo => "connects_to",
            RelationKind::AuthenticatesTo => "authenticates_to",
            RelationKind::Administers => "administers",
            RelationKind::MemberOf => "member_of",
            RelationKind::BelongsToZone => "belongs_to_zone",
            RelationKind::DependsOn => "depends_on",
            RelationKind::UsesCertificate => "uses_certificate",
            RelationKind::OwnedBy => "owned_by",
            RelationKind::ObservedBy => "observed_by",
            RelationKind::ChangedBy => "changed_by",
            RelationKind::CommunicatesWith => "communicates_with",
            RelationKind::Unknown => "unknown",
        }
    }

    /// Parse a tag (`None` for an unrecognized one).
    pub fn from_tag(s: &str) -> Option<RelationKind> {
        let k = match s.trim().to_ascii_lowercase().as_str() {
            "runs_on" => RelationKind::RunsOn,
            "connects_to" => RelationKind::ConnectsTo,
            "authenticates_to" => RelationKind::AuthenticatesTo,
            "administers" => RelationKind::Administers,
            "member_of" => RelationKind::MemberOf,
            "belongs_to_zone" => RelationKind::BelongsToZone,
            "depends_on" => RelationKind::DependsOn,
            "uses_certificate" => RelationKind::UsesCertificate,
            "owned_by" => RelationKind::OwnedBy,
            "observed_by" => RelationKind::ObservedBy,
            "changed_by" => RelationKind::ChangedBy,
            "communicates_with" => RelationKind::CommunicatesWith,
            _ => return None,
        };
        Some(k)
    }
}

/// The promotion ladder. `Unknown` is BOTH the default AND the `serde(other)`
/// catch-all, so a garbage or future state string decodes to `Unknown` — never a
/// spurious `Trusted`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactState {
    /// Observed but not yet trusted — quarantined, gated, never read as "normal".
    Candidate,
    /// The blessed baseline — the only state detection reads as "normal".
    Trusted,
    /// Flagged for review; excluded from "normal".
    Suspicious,
    /// Confirmed bad; excluded from "normal" and marks the entity compromised.
    KnownMalicious,
    /// Expired/withdrawn; no longer live.
    Retired,
    /// Forward-compat catch-all AND the default: a garbage or future state string
    /// decodes here, never to a spurious `Trusted`. `#[serde(other)]` requires the
    /// last position; `#[default]` makes an absent state safe.
    #[default]
    #[serde(other)]
    Unknown,
}

impl FactState {
    /// A PROTECTED state may be set only by an audit-bound transition (an empty
    /// `audit_id` transition to a protected state is inert on read). `Candidate`
    /// is NOT protected — the learner writes it best-effort, like a prediction.
    pub fn is_protected(self) -> bool {
        matches!(
            self,
            FactState::Trusted
                | FactState::Suspicious
                | FactState::KnownMalicious
                | FactState::Retired
        )
    }

    /// The two states that mark an entity compromised (it must never teach the
    /// Trusted baseline).
    pub fn is_compromised(self) -> bool {
        matches!(self, FactState::Suspicious | FactState::KnownMalicious)
    }
}

/// How a fact was learned: passively `Observed` from the event stream, or
/// `Asserted` from an operator-provided inventory/import (higher trust, but still
/// gated for security-relevant facts).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationMode {
    #[default]
    Observed,
    Asserted,
}

/// The kind of source an observation came from (used with the per-source trust
/// map + influence caps).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    #[default]
    EventStream,
    Inventory,
    Analyst,
    Agent,
    Correlation,
    #[serde(other)]
    Unknown,
}

/// A reference to an entity — the anti-poisoning join key (`Eq + Hash`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityRef {
    #[serde(default)]
    pub kind: EntityKind,
    #[serde(default)]
    pub id: String,
}

impl EntityRef {
    pub fn new(kind: EntityKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }
}

/// The provenance of an observation: which bounded source produced it, and the
/// trust assigned to that source at write time (from `EnvironmentConfig`, never
/// self-declared in event content).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    #[serde(default)]
    pub kind: SourceKind,
    /// A BOUNDED source identity — the collector / event `source`, never a
    /// per-event id (else the distinct-source and influence-cap guards are
    /// trivially defeated by volume from one feed).
    #[serde(default)]
    pub source_id: String,
    /// The trust weight for this source (assigned from config at write time).
    #[serde(default)]
    pub trust: f32,
}

/// The stable, content-addressed identity of a fact. EXCLUDES the value (so
/// competing values of one attribute share one id — exactly one can be Trusted)
/// and INCLUDES the relation target (so `host runs_on ip1` and `host runs_on ip2`
/// are distinct facts). Length-framed via [`frame`], so no component can bleed
/// into another.
pub fn fact_id(
    entity: &EntityRef,
    attribute: &str,
    relation: Option<RelationKind>,
    target: Option<&EntityRef>,
) -> String {
    frame(&[
        b"env-fact",
        entity.kind.tag().as_bytes(),
        entity.id.as_bytes(),
        attribute.as_bytes(),
        relation.map(|r| r.tag()).unwrap_or("").as_bytes(),
        target.map(|t| t.kind.tag()).unwrap_or("").as_bytes(),
        target.map(|t| t.id.as_str()).unwrap_or("").as_bytes(),
    ])
}

/// An append-only, bitemporal piece of evidence for a fact. Valid-time
/// (`valid_from`/`valid_to`) says what the world was; transaction-time
/// (`recorded_at`) says when we came to believe it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FactObservation {
    /// Content identity (see [`observation_id`]): `frame([fact_id, source_id,
    /// value])` — EXCLUDES the timestamp, so a re-sighting of an unchanged fact
    /// is the SAME id (an idempotent store no-op; the repeat only bumps the
    /// sighting scalar), while a changed value is a new row.
    #[serde(default)]
    pub observation_id: String,
    #[serde(default)]
    pub fact_id: String,
    #[serde(default)]
    pub entity: EntityRef,
    /// The attribute this observation is about (e.g. `role`, `open_port`); empty
    /// for a pure relation fact.
    #[serde(default)]
    pub attribute: String,
    #[serde(default)]
    pub relation: Option<RelationKind>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub source: SourceRef,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub mode: ObservationMode,
    /// Provenance: the learner rule, the import file, or the analyst.
    #[serde(default)]
    pub learned_from: String,
    /// VALID-TIME start — when the fact became true in the world.
    #[serde(default = "Utc::now")]
    pub valid_from: DateTime<Utc>,
    /// VALID-TIME end (`None` = still open).
    #[serde(default)]
    pub valid_to: Option<DateTime<Utc>>,
    /// TRANSACTION-TIME — when we recorded this belief.
    #[serde(default = "Utc::now")]
    pub recorded_at: DateTime<Utc>,
    /// Best-effort audit id for the observe (like `AgentPrediction.audit_id`);
    /// observations are unprotected, so this is provenance, not the invariant.
    #[serde(default)]
    pub audit_id: Option<String>,
}

/// An append-only governance transition on a fact's promotion state — the
/// audit-bound analogue of a registry `PromotionEvent`, rescoped to one fact.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FactTransition {
    #[serde(default)]
    pub transition_id: String,
    #[serde(default)]
    pub fact_id: String,
    #[serde(default)]
    pub to_state: FactState,
    #[serde(default)]
    pub from_state: FactState,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub actor: String,
    /// The BLESSED observation this transition promotes — its `value` is the one
    /// the fact carries while in `to_state`. Pins the value the way a registry
    /// promotion pins `target_digest`, so the Trusted value can't float on later
    /// observation arithmetic. Empty for states with no blessed value (e.g. a
    /// bare Retire).
    #[serde(default)]
    pub target_observation_id: String,
    /// When set, the fact stays gated from auto-promotion until this instant.
    #[serde(default)]
    pub quarantine_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub supersedes: Option<String>,
    /// THE INVARIANT BINDING: a PROTECTED transition with an empty `audit_id` is
    /// inert on read (see [`current_state`]).
    #[serde(default)]
    pub audit_id: String,
    #[serde(default = "Utc::now")]
    pub recorded_at: DateTime<Utc>,
}

/// A monotonic scalar per fact: bounds observation growth (one row per genuine
/// change; a pure repeat only bumps this) and feeds expiry (`last_seen`) and the
/// per-source influence cap (`per_source_counts`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sighting {
    #[serde(default)]
    pub fact_id: String,
    #[serde(default = "Utc::now")]
    pub first_seen: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub observation_count: u64,
    /// bounded-source-id -> count, the input to the influence cap.
    #[serde(default)]
    pub per_source_counts: BTreeMap<String, u64>,
}

/// The derived current (or as-of-`T`) view of a fact — the analogue of the
/// registry `active` record. Never stored; always materialized from the streams.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnvFact {
    pub fact_id: String,
    pub entity: EntityRef,
    pub attribute: String,
    pub relation: Option<RelationKind>,
    pub target_id: Option<String>,
    /// The live value: for a PROTECTED fact this is the BLESSED value pinned by
    /// the transition; for a Candidate it is the conflict-resolved observation.
    pub value: String,
    pub state: FactState,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub observation_count: u64,
    pub distinct_sources: Vec<String>,
    pub confidence: f32,
    pub mode: ObservationMode,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub learned_from: String,
    pub quarantine_until: Option<DateTime<Utc>>,
    /// The audit id of the transition that set `state` (`""` if unaudited/none —
    /// a protected state with `""` here was inert and folded away).
    pub current_audit_id: String,
    /// True when competing values could not be resolved (a genuine tie or a
    /// protected fact whose live observations disagree with the blessed value) —
    /// surfaced for a human, never silently overwritten.
    pub conflict_needs_human: bool,
}

// ---- bitemporal folds (pure; the analogue of the registry `active` fold) ----

/// The newest non-superseded transition, treating a PROTECTED transition with an
/// empty `audit_id` as inert (a forged redb row can't make a fact live). A clone
/// of the registry `newest_binding` fold, rescoped to one fact's transitions.
fn newest_transition(transitions: &[&FactTransition]) -> Option<usize> {
    let inert = |t: &FactTransition| t.to_state.is_protected() && t.audit_id.is_empty();
    // Build the superseded set ONLY from non-inert transitions: an inert (forged,
    // empty-audit) row must have no effect on read, so its `supersedes` must not
    // be able to knock a legitimate audited transition out of contention.
    let superseded: std::collections::HashSet<&str> = transitions
        .iter()
        .filter(|t| !inert(t))
        .filter_map(|t| t.supersedes.as_deref())
        .collect();
    transitions
        .iter()
        .enumerate()
        .filter(|(_, t)| !inert(t) && !superseded.contains(t.transition_id.as_str()))
        .max_by(|(_, a), (_, b)| {
            a.recorded_at
                .cmp(&b.recorded_at)
                .then_with(|| a.transition_id.cmp(&b.transition_id))
        })
        .map(|(i, _)| i)
}

/// The governing transition for a fact (its transitions only). `None` ⇒ the fact
/// has never had an effective transition (birth state applies).
pub fn current_transition(transitions: &[FactTransition]) -> Option<&FactTransition> {
    let refs: Vec<&FactTransition> = transitions.iter().collect();
    newest_transition(&refs).map(|i| refs[i])
}

/// Pick the conflict-resolved observation among competing values of a fact:
/// highest `source.trust * confidence`, then newest `recorded_at`. Returns the
/// winner and whether the top was a genuine tie (⇒ a human must decide).
fn resolve_value<'a>(obs: &[&'a FactObservation]) -> Option<(&'a FactObservation, bool)> {
    let score = |o: &FactObservation| (o.source.trust as f64) * (o.confidence as f64);
    let best = obs.iter().copied().max_by(|a, b| {
        score(a)
            .partial_cmp(&score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.recorded_at.cmp(&b.recorded_at))
    })?;
    // A genuine tie: another observation with a DIFFERENT value scores equal and
    // is not strictly older (so "newest wins" didn't actually break the tie).
    let tie = obs.iter().any(|o| {
        o.value != best.value
            && (score(o) - score(best)).abs() < f64::EPSILON
            && o.recorded_at == best.recorded_at
    });
    Some((best, tie))
}

/// Materialize the current view of one fact from its (already fact-scoped)
/// observation + transition streams and its sighting scalar. `ttl` (when set)
/// expires a stale NON-PROTECTED fact to `Retired` — protected facts
/// (Trusted/Suspicious/KnownMalicious/Retired) are NEVER expired by this fold;
/// they leave their state only through an audited transition.
pub fn materialize_fact(
    fid: &str,
    obs: &[FactObservation],
    transitions: &[FactTransition],
    sighting: Option<&Sighting>,
    ttl: Option<chrono::Duration>,
    now: DateTime<Utc>,
) -> Option<EnvFact> {
    if obs.is_empty() && transitions.is_empty() {
        return None;
    }
    let obs_refs: Vec<&FactObservation> = obs.iter().collect();

    // State + the audited transition context.
    let transition = current_transition(transitions);
    let mut state = match transition {
        Some(t) => t.to_state,
        None if !obs.is_empty() => FactState::Candidate, // birth
        None => FactState::Unknown,
    };
    let quarantine_until = transition.and_then(|t| t.quarantine_until);
    let current_audit_id = transition.map(|t| t.audit_id.clone()).unwrap_or_default();

    // Value: a PROTECTED fact carries the BLESSED value pinned by the transition;
    // a newer competing live observation does not silently replace it (that is
    // drift a human must bless). A non-protected fact uses conflict resolution.
    let (value, mode, confidence, valid_from, valid_to, learned_from, mut conflict) =
        if state.is_protected() {
            let blessed_id = transition
                .map(|t| t.target_observation_id.as_str())
                .unwrap_or("");
            let blessed = obs.iter().find(|o| o.observation_id == blessed_id);
            // Drift: the newest live observation disagrees with the blessed value.
            let newest_live = obs.iter().max_by_key(|o| o.recorded_at);
            let drift = match (blessed, newest_live) {
                (Some(b), Some(n)) => n.value != b.value,
                // A protected fact whose blessed observation is gone is itself a
                // conflict a human must resolve.
                (None, _) => !blessed_id.is_empty(),
                _ => false,
            };
            match blessed.or(newest_live) {
                Some(o) => (
                    o.value.clone(),
                    o.mode,
                    o.confidence,
                    o.valid_from,
                    o.valid_to,
                    o.learned_from.clone(),
                    drift,
                ),
                None => (
                    String::new(),
                    ObservationMode::default(),
                    0.0,
                    now,
                    None,
                    String::new(),
                    drift,
                ),
            }
        } else {
            match resolve_value(&obs_refs) {
                Some((o, tie)) => (
                    o.value.clone(),
                    o.mode,
                    o.confidence,
                    o.valid_from,
                    o.valid_to,
                    o.learned_from.clone(),
                    tie,
                ),
                None => (
                    String::new(),
                    ObservationMode::default(),
                    0.0,
                    now,
                    None,
                    String::new(),
                    false,
                ),
            }
        };

    // Counters: from the sighting scalar when present (current view); else derive
    // from the observation set (the as-of view has no reconstructable scalar).
    let (first_seen, last_seen, observation_count) = match sighting {
        Some(s) => (s.first_seen, s.last_seen, s.observation_count),
        None => {
            let first = obs.iter().map(|o| o.recorded_at).min().unwrap_or(now);
            let last = obs.iter().map(|o| o.recorded_at).max().unwrap_or(now);
            (first, last, obs.len() as u64)
        }
    };
    let mut distinct_sources: Vec<String> =
        obs.iter().map(|o| o.source.source_id.clone()).collect();
    distinct_sources.sort();
    distinct_sources.dedup();

    // Expiry: only a NON-protected (Candidate/Unknown) fact expires by time — a
    // security fact never silently exits its state via a fold (that would drop a
    // compromised entity out of the guarded set unaudited).
    if let Some(ttl) = ttl {
        if !state.is_protected() && now.signed_duration_since(last_seen) > ttl {
            state = FactState::Retired;
            conflict = false;
        }
    }

    let (entity, attribute, relation, target_id) = obs
        .iter()
        .max_by_key(|o| o.recorded_at)
        .map(|o| {
            (
                o.entity.clone(),
                o.attribute.clone(),
                o.relation,
                o.target_id.clone(),
            )
        })
        .unwrap_or_default();

    Some(EnvFact {
        fact_id: fid.to_string(),
        entity,
        attribute,
        relation,
        target_id,
        value,
        state,
        first_seen,
        last_seen,
        observation_count,
        distinct_sources,
        confidence,
        mode,
        valid_from,
        valid_to,
        learned_from,
        quarantine_until,
        current_audit_id,
        conflict_needs_human: conflict,
    })
}

/// The bitemporal query: what did we believe about this fact at `as_of`? Slices
/// both streams by TRANSACTION-TIME (`recorded_at <= as_of`) — immutable slices,
/// so it never races a writer — then re-runs the fold. Counters are derived from
/// the truncated observations (the sighting scalar is a current-only concept).
pub fn materialize_fact_asof(
    fid: &str,
    as_of: DateTime<Utc>,
    obs: &[FactObservation],
    transitions: &[FactTransition],
    ttl: Option<chrono::Duration>,
) -> Option<EnvFact> {
    let o: Vec<FactObservation> = obs
        .iter()
        .filter(|o| o.recorded_at <= as_of)
        .cloned()
        .collect();
    let t: Vec<FactTransition> = transitions
        .iter()
        .filter(|t| t.recorded_at <= as_of)
        .cloned()
        .collect();
    materialize_fact(fid, &o, &t, None, ttl, as_of)
}

/// A registry-style integrity finding for the environment store.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnvFinding {
    pub category: String,
    pub coord: String,
    pub detail: String,
}

/// Check the environment store upholds its invariants (pure, I/O-free, like
/// `verify_registry`): every PROTECTED transition is audit-bound; every
/// transition has an observation to govern; and no Trusted fact has drifted off
/// its blessed value or lost the blessed observation. An empty vec ⇒ sound.
pub fn verify_environment(
    obs: &[FactObservation],
    transitions: &[FactTransition],
) -> Vec<EnvFinding> {
    let mut out = Vec::new();
    for t in transitions {
        if t.to_state.is_protected() && t.audit_id.is_empty() {
            out.push(EnvFinding {
                category: "unaudited-transition".to_string(),
                coord: t.transition_id.clone(),
                detail: format!(
                    "{:?} of {} has an empty audit_id — inert on read",
                    t.to_state,
                    t.fact_id.get(..12).unwrap_or(&t.fact_id)
                ),
            });
        }
        if !obs.iter().any(|o| o.fact_id == t.fact_id) {
            out.push(EnvFinding {
                category: "dangling-transition".to_string(),
                coord: t.transition_id.clone(),
                detail: format!(
                    "transition governs fact {} which has no observation",
                    t.fact_id.get(..12).unwrap_or(&t.fact_id)
                ),
            });
        }
    }
    // Trusted-value drift: for each fact whose current state is Trusted, the
    // blessed observation must still exist and the newest live observation must
    // still agree with it (else a human must re-bless — never silently adopted).
    let mut fact_ids: Vec<&str> = transitions.iter().map(|t| t.fact_id.as_str()).collect();
    fact_ids.sort_unstable();
    fact_ids.dedup();
    for fid in fact_ids {
        let ft: Vec<FactTransition> = transitions
            .iter()
            .filter(|t| t.fact_id == fid)
            .cloned()
            .collect();
        let Some(cur) = current_transition(&ft) else {
            continue;
        };
        if cur.to_state != FactState::Trusted {
            continue;
        }
        let fo: Vec<&FactObservation> = obs.iter().filter(|o| o.fact_id == fid).collect();
        let blessed = fo
            .iter()
            .find(|o| o.observation_id == cur.target_observation_id);
        match blessed {
            None => out.push(EnvFinding {
                category: "trusted-value-drift".to_string(),
                coord: cur.transition_id.clone(),
                detail: format!(
                    "Trusted fact {} has no observation for its blessed value",
                    fid.get(..12).unwrap_or(fid)
                ),
            }),
            Some(b) => {
                if let Some(n) = fo.iter().max_by_key(|o| o.recorded_at) {
                    if n.value != b.value {
                        out.push(EnvFinding {
                            category: "trusted-value-drift".to_string(),
                            coord: cur.transition_id.clone(),
                            detail: format!(
                                "Trusted fact {} blessed '{}' but the newest observation is '{}' — re-confirm",
                                fid.get(..12).unwrap_or(fid),
                                b.value,
                                n.value
                            ),
                        });
                    }
                }
            }
        }
    }
    out
}

// ---- the anti-poisoning gate (pure; the safe-learning spine) ----------------

/// Tunable thresholds for the promotion gate. A pure value (built from
/// `EnvironmentConfig`) so the gate stays I/O-free and table-driven-testable.
#[derive(Debug, Clone)]
pub struct PromotionPolicy {
    /// A Candidate must age at least this long (since first_seen) before it can
    /// auto-promote.
    pub quarantine: chrono::Duration,
    /// The (shorter) quarantine for an Asserted (inventory) fact.
    pub asserted_quarantine: chrono::Duration,
    /// Minimum total sightings before auto-promotion.
    pub min_observations: u64,
    /// Minimum DISTINCT bounded source ids before auto-promotion.
    pub min_distinct_sources: usize,
    /// No single source's trust-weighted share of the evidence may exceed this.
    pub max_single_source_share: f64,
    /// A stale Candidate older than this expires to Retired.
    pub fact_ttl: chrono::Duration,
    /// Attributes / entity-kind tags that REQUIRE analyst approval, ON TOP OF the
    /// non-removable code floor (see [`is_high_impact`]) — config may ADD, never
    /// subtract.
    pub extra_high_impact: Vec<String>,
    /// bounded-source-id -> trust weight, for the influence cap.
    pub source_trust: BTreeMap<String, f32>,
    /// Trust for a source absent from `source_trust` (assigned at write time).
    pub default_source_trust: f32,
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        Self {
            quarantine: chrono::Duration::hours(24),
            asserted_quarantine: chrono::Duration::hours(1),
            min_observations: 5,
            min_distinct_sources: 2,
            max_single_source_share: 0.8,
            fact_ttl: chrono::Duration::days(90),
            extra_high_impact: Vec::new(),
            source_trust: BTreeMap::new(),
            default_source_trust: 0.5,
        }
    }
}

/// Everything the gate needs, assembled by the store layer (open cases +
/// compromised entities are store-derived; the fact + counts are materialized).
pub struct PromotionContext<'a> {
    pub fact: &'a EnvFact,
    pub now: DateTime<Utc>,
    /// Entities touched by a case that is NOT closed OR whose verdict is
    /// malicious (built by the store — see the compromised/open-case sets).
    pub open_case_entities: &'a HashSet<EntityRef>,
    /// Entities marked compromised by an audited Suspicious/KnownMalicious
    /// transition OR a malicious case verdict.
    pub compromised_entities: &'a HashSet<EntityRef>,
    /// Active maintenance/change windows (Asserted ChangeRecord facts).
    pub change_windows: &'a [EnvFact],
    /// This fact's per-source sighting counts (the influence-cap input).
    pub per_source_counts: &'a BTreeMap<String, u64>,
    pub policy: &'a PromotionPolicy,
}

/// A reason a promotion is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionBlock {
    /// An open (or malicious) case touches this entity — the CORE rule.
    OpenCaseTouchesEntity,
    /// The entity is known-compromised — the CORE rule.
    EntityCompromised,
    /// Still within its quarantine window (and no change window excuses it).
    QuarantineActive,
    InsufficientObservations,
    InsufficientDistinctSources,
    /// One source's trust-weighted share exceeds the cap.
    InfluenceCapExceeded,
    /// A high-impact fact — only an analyst may promote it.
    RequiresAnalystApproval,
    /// Competing values disagree (a genuine tie, or live observations contradict
    /// the blessed value) — a human must adjudicate; the system must not auto-bless
    /// one side. In the AUTO tier, so an analyst may still resolve and promote it.
    ConflictNeedsHuman,
}

/// The NON-REMOVABLE code floor of high-impact facts: identity, authz, and
/// trust-anchor facts ALWAYS require analyst approval. `extra` (from config) may
/// only ADD to this floor — no single config/env value can switch the gate off.
pub fn is_high_impact(fact: &EnvFact, extra: &[String]) -> bool {
    let floor_kind = matches!(
        fact.entity.kind,
        EntityKind::Identity
            | EntityKind::ServiceAccount
            | EntityKind::Role
            | EntityKind::Certificate
            | EntityKind::NetworkZone
    );
    let floor_rel = matches!(
        fact.relation,
        Some(RelationKind::Administers)
            | Some(RelationKind::AuthenticatesTo)
            | Some(RelationKind::BelongsToZone)
    );
    let added = extra
        .iter()
        .any(|h| h == &fact.attribute || h == fact.entity.kind.tag());
    floor_kind || floor_rel || added
}

/// True if any entity in `set` matches this fact's subject entity, or (by id) its
/// relation target. Over-blocks toward safety (a bare id match on the target is
/// intentional — the target's kind isn't on the materialized fact).
fn touches(fact: &EnvFact, set: &HashSet<EntityRef>) -> bool {
    set.contains(&fact.entity)
        || fact
            .target_id
            .as_deref()
            .is_some_and(|tid| set.iter().any(|e| e.id == tid))
}

/// True if an active ChangeRecord window covers this entity at `now` (its
/// valid-time interval contains `now`). Change records are operator-Asserted, so
/// an attacker without the admin token cannot declare one.
pub fn within_change_window(entity: &EntityRef, now: DateTime<Utc>, windows: &[EnvFact]) -> bool {
    windows.iter().any(|w| {
        w.entity.kind == EntityKind::ChangeRecord
            && w.target_id.as_deref() == Some(entity.id.as_str())
            && w.valid_from <= now
            && w.valid_to.map(|end| now < end).unwrap_or(true)
    })
}

/// True if any single source's trust-weighted share of the evidence exceeds the
/// cap (no single source/host/feed dominates the learned baseline). Zero total
/// weighted evidence cannot clear the cap (fail safe).
fn influence_cap_exceeded(per_source: &BTreeMap<String, u64>, policy: &PromotionPolicy) -> bool {
    // An unlisted source is weighted by the SAME default_source_trust the write
    // path stamped its observations with — not a hardcoded 1.0 — so the cap agrees
    // with the trust the evidence was actually recorded at (and an operator who
    // sets default_source_trust = 0 gets the fail-safe: zero total ⇒ blocked).
    let weight = |src: &str, count: u64| {
        let trust = *policy
            .source_trust
            .get(src)
            .unwrap_or(&policy.default_source_trust);
        (count as f64) * (trust as f64)
    };
    let total: f64 = per_source.iter().map(|(s, c)| weight(s, *c)).sum();
    if total <= 0.0 {
        return true;
    }
    per_source
        .iter()
        .any(|(s, c)| weight(s, *c) / total > policy.max_single_source_share)
}

/// The INVIOLABLE blocks — enforced for BOTH auto and analyst promotion. An open
/// (or malicious) case, or a compromised entity, can never teach the Trusted
/// baseline, by any path.
pub fn hard_blocks(ctx: &PromotionContext) -> Vec<PromotionBlock> {
    let mut b = Vec::new();
    if touches(ctx.fact, ctx.open_case_entities) {
        b.push(PromotionBlock::OpenCaseTouchesEntity);
    }
    if touches(ctx.fact, ctx.compromised_entities) {
        b.push(PromotionBlock::EntityCompromised);
    }
    b
}

/// The blocks an ANALYST approval clears (quarantine, evidence thresholds,
/// influence cap, high-impact). Cleared by a human; never bypass the hard blocks.
pub fn auto_blocks(ctx: &PromotionContext) -> Vec<PromotionBlock> {
    let mut b = Vec::new();
    // Quarantine is derived from first_seen (not a stored flag), so a fact that
    // never received a Candidate transition can't skip it. Asserted facts get the
    // shorter window. An active change window excuses it (expected change).
    let window = if ctx.fact.mode == ObservationMode::Asserted {
        ctx.policy.asserted_quarantine
    } else {
        ctx.policy.quarantine
    };
    let quarantined = ctx.now < ctx.fact.first_seen + window;
    if quarantined && !within_change_window(&ctx.fact.entity, ctx.now, ctx.change_windows) {
        b.push(PromotionBlock::QuarantineActive);
    }
    if ctx.fact.observation_count < ctx.policy.min_observations {
        b.push(PromotionBlock::InsufficientObservations);
    }
    if ctx.fact.distinct_sources.len() < ctx.policy.min_distinct_sources {
        b.push(PromotionBlock::InsufficientDistinctSources);
    }
    if influence_cap_exceeded(ctx.per_source_counts, ctx.policy) {
        b.push(PromotionBlock::InfluenceCapExceeded);
    }
    if is_high_impact(ctx.fact, &ctx.policy.extra_high_impact) {
        b.push(PromotionBlock::RequiresAnalystApproval);
    }
    if ctx.fact.conflict_needs_human {
        b.push(PromotionBlock::ConflictNeedsHuman);
    }
    b
}

/// May the system AUTO-promote this fact to Trusted? Requires BOTH gate tiers
/// clear.
pub fn may_auto_promote(ctx: &PromotionContext) -> bool {
    hard_blocks(ctx).is_empty() && auto_blocks(ctx).is_empty()
}

/// May an ANALYST promote this fact to Trusted? The approval clears the auto
/// blocks, but the hard blocks remain inviolable.
pub fn may_analyst_promote(ctx: &PromotionContext) -> bool {
    hard_blocks(ctx).is_empty()
}

// ---- the pure learner + inventory import ------------------------------------

/// The stable content id of an observation — the identity-defining tuple (fact +
/// bounded source + value), timestamp EXCLUDED so a re-sighting is idempotent.
pub fn observation_id(fact_id: &str, source_id: &str, value: &str) -> String {
    frame(&[
        b"env-obs",
        fact_id.as_bytes(),
        source_id.as_bytes(),
        value.as_bytes(),
    ])
}

/// Assemble one Candidate observation (Observed mode, learner provenance).
#[allow(clippy::too_many_arguments)]
fn candidate(
    entity: &EntityRef,
    attribute: &str,
    relation: Option<RelationKind>,
    target: Option<&EntityRef>,
    value: &str,
    src: &SourceRef,
    confidence: f32,
    valid_from: DateTime<Utc>,
    now: DateTime<Utc>,
) -> FactObservation {
    let fid = fact_id(entity, attribute, relation, target);
    FactObservation {
        observation_id: observation_id(&fid, &src.source_id, value),
        fact_id: fid,
        entity: entity.clone(),
        attribute: attribute.to_string(),
        relation,
        target_id: target.map(|t| t.id.clone()),
        value: value.to_string(),
        source: src.clone(),
        confidence,
        mode: ObservationMode::Observed,
        learned_from: "learner".to_string(),
        valid_from,
        valid_to: None,
        recorded_at: now,
        audit_id: None,
    }
}

/// Turn a batch of events into CANDIDATE observations — NEVER Trusted. Emits a
/// low-confidence host role, host↔ip communication edges, and seen identities.
/// Every observation is attributed to a BOUNDED source id (the collector
/// `event.source`, never a per-event id — FIX for the influence-cap guards) with
/// trust assigned from `policy` at write time (not self-declared in event
/// content). Pure: the garmr-cli loop persists + best-effort audits these.
///
/// KNOWN LIMITATION (the distinct-source + influence-cap guards are only as
/// strong as the ingest trust boundary): `event.source` is set by the shipper at
/// ingest, so an actor who holds an ingest credential can present as several
/// distinct `source` labels for one fact and satisfy `min_distinct_sources` /
/// stay under the influence cap on their own. This is acceptable in Phase 5
/// because NOTHING consumes the Trusted view yet (the detector integration is the
/// Phase-7 seam), so a poisoned Candidate/Trusted fact is inert. Binding `source`
/// to the authenticated shipper identity — so the distinct-source count reflects
/// real collector diversity — is deferred to the collector-reliability work
/// (Phase 12) and MUST land before Phase 7 wires detection onto the Trusted view.
pub fn derive_candidates(
    events: &[crate::Event],
    policy: &PromotionPolicy,
    now: DateTime<Utc>,
) -> Vec<FactObservation> {
    let mut out = Vec::new();
    for ev in events {
        if ev.host.is_empty() {
            continue;
        }
        let src = self_declared_source(ev, policy);
        push_event_candidates(&mut out, ev, &src, now);
    }
    out
}

/// Phase-12 authenticated variant of [`derive_candidates`]. Each event carries
/// the TRUSTED collector id stamped at ingest (`Some`) or `None` if the event
/// arrived unauthenticated. The derived observation's `source_id` is the
/// collector id, not the shipper-self-declared `event.source` — so the Phase-5
/// anti-poisoning distinct-source count reflects real authenticated collectors
/// and one compromised collector can forge only its own single source.
///
/// `bind` = collectors are configured for this deployment. In bind mode an event
/// with no trusted collector id is DROPPED (not folded to a shared sentinel
/// source, which would itself be a poisoning channel) — unauthenticated events
/// never feed the learner once authentication is in force. With `bind == false`
/// (default-off, no collectors) behaviour is byte-identical to
/// `derive_candidates`: the self-declared source is used.
pub fn derive_candidates_bound(
    rows: &[(crate::Event, Option<String>)],
    policy: &PromotionPolicy,
    now: DateTime<Utc>,
    bind: bool,
) -> Vec<FactObservation> {
    let mut out = Vec::new();
    for (ev, collector_id) in rows {
        if ev.host.is_empty() {
            continue;
        }
        let src = match collector_id.as_deref().filter(|c| !c.is_empty()) {
            // Authenticated: the collector id is the trust anchor.
            Some(cid) => {
                let trust = policy
                    .source_trust
                    .get(cid)
                    .copied()
                    .unwrap_or(policy.default_source_trust);
                SourceRef {
                    kind: SourceKind::EventStream,
                    source_id: cid.to_string(),
                    trust,
                }
            }
            // Unauthenticated: dropped in bind mode; self-declared otherwise.
            None if bind => continue,
            None => self_declared_source(ev, policy),
        };
        push_event_candidates(&mut out, ev, &src, now);
    }
    out
}

/// The pre-Phase-12 source: the shipper-self-declared `event.source` (or
/// `"unknown"`), weighted by the policy trust map. Poisonable — a single shipper
/// can declare arbitrarily many distinct sources — which is exactly why the
/// authenticated path keys on the collector id instead.
fn self_declared_source(ev: &crate::Event, policy: &PromotionPolicy) -> SourceRef {
    let src_id = if ev.source.is_empty() {
        "unknown".to_string()
    } else {
        ev.source.to_string()
    };
    let trust = policy
        .source_trust
        .get(&src_id)
        .copied()
        .unwrap_or(policy.default_source_trust);
    SourceRef {
        kind: SourceKind::EventStream,
        source_id: src_id,
        trust,
    }
}

/// Emit the candidate observations for one event under a resolved source. Shared
/// by [`derive_candidates`] and [`derive_candidates_bound`] so both derive the
/// identical fact set; only source resolution differs between them.
fn push_event_candidates(
    out: &mut Vec<FactObservation>,
    ev: &crate::Event,
    src: &SourceRef,
    now: DateTime<Utc>,
) {
    let host = EntityRef::new(EntityKind::Host, ev.host.clone());

    // 1. Host role (low-confidence heuristic; the Phase-7 seam).
    let role = crate::domain::heuristic_role(&ev.host, &ev.source, &ev.log_type);
    out.push(candidate(
        &host, "role", None, None, role, src, 0.3, ev.ts, now,
    ));

    // 2. Host communicates-with Ip (from the extracted source ip).
    if let Some(ip) = ev.src_ip().filter(|s| !s.is_empty()) {
        let target = EntityRef::new(EntityKind::Ip, ip.to_string());
        out.push(candidate(
            &host,
            "",
            Some(RelationKind::CommunicatesWith),
            Some(&target),
            ip,
            src,
            0.5,
            ev.ts,
            now,
        ));
    }

    // 3. Identity seen (db_user / user). Identity is high-impact — it can be
    //    a Candidate but never auto-promotes.
    for key in ["db_user", "user"] {
        if let Some(u) = ev.field(key).filter(|s| !s.is_empty()) {
            let ident = EntityRef::new(EntityKind::Identity, u.to_string());
            out.push(candidate(
                &ident, "active", None, None, "seen", src, 0.4, ev.ts, now,
            ));
            break;
        }
    }
}

/// The wire format of a local inventory file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryFormat {
    Toml,
    Json,
}

/// One asserted fact in an inventory file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InventoryFact {
    pub entity_kind: String,
    pub entity_id: String,
    #[serde(default)]
    pub attribute: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub relation: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub valid_to: Option<DateTime<Utc>>,
}

/// A local inventory file: a list of asserted facts.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InventoryFile {
    #[serde(default)]
    pub facts: Vec<InventoryFact>,
}

/// Parse a local inventory file (TOML or JSON) into ASSERTED observations
/// (higher trust than passively observed, but still gated for security-relevant
/// facts). Air-gap friendly — reads bytes, never the network. `source_id` is the
/// bounded inventory name; `trust` is assigned by the caller from config. An
/// entry with an unknown `entity_kind` is skipped, not faulted.
pub fn parse_inventory(
    bytes: &[u8],
    format: InventoryFormat,
    source_id: &str,
    trust: f32,
    now: DateTime<Utc>,
) -> crate::Result<Vec<FactObservation>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| crate::Error::Config(format!("inventory is not UTF-8: {e}")))?;
    let file: InventoryFile = match format {
        InventoryFormat::Toml => toml::from_str(text)
            .map_err(|e| crate::Error::Config(format!("inventory TOML: {e}")))?,
        InventoryFormat::Json => serde_json::from_str(text)
            .map_err(|e| crate::Error::Config(format!("inventory JSON: {e}")))?,
    };
    let src = SourceRef {
        kind: SourceKind::Inventory,
        source_id: source_id.to_string(),
        trust,
    };
    let mut out = Vec::new();
    for f in file.facts {
        let Some(ekind) = EntityKind::from_tag(&f.entity_kind) else {
            continue; // unknown kind → skip, don't fault the whole file
        };
        let entity = EntityRef::new(ekind, f.entity_id);
        let relation = f.relation.as_deref().and_then(RelationKind::from_tag);
        let target = match (
            &f.target_id,
            f.target_kind.as_deref().and_then(EntityKind::from_tag),
        ) {
            (Some(tid), Some(tk)) => Some(EntityRef::new(tk, tid.clone())),
            _ => None,
        };
        let fid = fact_id(&entity, &f.attribute, relation, target.as_ref());
        out.push(FactObservation {
            observation_id: observation_id(&fid, source_id, &f.value),
            fact_id: fid,
            entity,
            attribute: f.attribute,
            relation,
            target_id: f.target_id,
            value: f.value,
            source: src.clone(),
            confidence: f.confidence.unwrap_or(0.9),
            mode: ObservationMode::Asserted,
            learned_from: format!("inventory:{source_id}"),
            valid_from: f.valid_from.unwrap_or(now),
            valid_to: f.valid_to,
            recorded_at: now,
            audit_id: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal observation for a fact (fills the identity + a value).
    fn obs(fid: &str, obs_id: &str, value: &str, src: &str, at: DateTime<Utc>) -> FactObservation {
        FactObservation {
            observation_id: obs_id.to_string(),
            fact_id: fid.to_string(),
            entity: EntityRef::new(EntityKind::Host, "web01"),
            attribute: "role".to_string(),
            value: value.to_string(),
            source: SourceRef {
                kind: SourceKind::EventStream,
                source_id: src.to_string(),
                trust: 1.0,
            },
            confidence: 1.0,
            recorded_at: at,
            valid_from: at,
            ..Default::default()
        }
    }

    fn trans(
        fid: &str,
        id: &str,
        to: FactState,
        blessed: &str,
        audit: &str,
        at: DateTime<Utc>,
    ) -> FactTransition {
        FactTransition {
            transition_id: id.to_string(),
            fact_id: fid.to_string(),
            to_state: to,
            target_observation_id: blessed.to_string(),
            audit_id: audit.to_string(),
            recorded_at: at,
            ..Default::default()
        }
    }

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn unaudited_protected_transition_is_inert() {
        let fid = "f1";
        let o = vec![obs(fid, "o1", "server", "sA", t0())];
        // A forged Trusted transition with no audit id must NOT make the fact Trusted.
        let forged = vec![trans(fid, "x", FactState::Trusted, "o1", "", t0())];
        let f = materialize_fact(fid, &o, &forged, None, None, t0()).unwrap();
        assert_eq!(
            f.state,
            FactState::Candidate,
            "forged Trusted is inert → birth Candidate"
        );
    }

    #[test]
    fn an_inert_transition_cannot_supersede_a_live_one() {
        // A legit audited KnownMalicious transition, then a FORGED inert (empty
        // audit) transition whose `supersedes` points at the legit one. The inert
        // row must not knock the legit transition out of contention.
        let fid = "f1";
        let o = vec![obs(fid, "o1", "bad", "sA", t0())];
        let mut legit = trans(
            fid,
            "tmal",
            FactState::KnownMalicious,
            "o1",
            "audit-1",
            t0(),
        );
        let mut forged = trans(
            fid,
            "forged",
            FactState::Retired,
            "",
            "", // no audit → inert
            t0() + chrono::Duration::hours(1),
        );
        forged.supersedes = Some("tmal".into());
        legit.supersedes = None;
        let f = materialize_fact(fid, &o, &[legit, forged], None, None, t0()).unwrap();
        assert_eq!(
            f.state,
            FactState::KnownMalicious,
            "the forged inert row's supersedes must have no effect"
        );
    }

    #[test]
    fn blessed_value_does_not_float_after_promotion() {
        let fid = "f1";
        let t1 = t0() + chrono::Duration::hours(1);
        // Promoted with value=server blessed to o1; a later o2=router must NOT
        // become the Trusted value — it's drift, flagged for a human.
        let o = vec![
            obs(fid, "o1", "server", "sA", t0()),
            obs(fid, "o2", "router", "sB", t1),
        ];
        let tr = vec![trans(fid, "p", FactState::Trusted, "o1", "audit-1", t0())];
        let f = materialize_fact(fid, &o, &tr, None, None, t1).unwrap();
        assert_eq!(f.state, FactState::Trusted);
        assert_eq!(f.value, "server", "Trusted value stays the blessed one");
        assert!(
            f.conflict_needs_human,
            "the drifting observation is surfaced"
        );
    }

    #[test]
    fn expiry_retires_candidate_but_never_a_compromised_fact() {
        let fid = "f1";
        let old = t0();
        let now = t0() + chrono::Duration::days(90);
        let ttl = Some(chrono::Duration::days(30));
        // A stale Candidate expires to Retired.
        let cand = materialize_fact(
            fid,
            &[obs(fid, "o1", "server", "sA", old)],
            &[],
            None,
            ttl,
            now,
        )
        .unwrap();
        assert_eq!(cand.state, FactState::Retired);
        // A stale KnownMalicious fact does NOT expire (would drop it from the
        // compromised set unaudited).
        let mal = vec![trans(
            fid,
            "m",
            FactState::KnownMalicious,
            "o1",
            "audit-2",
            old,
        )];
        let f = materialize_fact(
            fid,
            &[obs(fid, "o1", "bad", "sA", old)],
            &mal,
            None,
            ttl,
            now,
        )
        .unwrap();
        assert_eq!(
            f.state,
            FactState::KnownMalicious,
            "a compromised fact never auto-expires"
        );
    }

    #[test]
    fn asof_returns_historical_belief() {
        let fid = "f1";
        let t1 = t0() + chrono::Duration::hours(1);
        let o = vec![obs(fid, "o1", "server", "sA", t0())];
        let tr = vec![trans(fid, "p", FactState::Trusted, "o1", "audit-1", t1)];
        // Before the promotion: Candidate. After: Trusted.
        let before = materialize_fact_asof(fid, t0(), &o, &tr, None).unwrap();
        assert_eq!(before.state, FactState::Candidate);
        let after = materialize_fact_asof(fid, t1, &o, &tr, None).unwrap();
        assert_eq!(after.state, FactState::Trusted);
    }

    #[test]
    fn verify_flags_unaudited_dangling_and_drift() {
        let fid = "f1";
        // unaudited protected transition
        let forged = trans(fid, "u", FactState::Trusted, "o1", "", t0());
        // dangling: a transition whose fact has no observation
        let dangling = trans("f-missing", "d", FactState::Suspicious, "", "audit-3", t0());
        let o = vec![obs(fid, "o1", "server", "sA", t0())];
        let findings = verify_environment(&o, &[forged, dangling]);
        let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(cats.contains(&"unaudited-transition"));
        assert!(cats.contains(&"dangling-transition"));

        // drift: Trusted blessed to o1=server but newest observation is router
        let t1 = t0() + chrono::Duration::hours(1);
        let o2 = vec![
            obs(fid, "o1", "server", "sA", t0()),
            obs(fid, "o2", "router", "sB", t1),
        ];
        let tr = vec![trans(fid, "p", FactState::Trusted, "o1", "audit-1", t0())];
        let d = verify_environment(&o2, &tr);
        assert!(d.iter().any(|f| f.category == "trusted-value-drift"));
    }

    #[test]
    fn verify_does_not_panic_on_a_short_fact_id() {
        let short = trans("ab", "u", FactState::Trusted, "", "", t0());
        let _ = verify_environment(&[], std::slice::from_ref(&short)); // must not panic
    }

    #[test]
    fn everything_decodes_from_empty_object() {
        // The STORED / wire-in types must tolerate a missing-field row (a newer
        // writer, a truncated blob). EnvFact is a derived output view — always
        // freshly materialized, never decoded from a stored row — so it is not
        // part of this contract.
        let _o: FactObservation = serde_json::from_str("{}").unwrap();
        let _t: FactTransition = serde_json::from_str("{}").unwrap();
        let _s: Sighting = serde_json::from_str("{}").unwrap();
        let _e: EntityRef = serde_json::from_str("{}").unwrap();
        // Forward-compat: unknown enum strings decode to Unknown, never a
        // spurious Trusted / real kind.
        let k: EntityKind = serde_json::from_str("\"some_future_kind\"").unwrap();
        assert_eq!(k, EntityKind::Unknown);
        let st: FactState = serde_json::from_str("\"quantum\"").unwrap();
        assert_eq!(st, FactState::Unknown);
        let r: RelationKind = serde_json::from_str("\"beams_to\"").unwrap();
        assert_eq!(r, RelationKind::Unknown);
    }

    #[test]
    fn fact_id_excludes_value_but_includes_target() {
        let host = EntityRef::new(EntityKind::Host, "web01");
        // Competing values of one attribute share ONE id (so exactly one can be
        // Trusted and conflict-resolution picks among them).
        let base = fact_id(&host, "role", None, None);
        assert_eq!(base, fact_id(&host, "role", None, None));
        // Different attribute → different fact.
        assert_ne!(base, fact_id(&host, "os", None, None));
        // A relation target is part of the identity: runs_on ip1 != runs_on ip2.
        let ip1 = EntityRef::new(EntityKind::Ip, "10.0.0.1");
        let ip2 = EntityRef::new(EntityKind::Ip, "10.0.0.2");
        let r1 = fact_id(&host, "", Some(RelationKind::RunsOn), Some(&ip1));
        let r2 = fact_id(&host, "", Some(RelationKind::RunsOn), Some(&ip2));
        assert_ne!(r1, r2);
        assert_ne!(r1, base);
    }

    #[test]
    fn fact_id_is_injective_across_component_boundaries() {
        // Length framing: entity id "a" + attribute "bc" must differ from
        // entity id "ab" + attribute "c".
        let a = fact_id(&EntityRef::new(EntityKind::Host, "a"), "bc", None, None);
        let b = fact_id(&EntityRef::new(EntityKind::Host, "ab"), "c", None, None);
        assert_ne!(a, b);
    }

    #[test]
    fn state_protection_and_compromise_predicates() {
        assert!(FactState::Trusted.is_protected());
        assert!(FactState::Retired.is_protected());
        assert!(!FactState::Candidate.is_protected());
        assert!(!FactState::Unknown.is_protected());
        assert!(FactState::KnownMalicious.is_compromised());
        assert!(FactState::Suspicious.is_compromised());
        assert!(!FactState::Trusted.is_compromised());
    }

    // ---- anti-poisoning gate tests ----

    /// A clean, promotable Candidate host fact (2 sources, past quarantine, enough
    /// observations, balanced influence) — the baseline the tests perturb.
    fn promotable_fact() -> EnvFact {
        EnvFact {
            fact_id: "f1".into(),
            entity: EntityRef::new(EntityKind::Host, "web01"),
            attribute: "role".into(),
            value: "server".into(),
            state: FactState::Candidate,
            observation_count: 10,
            distinct_sources: vec!["sA".into(), "sB".into()],
            quarantine_until: Some(t0()), // already elapsed by `now`
            ..Default::default()
        }
    }

    fn counts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(s, c)| (s.to_string(), *c)).collect()
    }

    fn ctx<'a>(
        fact: &'a EnvFact,
        open: &'a HashSet<EntityRef>,
        comp: &'a HashSet<EntityRef>,
        windows: &'a [EnvFact],
        per_source: &'a BTreeMap<String, u64>,
        policy: &'a PromotionPolicy,
    ) -> PromotionContext<'a> {
        PromotionContext {
            fact,
            now: t0() + chrono::Duration::days(2),
            open_case_entities: open,
            compromised_entities: comp,
            change_windows: windows,
            per_source_counts: per_source,
            policy,
        }
    }

    #[test]
    fn clean_candidate_auto_promotes() {
        let f = promotable_fact();
        let (open, comp) = (HashSet::new(), HashSet::new());
        let per = counts(&[("sA", 5), ("sB", 5)]);
        let pol = PromotionPolicy::default();
        assert!(may_auto_promote(&ctx(&f, &open, &comp, &[], &per, &pol)));
    }

    #[test]
    fn contested_fact_blocks_auto_but_not_analyst() {
        // A fact whose values disagree must never be auto-blessed toward one side;
        // a human may still adjudicate it (auto tier, not a hard block).
        let mut f = promotable_fact();
        f.conflict_needs_human = true;
        let (open, comp) = (HashSet::new(), HashSet::new());
        let per = counts(&[("sA", 5), ("sB", 5)]);
        let pol = PromotionPolicy::default();
        let c = ctx(&f, &open, &comp, &[], &per, &pol);
        assert!(auto_blocks(&c).contains(&PromotionBlock::ConflictNeedsHuman));
        assert!(!may_auto_promote(&c));
        assert!(may_analyst_promote(&c));
    }

    #[test]
    fn open_case_hard_blocks_even_an_analyst() {
        let f = promotable_fact();
        let mut open = HashSet::new();
        open.insert(EntityRef::new(EntityKind::Host, "web01"));
        let comp = HashSet::new();
        let per = counts(&[("sA", 5), ("sB", 5)]);
        let pol = PromotionPolicy::default();
        let c = ctx(&f, &open, &comp, &[], &per, &pol);
        assert!(hard_blocks(&c).contains(&PromotionBlock::OpenCaseTouchesEntity));
        assert!(!may_auto_promote(&c));
        assert!(
            !may_analyst_promote(&c),
            "the open-case block is inviolable"
        );
    }

    #[test]
    fn compromised_entity_hard_blocks() {
        let f = promotable_fact();
        let open = HashSet::new();
        let mut comp = HashSet::new();
        comp.insert(EntityRef::new(EntityKind::Host, "web01"));
        let per = counts(&[("sA", 5), ("sB", 5)]);
        let pol = PromotionPolicy::default();
        let c = ctx(&f, &open, &comp, &[], &per, &pol);
        assert!(!may_analyst_promote(&c));
    }

    #[test]
    fn single_source_flood_is_capped() {
        let f = promotable_fact();
        let (open, comp) = (HashSet::new(), HashSet::new());
        // 99 from one source, 1 from another: distinct-sources passes but the
        // influence cap does not.
        let per = counts(&[("sA", 99), ("sB", 1)]);
        let pol = PromotionPolicy::default();
        let c = ctx(&f, &open, &comp, &[], &per, &pol);
        assert!(auto_blocks(&c).contains(&PromotionBlock::InfluenceCapExceeded));
        assert!(!may_auto_promote(&c));
        // An analyst can still override a mere influence cap (not a hard block).
        assert!(may_analyst_promote(&c));
    }

    #[test]
    fn high_impact_needs_analyst_and_config_cannot_remove_the_floor() {
        let mut f = promotable_fact();
        f.entity = EntityRef::new(EntityKind::Identity, "svc-deploy");
        let (open, comp) = (HashSet::new(), HashSet::new());
        let per = counts(&[("sA", 5), ("sB", 5)]);
        // Even with an EMPTY extra_high_impact, the code floor still fires.
        let pol = PromotionPolicy {
            extra_high_impact: Vec::new(),
            ..Default::default()
        };
        let c = ctx(&f, &open, &comp, &[], &per, &pol);
        assert!(auto_blocks(&c).contains(&PromotionBlock::RequiresAnalystApproval));
        assert!(!may_auto_promote(&c));
        assert!(
            may_analyst_promote(&c),
            "an analyst may promote a high-impact fact"
        );
    }

    #[test]
    fn quarantine_blocks_but_a_change_window_excuses_it() {
        let mut f = promotable_fact();
        let now = t0() + chrono::Duration::days(2);
        f.first_seen = now; // just seen → still inside the 24h quarantine window
        let (open, comp) = (HashSet::new(), HashSet::new());
        let per = counts(&[("sA", 5), ("sB", 5)]);
        let pol = PromotionPolicy::default();
        // Without a window: quarantine blocks auto-promotion.
        assert!(auto_blocks(&ctx(&f, &open, &comp, &[], &per, &pol))
            .contains(&PromotionBlock::QuarantineActive));
        // With an active change window covering web01: quarantine is excused.
        let window = EnvFact {
            entity: EntityRef::new(EntityKind::ChangeRecord, "cw-1"),
            target_id: Some("web01".into()),
            valid_from: t0(),
            valid_to: Some(now + chrono::Duration::days(5)),
            ..Default::default()
        };
        let windows = [window];
        assert!(!auto_blocks(&ctx(&f, &open, &comp, &windows, &per, &pol))
            .contains(&PromotionBlock::QuarantineActive));
    }

    // ---- learner + inventory tests ----

    fn ev(host: &str, source: &str, log_type: &str, fields: &[(&str, &str)]) -> crate::Event {
        crate::Event {
            ts: t0(),
            host: host.into(),
            service: "".into(),
            source: source.into(),
            environment: "prod".into(),
            severity: "low".into(),
            log_type: log_type.into(),
            message: String::new(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn learner_attributes_to_a_bounded_source_and_is_idempotent() {
        let pol = PromotionPolicy::default();
        let e = ev("web01", "alloy-nixos", "system", &[("src_ip", "10.0.0.5")]);
        let now = t0() + chrono::Duration::hours(1);
        let a = derive_candidates(std::slice::from_ref(&e), &pol, now);
        // A role fact + a communicates_with edge; the source id is the bounded
        // collector, never a per-event id.
        assert!(a.iter().all(|o| o.source.source_id == "alloy-nixos"));
        assert!(a.iter().all(|o| o.mode == ObservationMode::Observed));
        assert!(a
            .iter()
            .any(|o| o.attribute == "role" && o.value == "server"));
        assert!(a
            .iter()
            .any(|o| o.relation == Some(RelationKind::CommunicatesWith) && o.value == "10.0.0.5"));
        // Re-sighting the SAME events yields the SAME observation ids (idempotent).
        let b = derive_candidates(
            std::slice::from_ref(&e),
            &pol,
            now + chrono::Duration::days(1),
        );
        let ids_a: Vec<&str> = a.iter().map(|o| o.observation_id.as_str()).collect();
        let ids_b: Vec<&str> = b.iter().map(|o| o.observation_id.as_str()).collect();
        assert_eq!(ids_a, ids_b, "re-sighting is idempotent by content id");
    }

    #[test]
    fn bound_learner_keys_on_the_collector_not_the_self_declared_source() {
        let pol = PromotionPolicy::default();
        let now = t0() + chrono::Duration::hours(1);
        // One collector ("fw-collector") self-declaring THREE distinct sources.
        // Unbound, that forges three sources — the poisoning vector. Bound, every
        // observation is keyed on the single trusted collector id.
        let rows: Vec<(crate::Event, Option<String>)> = vec![
            (
                ev("web01", "s1", "system", &[]),
                Some("fw-collector".into()),
            ),
            (
                ev("web01", "s2", "system", &[]),
                Some("fw-collector".into()),
            ),
            (
                ev("web01", "s3", "system", &[]),
                Some("fw-collector".into()),
            ),
        ];
        let obs = derive_candidates_bound(&rows, &pol, now, true);
        assert!(!obs.is_empty());
        assert!(
            obs.iter().all(|o| o.source.source_id == "fw-collector"),
            "bound observations key on the collector id, collapsing forged sources"
        );
    }

    #[test]
    fn bound_learner_drops_unauthenticated_rows_only_in_bind_mode() {
        let pol = PromotionPolicy::default();
        let now = t0() + chrono::Duration::hours(1);
        let rows: Vec<(crate::Event, Option<String>)> = vec![
            (ev("web01", "nginx", "app", &[]), None),
            (ev("db01", "pg", "app", &[]), Some("dbc".into())),
        ];
        // Bind mode: the NULL-collector row is dropped (no shared sentinel source).
        let bound = derive_candidates_bound(&rows, &pol, now, true);
        assert!(bound.iter().all(|o| o.entity.id != "web01"));
        assert!(bound.iter().any(|o| o.source.source_id == "dbc"));
        // Default-off (no collectors): identical to the self-declared path.
        let open = derive_candidates_bound(&rows, &pol, now, false);
        assert!(open.iter().any(|o| o.source.source_id == "nginx"));
        assert!(open.iter().any(|o| o.source.source_id == "dbc"));
    }

    #[test]
    fn learner_role_heuristic_matches_the_seam() {
        let pol = PromotionPolicy::default();
        let now = t0();
        let role = |host: &str, src: &str, lt: &str| {
            derive_candidates(&[ev(host, src, lt, &[])], &pol, now)
                .into_iter()
                .find(|o| o.attribute == "role")
                .map(|o| o.value)
                .unwrap()
        };
        assert_eq!(role("fw01", "pfsense", "firewall"), "router");
        assert_eq!(role("vault-1", "openbao", "app"), "vault");
        assert_eq!(role("sw3", "snmp", "system"), "switch");
        assert_eq!(role("web01", "nginx", "app"), "server");
    }

    #[test]
    fn inventory_parses_toml_and_skips_unknown_kinds() {
        let toml = r#"
[[facts]]
entity_kind = "host"
entity_id = "db01"
attribute = "role"
value = "database"

[[facts]]
entity_kind = "some_future_kind"
entity_id = "x"
"#;
        let now = t0();
        let facts =
            parse_inventory(toml.as_bytes(), InventoryFormat::Toml, "cmdb", 0.9, now).unwrap();
        assert_eq!(facts.len(), 1, "the unknown-kind entry is skipped");
        assert_eq!(facts[0].mode, ObservationMode::Asserted);
        assert_eq!(facts[0].entity.kind, EntityKind::Host);
        assert_eq!(facts[0].value, "database");
        assert_eq!(facts[0].source.source_id, "cmdb");
    }

    #[test]
    fn inventory_parses_json() {
        let json = r#"{"facts":[{"entity_kind":"identity","entity_id":"svc","attribute":"active","value":"yes"}]}"#;
        let facts =
            parse_inventory(json.as_bytes(), InventoryFormat::Json, "idp", 1.0, t0()).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].entity.kind, EntityKind::Identity);
    }
}
