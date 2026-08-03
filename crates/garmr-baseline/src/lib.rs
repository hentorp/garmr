// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 — user & application **behavioral baselines**.
//!
//! A [`BaselineStore`] learns what is *normal* for each entity (a user, role,
//! service account, application, or peer group) across many behavioral
//! dimensions, so the Phase-8 detectors can ask three questions:
//!
//! - **Novelty** — is this a query fingerprint / client / object / … the entity
//!   has never used before? ([`BaselineStore::novelty`])
//! - **Off-hours** — is this access at an hour the entity is rarely active?
//!   ([`BaselineStore::off_hours`])
//! - **Deviation** — is this row-count / volume far above the entity's norm?
//!   ([`BaselineStore::deviation`]) — and how does it compare to the entity's
//!   peer group? ([`BaselineStore::peer_novelty`])
//!
//! ## Trusted-only, gated, poison-resistant
//!
//! Behavior is learned into a **Candidate** profile; only a human/gate-promoted
//! **Trusted** profile answers the detector queries — a Candidate is visible but
//! never fires a finding (mirroring the environment model's `TrustedView`). This
//! is a hard invariant: an attacker who floods a new pattern cannot make it
//! "normal" until the profile is Trusted, and promotion is blocked while the
//! entity has an open case, is compromised, or committed a policy violation in
//! the window ([`hard_blocks`]). And a **forbidden-by-policy action is never
//! learnable as normal** — the caller must not feed policy-denied accesses into
//! [`BaselineStore::observe`], and [`hard_blocks`] refuses promotion after any
//! policy violation. Frequency alone never legitimizes: novelty is measured
//! against the *set* of trusted values, not their counts.
//!
//! Pure, no I/O — the store is a serializable in-memory model; persistence rides
//! the state store, exactly like the environment facts and the registries.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use garmr_core::AuditRecord;
use serde::{Deserialize, Serialize};

/// Version prefix for a serialized store / digest; bump on a model change.
pub const BASELINE_VERSION: &str = "bl1";

// =========================================================================
// entity + dimension
// =========================================================================

/// The kind of thing a baseline profiles. `Unknown` is the forward-compatible
/// catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    User,
    Role,
    Group,
    ServiceAccount,
    Application,
    PeerGroup,
    #[serde(other)]
    Unknown,
}

/// A profiled entity — a `(kind, id)` pair (e.g. `User`/"anna").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Entity {
    pub kind: EntityKind,
    pub id: String,
}

impl Entity {
    pub fn new(kind: EntityKind, id: impl Into<String>) -> Self {
        Entity {
            kind,
            id: id.into(),
        }
    }
    fn key(&self) -> (EntityKind, String) {
        (self.kind, self.id.clone())
    }
}

/// A behavioral dimension. Serializes as a snake_case string so it is a valid
/// JSON map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    // categorical (novelty)
    QueryFingerprint,
    Client,
    SourceHost,
    Object,
    Operation,
    Database,
    Schema,
    SubjectType,
    // temporal (off-hours / weekday)
    HourOfDay,
    Weekday,
    // numeric (deviation)
    RowsRead,
    BytesRead,
    DistinctSubjects,
}

impl Dimension {
    /// All categorical dimensions (the ones novelty checks apply to).
    pub const CATEGORICAL: &'static [Dimension] = &[
        Dimension::QueryFingerprint,
        Dimension::Client,
        Dimension::SourceHost,
        Dimension::Object,
        Dimension::Operation,
        Dimension::Database,
        Dimension::Schema,
        Dimension::SubjectType,
    ];
}

// =========================================================================
// state + maturity
// =========================================================================

/// Promotion state of a profile. Only [`BaselineState::Trusted`] profiles answer
/// detector queries. `Unknown` is the forward-compatible default/catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineState {
    #[default]
    Candidate,
    Trusted,
    Suspicious,
    Retired,
    #[serde(other)]
    Unknown,
}

/// How mature/healthy a baseline is — surfaced in APIs + the WebUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Maturity {
    /// No observations yet.
    Empty,
    /// Accumulating, below the promotion thresholds.
    Learning,
    /// Meets the thresholds; awaiting promotion.
    Candidate,
    /// Trusted and healthy.
    Stable,
    /// Trusted but the recent distribution shifted materially.
    Drifting,
    /// Trusted but data-quality degraded (untrusted source / parser failures).
    Degraded,
    /// Marked suspicious (compromise / policy violation touched it).
    Suspicious,
}

// =========================================================================
// per-dimension trackers
// =========================================================================

/// One observed categorical value's count + first/last-seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueObs {
    pub count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Hard cap on distinct values stored per categorical dimension — a memory
/// backstop for high-cardinality dimensions (e.g. query fingerprints) on the
/// ingest hot path. Once reached, a value already in the set keeps accumulating
/// but a genuinely-new value is dropped rather than stored (learning saturates;
/// it never blows up). A production deployment with very high cardinality should
/// swap the exact set for a membership sketch — see the Phase-11 retrieval work.
pub const MAX_DISTINCT_VALUES: usize = 100_000;

/// The distribution of a categorical dimension (novelty = a value not in the set).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoricalStat {
    pub values: BTreeMap<String, ValueObs>,
    /// Count of distinct values dropped after hitting [`MAX_DISTINCT_VALUES`]
    /// (surfaced so an operator can see a saturated, less-trustworthy dimension).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl CategoricalStat {
    fn observe(&mut self, value: &str, ts: DateTime<Utc>) {
        if !self.values.contains_key(value) && self.values.len() >= MAX_DISTINCT_VALUES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.values
            .entry(value.to_string())
            .and_modify(|o| {
                o.count += 1;
                if ts > o.last_seen {
                    o.last_seen = ts;
                }
                if ts < o.first_seen {
                    o.first_seen = ts;
                }
            })
            .or_insert(ValueObs {
                count: 1,
                first_seen: ts,
                last_seen: ts,
            });
    }
    pub fn contains(&self, value: &str) -> bool {
        self.values.contains_key(value)
    }
    pub fn distinct(&self) -> usize {
        self.values.len()
    }
    /// Values in `self` that are absent from `other` (used for peer comparison).
    pub fn not_in(&self, other: &CategoricalStat) -> Vec<String> {
        self.values
            .keys()
            .filter(|v| !other.values.contains_key(*v))
            .cloned()
            .collect()
    }
}

/// Hour-of-day / weekday histogram (off-hours = a rare bucket).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalStat {
    pub hour: [u64; 24],
    pub weekday: [u64; 7],
    pub total: u64,
}

impl TemporalStat {
    fn observe(&mut self, hour: u8, weekday: u8) {
        if (hour as usize) < 24 {
            self.hour[hour as usize] += 1;
        }
        if (weekday as usize) < 7 {
            self.weekday[weekday as usize] += 1;
        }
        self.total += 1;
    }
    /// True if this hour is rare vs the entity's peak hour — never seen, or below
    /// 10% of the busiest hour. Robust to a spread-out schedule.
    pub fn hour_is_rare(&self, hour: u8, min_total: u64) -> bool {
        if self.total < min_total || (hour as usize) >= 24 {
            return false;
        }
        let c = self.hour[hour as usize];
        if c == 0 {
            return true;
        }
        let peak = *self.hour.iter().max().unwrap_or(&0);
        (c as f64) < (peak as f64) * 0.1
    }
}

/// Robust numeric stats for a dimension (deviation = far above the norm).
/// Keeps running sum/sum-sq for mean/stddev and a bounded sorted sample for
/// median/MAD (deterministic — no randomness).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumericStat {
    pub count: u64,
    pub sum: f64,
    pub sum_sq: f64,
    pub min: f64,
    pub max: f64,
    /// Bounded ascending sample for median/MAD.
    pub sample: Vec<f64>,
}

const NUMERIC_SAMPLE_CAP: usize = 512;

impl Default for NumericStat {
    fn default() -> Self {
        NumericStat {
            count: 0,
            sum: 0.0,
            sum_sq: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            sample: Vec::new(),
        }
    }
}

impl NumericStat {
    fn observe(&mut self, x: f64) {
        if !x.is_finite() {
            return;
        }
        self.count += 1;
        self.sum += x;
        self.sum_sq += x * x;
        self.min = self.min.min(x);
        self.max = self.max.max(x);
        if self.sample.len() < NUMERIC_SAMPLE_CAP {
            let pos = self.sample.partition_point(|&v| v < x);
            self.sample.insert(pos, x);
        }
    }
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }
    pub fn stddev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let n = self.count as f64;
        ((self.sum_sq - self.sum * self.sum / n) / (n - 1.0))
            .max(0.0)
            .sqrt()
    }
    pub fn median(&self) -> f64 {
        let s = &self.sample;
        if s.is_empty() {
            return 0.0;
        }
        let m = s.len() / 2;
        if s.len() % 2 == 1 {
            s[m]
        } else {
            (s[m - 1] + s[m]) / 2.0
        }
    }
    /// Median absolute deviation (robust spread).
    pub fn mad(&self) -> f64 {
        let s = &self.sample;
        if s.is_empty() {
            return 0.0;
        }
        let med = self.median();
        let mut dev: Vec<f64> = s.iter().map(|&v| (v - med).abs()).collect();
        dev.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let m = dev.len() / 2;
        if dev.len() % 2 == 1 {
            dev[m]
        } else {
            (dev[m - 1] + dev[m]) / 2.0
        }
    }
    /// Robust upper-tail z-score of `x` vs the baseline (0 if below the median).
    /// Uses MAD (scaled to a normal sigma) and falls back to stddev when MAD is
    /// degenerate. Only positive deviations count (we care about *high* volume).
    pub fn upper_z(&self, x: f64) -> f64 {
        let med = self.median();
        if x <= med {
            return 0.0;
        }
        let mad = self.mad();
        let sigma = if mad > 0.0 {
            1.4826 * mad
        } else {
            self.stddev()
        };
        if sigma <= 0.0 {
            // no spread ever seen: any value strictly above is notable.
            return if x > med { f64::INFINITY } else { 0.0 };
        }
        (x - med) / sigma
    }
}

// =========================================================================
// profile
// =========================================================================

/// A per-entity behavioral profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub entity: Entity,
    #[serde(default)]
    pub state: BaselineState,
    pub observation_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default)]
    pub distinct_sources: BTreeSet<String>,
    /// True if any observation carried a low/untrusted source_trust or a parser
    /// failure marker (degrades maturity).
    #[serde(default)]
    pub data_quality_degraded: bool,
    #[serde(default)]
    pub categorical: BTreeMap<Dimension, CategoricalStat>,
    #[serde(default)]
    pub temporal: BTreeMap<Dimension, TemporalStat>,
    #[serde(default)]
    pub numeric: BTreeMap<Dimension, NumericStat>,
}

impl BaselineProfile {
    fn new(entity: Entity) -> Self {
        BaselineProfile {
            entity,
            state: BaselineState::Candidate,
            observation_count: 0,
            first_seen: None,
            last_seen: None,
            distinct_sources: BTreeSet::new(),
            data_quality_degraded: false,
            categorical: BTreeMap::new(),
            temporal: BTreeMap::new(),
            numeric: BTreeMap::new(),
        }
    }

    fn observe(&mut self, rec: &AuditRecord, ts: DateTime<Utc>, source: &str) {
        self.observation_count += 1;
        self.first_seen = Some(self.first_seen.map_or(ts, |f| f.min(ts)));
        self.last_seen = Some(self.last_seen.map_or(ts, |l| l.max(ts)));
        if !source.is_empty() {
            self.distinct_sources.insert(source.to_string());
        }
        // A low source_trust or a "low" parser confidence degrades data quality.
        if matches!(
            rec.classification.source_trust.as_deref(),
            Some("low") | Some("untrusted")
        ) {
            self.data_quality_degraded = true;
        }

        // Categorical dimensions share a single extraction with the query path
        // (`categorical_value`) so learn-time and detect-time never disagree.
        for &d in Dimension::CATEGORICAL {
            if let Some(v) = categorical_value(rec, d) {
                self.categorical.entry(d).or_default().observe(&v, ts);
            }
        }

        let temporal = self.temporal.entry(Dimension::HourOfDay).or_default();
        temporal.observe(ts.hour() as u8, ts.weekday().num_days_from_monday() as u8);
        // Weekday shares the same tracker instance (HourOfDay holds both arrays).

        if let Some(n) = rec.action.rows_read {
            self.numeric
                .entry(Dimension::RowsRead)
                .or_default()
                .observe(n as f64);
        }
        if let Some(n) = rec.action.bytes_read {
            self.numeric
                .entry(Dimension::BytesRead)
                .or_default()
                .observe(n as f64);
        }
    }

    /// Wall-clock span covered by observations.
    pub fn span(&self) -> Duration {
        match (self.first_seen, self.last_seen) {
            (Some(f), Some(l)) => l - f,
            _ => Duration::zero(),
        }
    }

    /// Current maturity, given the promotion policy.
    pub fn maturity(&self, policy: &PromotionPolicy) -> Maturity {
        if self.state == BaselineState::Suspicious {
            return Maturity::Suspicious;
        }
        if self.observation_count == 0 {
            return Maturity::Empty;
        }
        if self.state == BaselineState::Trusted {
            if self.data_quality_degraded {
                return Maturity::Degraded;
            }
            return Maturity::Stable;
        }
        // Candidate/other: Learning until it meets the thresholds, then Candidate.
        if auto_blocks(&PromotionContext::ready(self, policy)).is_empty() {
            Maturity::Candidate
        } else {
            Maturity::Learning
        }
    }
}

// =========================================================================
// promotion policy + gates (mirrors the environment-model gate)
// =========================================================================

/// Thresholds a Candidate must meet before it can become Trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionPolicy {
    pub min_observations: u64,
    pub min_span_secs: i64,
    pub min_distinct_sources: usize,
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        // A user baseline legitimately comes from one collector, so distinct-
        // sources defaults to 1; observations + span guard against a thin/poisoned
        // profile.
        PromotionPolicy {
            min_observations: 30,
            min_span_secs: 3 * 24 * 3600,
            min_distinct_sources: 1,
        }
    }
}

/// Why a promotion is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionBlock {
    OpenCaseTouchesEntity,
    EntityCompromised,
    PolicyViolationInWindow,
    ParserIntegrityFailure,
    /// The profile is marked Suspicious (a compromise / policy violation touched
    /// it). It must be explicitly cleared after human review before it can ever
    /// be promoted again — never silently re-trusted.
    EntitySuspicious,
    InsufficientObservations,
    InsufficientSpan,
    InsufficientDistinctSources,
    RequiresAnalystApproval,
}

/// The context a promotion decision is made in.
pub struct PromotionContext<'a> {
    pub profile: &'a BaselineProfile,
    pub policy: &'a PromotionPolicy,
    /// The entity currently has an open security case.
    pub entity_has_open_case: bool,
    /// The entity/identity is known-compromised.
    pub entity_compromised: bool,
    /// The entity committed a policy violation within the learning window.
    pub policy_violation_in_window: bool,
    /// The audit/parser integrity for this entity's data is intact.
    pub parser_integrity_ok: bool,
    /// High-impact profiles always require analyst approval (never auto).
    pub requires_analyst_approval: bool,
}

impl<'a> PromotionContext<'a> {
    /// A context with only the profile/policy set (all guards clear) — for the
    /// maturity computation and threshold checks.
    fn ready(profile: &'a BaselineProfile, policy: &'a PromotionPolicy) -> Self {
        PromotionContext {
            profile,
            policy,
            entity_has_open_case: false,
            entity_compromised: false,
            policy_violation_in_window: false,
            parser_integrity_ok: true,
            requires_analyst_approval: false,
        }
    }
}

/// Inviolable blocks — no promotion path (auto OR analyst) may cross these.
/// A forbidden/compromised/under-investigation entity's behavior is never
/// learnable as normal.
pub fn hard_blocks(ctx: &PromotionContext) -> Vec<PromotionBlock> {
    let mut b = Vec::new();
    if ctx.entity_has_open_case {
        b.push(PromotionBlock::OpenCaseTouchesEntity);
    }
    if ctx.entity_compromised {
        b.push(PromotionBlock::EntityCompromised);
    }
    if ctx.policy_violation_in_window {
        b.push(PromotionBlock::PolicyViolationInWindow);
    }
    if !ctx.parser_integrity_ok {
        b.push(PromotionBlock::ParserIntegrityFailure);
    }
    b
}

/// Threshold blocks — clearable by analyst approval, not by auto-promotion.
pub fn auto_blocks(ctx: &PromotionContext) -> Vec<PromotionBlock> {
    let mut b = Vec::new();
    let p = ctx.profile;
    if p.observation_count < ctx.policy.min_observations {
        b.push(PromotionBlock::InsufficientObservations);
    }
    if p.span().num_seconds() < ctx.policy.min_span_secs {
        b.push(PromotionBlock::InsufficientSpan);
    }
    if p.distinct_sources.len() < ctx.policy.min_distinct_sources {
        b.push(PromotionBlock::InsufficientDistinctSources);
    }
    if ctx.requires_analyst_approval {
        b.push(PromotionBlock::RequiresAnalystApproval);
    }
    b
}

/// May this profile be AUTO-promoted (no analyst)? All hard + threshold blocks
/// must be clear.
pub fn may_auto_promote(ctx: &PromotionContext) -> bool {
    hard_blocks(ctx).is_empty() && auto_blocks(ctx).is_empty()
}

/// May an ANALYST promote this profile? Only the inviolable hard blocks apply.
pub fn may_analyst_promote(ctx: &PromotionContext) -> bool {
    hard_blocks(ctx).is_empty()
}

// =========================================================================
// detector-facing verdicts (Trusted-only)
// =========================================================================

/// A novelty verdict. `novel` is true ONLY for a Trusted baseline that has never
/// seen the value; a Candidate/learning baseline returns `novel=false` with its
/// maturity so the detector can abstain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Novelty {
    pub novel: bool,
    pub maturity: Maturity,
    pub dimension: Dimension,
    pub value: String,
    pub trusted_distinct: usize,
}

/// An off-hours verdict (Trusted-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffHours {
    pub off_hours: bool,
    pub maturity: Maturity,
    pub hour: u8,
}

/// A numeric-deviation verdict (Trusted-only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deviation {
    pub deviating: bool,
    pub upper_z: f64,
    pub maturity: Maturity,
    pub dimension: Dimension,
}

// =========================================================================
// store
// =========================================================================

/// Serde glue: store the tuple-keyed profile map as a flat array of profiles
/// (each profile already carries its `entity`), because a JSON object cannot
/// have a non-string key. Rebuilt into the map on deserialize.
mod profiles_as_seq {
    use super::{BTreeMap, BaselineProfile, Entity, EntityKind};
    use serde::de::Deserializer;
    use serde::ser::{SerializeSeq, Serializer};
    use serde::Deserialize;

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<(EntityKind, String), BaselineProfile>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(map.len()))?;
        for p in map.values() {
            seq.serialize_element(p)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<(EntityKind, String), BaselineProfile>, D::Error> {
        let profiles = Vec::<BaselineProfile>::deserialize(d)?;
        Ok(profiles
            .into_iter()
            .map(|p| {
                let e = Entity::new(p.entity.kind, p.entity.id.clone());
                (e.key(), p)
            })
            .collect())
    }
}

/// The behavioral-baseline store: per-entity profiles.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BaselineStore {
    // Serialized as a JSON array (each profile carries its own `entity`): a
    // `BTreeMap` with a tuple key is not a valid JSON object, so a plain derive
    // would fail to serialize. On load the map is rebuilt from each entity key.
    #[serde(with = "profiles_as_seq", default)]
    profiles: BTreeMap<(EntityKind, String), BaselineProfile>,
    #[serde(default)]
    pub policy: PromotionPolicy,
    /// Robust-z threshold for a numeric deviation to fire.
    #[serde(default = "default_z")]
    pub deviation_z: f64,
    /// Minimum observations before off-hours/deviation are meaningful.
    #[serde(default = "default_min_conf")]
    pub min_confidence: u64,
}

fn default_z() -> f64 {
    3.5
}
fn default_min_conf() -> u64 {
    20
}

impl BaselineStore {
    pub fn new(policy: PromotionPolicy) -> Self {
        BaselineStore {
            profiles: BTreeMap::new(),
            policy,
            deviation_z: default_z(),
            min_confidence: default_min_conf(),
        }
    }

    /// Fold one access into the CANDIDATE baselines of every entity it implies:
    /// the actor (User or ServiceAccount), the application, and the role. The
    /// caller MUST NOT feed a policy-denied access here (see the module invariant).
    pub fn observe(&mut self, rec: &AuditRecord, ts: DateTime<Utc>, source: &str) {
        for e in derived_entities(rec) {
            self.observe_into(&e, rec, ts, source);
        }
    }

    /// Fold an access into one explicit entity's profile — used for peer-group
    /// profiles, where the caller supplies the group membership.
    pub fn observe_into(
        &mut self,
        entity: &Entity,
        rec: &AuditRecord,
        ts: DateTime<Utc>,
        source: &str,
    ) {
        // A Trusted/Retired profile is frozen; learning continues only for
        // Candidate/Suspicious (Suspicious keeps accumulating evidence but never
        // answers queries).
        let prof = self
            .profiles
            .entry(entity.key())
            .or_insert_with(|| BaselineProfile::new(entity.clone()));
        if matches!(
            prof.state,
            BaselineState::Candidate | BaselineState::Suspicious
        ) {
            prof.observe(rec, ts, source);
        }
    }

    pub fn get(&self, entity: &Entity) -> Option<&BaselineProfile> {
        self.profiles.get(&entity.key())
    }
    pub fn profiles(&self) -> impl Iterator<Item = &BaselineProfile> {
        self.profiles.values()
    }
    pub fn len(&self) -> usize {
        self.profiles.len()
    }
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// The maturity of an entity's profile (Empty if none).
    pub fn maturity(&self, entity: &Entity) -> Maturity {
        self.get(entity)
            .map_or(Maturity::Empty, |p| p.maturity(&self.policy))
    }

    /// Promote an entity's profile to Trusted, honoring `ctx` (fill the guards
    /// from the surrounding system: open cases, compromise, policy violations,
    /// parser integrity). Returns the blocks if refused; `analyst` allows
    /// clearing threshold blocks. On success the state becomes Trusted.
    pub fn promote(
        &mut self,
        entity: &Entity,
        analyst: bool,
        guards: PromotionGuards,
    ) -> Result<(), Vec<PromotionBlock>> {
        let blocks = self.promotion_blocks(entity, analyst, guards);
        if !blocks.is_empty() {
            return Err(blocks);
        }
        // Re-fetch mutably only now that we know it's allowed.
        if let Some(prof) = self.profiles.get_mut(&entity.key()) {
            prof.state = BaselineState::Trusted;
        }
        Ok(())
    }

    /// The blocks that WOULD prevent promoting `entity` right now, WITHOUT
    /// mutating — so a caller can audit fail-closed *before* applying (empty ⇒
    /// promotion is allowed). Mirrors [`BaselineStore::promote`]'s decision.
    pub fn promotion_blocks(
        &self,
        entity: &Entity,
        analyst: bool,
        guards: PromotionGuards,
    ) -> Vec<PromotionBlock> {
        let Some(prof) = self.profiles.get(&entity.key()) else {
            return vec![PromotionBlock::InsufficientObservations];
        };
        // A Suspicious profile is never silently re-trusted: it must be cleared
        // by a human (`clear_suspicion`) after review first.
        if prof.state == BaselineState::Suspicious {
            return vec![PromotionBlock::EntitySuspicious];
        }
        let ctx = PromotionContext {
            profile: prof,
            policy: &self.policy,
            entity_has_open_case: guards.entity_has_open_case,
            entity_compromised: guards.entity_compromised,
            policy_violation_in_window: guards.policy_violation_in_window,
            parser_integrity_ok: guards.parser_integrity_ok(),
            requires_analyst_approval: guards.requires_analyst_approval,
        };
        let ok = if analyst {
            may_analyst_promote(&ctx)
        } else {
            may_auto_promote(&ctx)
        };
        if ok {
            Vec::new()
        } else if analyst {
            hard_blocks(&ctx)
        } else {
            let mut all = hard_blocks(&ctx);
            all.extend(auto_blocks(&ctx));
            all
        }
    }

    /// Mark a profile Suspicious (compromise / policy violation touched it): it
    /// stops answering queries and can no longer be trusted without review.
    pub fn mark_suspicious(&mut self, entity: &Entity) {
        if let Some(p) = self.profiles.get_mut(&entity.key()) {
            p.state = BaselineState::Suspicious;
        }
    }

    /// Clear a Suspicious marking after human review, returning the profile to
    /// Candidate so it can re-learn and (once it re-earns trust) be promoted
    /// again. No-op unless the profile is currently Suspicious.
    pub fn clear_suspicion(&mut self, entity: &Entity) {
        if let Some(p) = self.profiles.get_mut(&entity.key()) {
            if p.state == BaselineState::Suspicious {
                p.state = BaselineState::Candidate;
            }
        }
    }

    // ---- detector queries (Trusted profiles only) ----------------------

    fn trusted(&self, entity: &Entity) -> Option<&BaselineProfile> {
        self.get(entity)
            .filter(|p| p.state == BaselineState::Trusted)
    }

    /// Is `value` novel for `entity` on `dimension`? True only for a Trusted
    /// baseline that has never seen it.
    pub fn novelty(&self, entity: &Entity, dimension: Dimension, value: &str) -> Novelty {
        let maturity = self.maturity(entity);
        let (novel, distinct) = match self
            .trusted(entity)
            .and_then(|p| p.categorical.get(&dimension))
        {
            Some(stat) => (!stat.contains(value), stat.distinct()),
            None => (false, 0), // no trusted baseline → abstain (never novel)
        };
        Novelty {
            novel,
            maturity,
            dimension,
            value: value.to_string(),
            trusted_distinct: distinct,
        }
    }

    /// Is `hour` off-hours for `entity`? True only for a Trusted baseline with
    /// enough history where the hour is rare.
    pub fn off_hours(&self, entity: &Entity, hour: u8) -> OffHours {
        let maturity = self.maturity(entity);
        let off = self
            .trusted(entity)
            .and_then(|p| p.temporal.get(&Dimension::HourOfDay))
            .map(|t| t.hour_is_rare(hour, self.min_confidence))
            .unwrap_or(false);
        OffHours {
            off_hours: off,
            maturity,
            hour,
        }
    }

    /// Does `value` deviate high on a numeric `dimension` for `entity`? True only
    /// for a Trusted baseline with enough history and an upper-z over threshold.
    pub fn deviation(&self, entity: &Entity, dimension: Dimension, value: f64) -> Deviation {
        let maturity = self.maturity(entity);
        let (deviating, z) = match self.trusted(entity).and_then(|p| p.numeric.get(&dimension)) {
            Some(stat) if stat.count >= self.min_confidence => {
                let z = stat.upper_z(value);
                (z >= self.deviation_z, z)
            }
            _ => (false, 0.0),
        };
        Deviation {
            deviating,
            upper_z: z,
            maturity,
            dimension,
        }
    }

    /// Peer-group novelty: values the user uses on `dimension` that NO peer in
    /// the group's Trusted baseline uses — a material deviation from the peer
    /// norm. Empty when either baseline is not Trusted.
    pub fn peer_novelty(
        &self,
        user: &Entity,
        peer_group: &Entity,
        dimension: Dimension,
    ) -> Vec<String> {
        match (
            self.trusted(user)
                .and_then(|p| p.categorical.get(&dimension)),
            self.trusted(peer_group)
                .and_then(|p| p.categorical.get(&dimension)),
        ) {
            (Some(u), Some(g)) => u.not_in(g),
            _ => Vec::new(),
        }
    }

    /// Content digest of the store (version-prefixed), for a stored snapshot id.
    pub fn digest(&self) -> String {
        // Serialize the profiles as a flat list (a tuple-keyed map is not valid
        // JSON) so the digest reflects real content, not an empty fallback.
        let profiles: Vec<&BaselineProfile> = self.profiles.values().collect();
        let json = serde_json::to_vec(&profiles).unwrap_or_default();
        format!("{BASELINE_VERSION}:{}", &blake3::hash(&json).to_hex()[..32])
    }
}

/// The promotion guards the surrounding system supplies (defaults are the safe,
/// all-clear values — set the ones your system knows).
#[derive(Debug, Clone, Copy, Default)]
pub struct PromotionGuards {
    pub entity_has_open_case: bool,
    pub entity_compromised: bool,
    pub policy_violation_in_window: bool,
    pub requires_analyst_approval: bool,
    pub parser_integrity_ok_override: Option<bool>,
}

impl PromotionGuards {
    fn parser_integrity_ok(&self) -> bool {
        self.parser_integrity_ok_override.unwrap_or(true)
    }
}

/// The primary actor entity an access implies — a `ServiceAccount` when the
/// record is flagged as one, else a `User`. `None` when there is no actor id.
/// Detectors query the baseline for this entity.
pub fn actor_entity(rec: &AuditRecord) -> Option<Entity> {
    let id = rec.actor.actor_id.trim();
    if id.is_empty() {
        return None;
    }
    let kind = if rec.actor.service_account {
        EntityKind::ServiceAccount
    } else {
        EntityKind::User
    };
    Some(Entity::new(kind, id))
}

/// The categorical value an access carries on `dimension`, matching exactly what
/// [`BaselineProfile::observe`] folds in — the single source of truth so a
/// learned value and a queried value are extracted identically. Returns `None`
/// for a non-categorical dimension or an absent/empty value.
pub fn categorical_value(rec: &AuditRecord, dimension: Dimension) -> Option<String> {
    let v = match dimension {
        Dimension::QueryFingerprint => rec.action.statement_fingerprint.as_deref(),
        Dimension::Client => rec
            .context
            .client_application
            .as_deref()
            .or(rec.context.client_ip.as_deref())
            .or(rec.context.client_host.as_deref()),
        Dimension::SourceHost => rec.context.host.as_deref(),
        Dimension::Object => rec.action.object_name.as_deref(),
        Dimension::Operation => rec
            .action
            .query_type
            .map(|q| q.as_str())
            .or(rec.action.action.as_deref()),
        Dimension::Database => rec.context.database.as_deref(),
        Dimension::Schema => rec.context.database_schema.as_deref(),
        Dimension::SubjectType => rec.action.subject_type.as_deref(),
        _ => None,
    };
    v.filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// Which entities an access implies (actor + application + role). The actor is a
/// ServiceAccount when flagged, else a User.
fn derived_entities(rec: &AuditRecord) -> Vec<Entity> {
    let mut out = Vec::new();
    if !rec.actor.actor_id.trim().is_empty() {
        let kind = if rec.actor.service_account {
            EntityKind::ServiceAccount
        } else {
            EntityKind::User
        };
        out.push(Entity::new(kind, rec.actor.actor_id.clone()));
    }
    if let Some(app) = rec
        .context
        .application_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        out.push(Entity::new(EntityKind::Application, app));
    }
    if let Some(role) = rec.actor.actor_role.as_deref().filter(|s| !s.is_empty()) {
        out.push(Entity::new(EntityKind::Role, role));
    }
    out
}

#[cfg(test)]
mod tests;
