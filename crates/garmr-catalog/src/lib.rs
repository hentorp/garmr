// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 4 — the application & resource **catalog**.
//!
//! The catalog is garmr's governed inventory of the things a security decision
//! reasons *about*: the applications that touch data, the data sources /
//! databases / schemas / tables / views / API endpoints / document collections
//! they expose, which of those are sensitive and at what
//! [`DataClassification`], plus the roles, peer groups, approved clients,
//! maintenance windows and expected automation identities that make an access
//! "normal". Detectors ask "is this unusual?" and the policy engine asks "is
//! this *allowed*?" — both need a trustworthy answer to "*what is this thing,
//! and who is supposed to touch it?*". That answer lives here.
//!
//! ## Governance is the whole point — a Candidate is NOT the truth
//!
//! Anything the platform can *discover on its own* (from the Postgres catalog,
//! from an API import, or from mere observation of traffic) enters as a
//! [`ApprovalState::Candidate`]. A Candidate is **visible** — an analyst can see
//! it, review it, and promote it — but it **confers no sensitivity and no
//! expected-users set to any security decision**. Only a human-promoted
//! [`ApprovalState::Trusted`] entry resolves. This is a hard invariant: if a
//! discovered "sensitive" fact could silently make [`Catalog::is_sensitive`]
//! true, an attacker who can influence discovery could either *hide* a resource
//! (never happens — discovery cannot demote) or, worse, *poison* the inventory.
//! So resolution reads Trusted only. [`ApprovalState::Retired`] entries are
//! inactive and never resolve either.
//!
//! ## Pure, no I/O
//!
//! Every type is a plain serde value and every function is a pure computation
//! over in-memory data. The single exception is [`Catalog::from_toml`], which
//! parses a documented catalog file *text* (the caller reads the file) into
//! Candidate entries — it performs no I/O itself. Persistence (versioned,
//! human-approved, reversible) rides the existing registry-governance channel,
//! exactly like [`garmr_policy`](https://docs.rs/garmr-policy)'s policy set; this
//! crate is the modelling + resolution core.
//!
//! ## Object-name matching
//!
//! Resolution matches an accessed object name against a catalog entry's stored
//! name using [`object_pattern_matches`], which is deliberately consistent with
//! `garmr-policy`'s object matcher: exact (case-insensitive), an unqualified
//! match (`persons` matches `public.persons`), and a schema wildcard (`raw.*`
//! matches `raw.anything`).

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use garmr_core::AuditRecord;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// =========================================================================
// data classification
// =========================================================================

/// How sensitive a resource's data is. A small, ordered ladder of well-known
/// levels plus a [`DataClassification::Custom`] catch-all so a deployment can
/// carry its own labels without a code change. Serializes as a plain lowercase
/// string (`"confidential"`), which is exactly what the policy engine's
/// `data_classification` selector and the audit record's
/// `classification.data_classification` field expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataClassification {
    /// Freely shareable, no restriction.
    Public,
    /// Internal-use, not for external release.
    Internal,
    /// Confidential — includes ordinary personal data (PII).
    Confidential,
    /// Restricted — special-category / highly confidential data.
    Restricted,
    /// Secret — the most tightly held data.
    Secret,
    /// A deployment-specific label the code does not know by name. Carried
    /// verbatim; ranked between Internal and Confidential for ordering.
    Custom(String),
}

impl DataClassification {
    /// Parse a label (case-insensitive, tolerant of common synonyms). An empty
    /// or unrecognized label becomes [`DataClassification::Custom`] carrying the
    /// normalized text so nothing is silently dropped.
    pub fn parse(s: &str) -> DataClassification {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace([' ', '-'], "_")
            .as_str()
        {
            "public" | "open" | "unclassified" => DataClassification::Public,
            "internal" | "internal_use" | "internal_only" => DataClassification::Internal,
            "confidential" | "pii" | "personal" | "personal_data" | "sensitive" => {
                DataClassification::Confidential
            }
            "restricted" | "highly_confidential" | "special_category" => {
                DataClassification::Restricted
            }
            "secret" | "top_secret" => DataClassification::Secret,
            other => DataClassification::Custom(other.to_string()),
        }
    }

    /// The canonical lowercase label. For [`DataClassification::Custom`] this is
    /// the stored text.
    pub fn as_label(&self) -> String {
        match self {
            DataClassification::Public => "public".to_string(),
            DataClassification::Internal => "internal".to_string(),
            DataClassification::Confidential => "confidential".to_string(),
            DataClassification::Restricted => "restricted".to_string(),
            DataClassification::Secret => "secret".to_string(),
            DataClassification::Custom(s) => s.clone(),
        }
    }

    /// A sensitivity rank used when several matching entries disagree — the
    /// highest rank wins. A Custom label sits between Internal and Confidential
    /// because the code cannot know it is safe to rank it lower.
    pub fn rank(&self) -> u8 {
        match self {
            DataClassification::Public => 0,
            DataClassification::Internal => 1,
            DataClassification::Custom(_) => 2,
            DataClassification::Confidential => 3,
            DataClassification::Restricted => 4,
            DataClassification::Secret => 5,
        }
    }
}

impl Serialize for DataClassification {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_label())
    }
}

impl<'de> Deserialize<'de> for DataClassification {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(DataClassification::parse(&s))
    }
}

// =========================================================================
// object-name matching (consistent with garmr-policy)
// =========================================================================

/// Match a catalog entry's object pattern against an accessed object name.
///
/// Supports exact (case-insensitive), an unqualified match (`persons` matches
/// `public.persons`), and a schema wildcard (`raw.*` matches `raw.anything` as
/// well as the bare `raw`). Deliberately identical in behaviour to
/// `garmr-policy`'s object matcher so the catalog and the policy engine never
/// disagree about what an object name means.
pub fn object_pattern_matches(pattern: &str, obj: &str) -> bool {
    // Allocation-free: this runs per catalog entry per event on the app-audit
    // firehose (via `catalog.stamp`), and the old body did TWO `to_ascii_lowercase`
    // heap allocations (`pattern` + `obj`) on EVERY call. ASCII-case-insensitive
    // compares over the borrowed strs are byte-identical in behaviour with zero
    // allocation. (`.` / `.*` / `*` are ASCII, so structural checks need no fold.)
    if pattern.eq_ignore_ascii_case(obj) {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        // `o == prefix` OR `o` starts with `prefix.` — case-insensitively, and
        // over bytes so a multi-byte `obj` can never split on a char boundary.
        if obj.eq_ignore_ascii_case(prefix) {
            return true;
        }
        let (pb, ob) = (prefix.as_bytes(), obj.as_bytes());
        return ob.len() > pb.len()
            && ob[pb.len()] == b'.'
            && ob[..pb.len()].eq_ignore_ascii_case(pb);
    }
    // An unqualified pattern matches the last dotted segment of the object.
    !pattern.contains('.')
        && obj.rsplit('.').next().is_some_and(|seg| seg.eq_ignore_ascii_case(pattern))
}

/// The monotonic object-resolution reduction, shared by the linear
/// [`Catalog::resolve_object_at`] and the indexed [`ObjectIndex::resolve_object_at`].
/// `cands` yields candidate entries **in original `entries` order**; each is
/// filtered by `is_effective(at)` → `object_facts` → [`object_pattern_matches`],
/// then folded: monotonic `sensitive`, FIRST-seen `application`/`owner` (so order
/// matters — callers pass candidates in entries order), highest-rank
/// `classification`, and the union of `expected_users`. Byte-identical whether the
/// candidate set is all entries or an index-narrowed subset.
fn reduce_object_matches<'a>(
    cands: impl Iterator<Item = &'a CatalogEntry>,
    name: &str,
    at: Option<DateTime<Utc>>,
) -> Option<ResolvedResource> {
    let mut matched = false;
    let mut out = ResolvedResource::default();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    let mut best_rank: Option<u8> = None;

    for entry in cands {
        if !entry.is_effective(at) {
            continue;
        }
        let Some(f) = entry.resource.object_facts() else {
            continue;
        };
        if !object_pattern_matches(f.pattern, name) {
            continue;
        }
        matched = true;
        out.sensitive |= f.sensitive;
        if out.application.is_none() {
            out.application = f.application.map(str::to_string);
        }
        if out.owner.is_none() {
            out.owner = f.owner.map(str::to_string);
        }
        if let Some(c) = f.classification {
            if best_rank.is_none_or(|r| c.rank() > r) {
                best_rank = Some(c.rank());
                out.classification = Some(c);
            }
        }
        expected.extend(f.expected_users.iter().cloned());
    }

    if !matched {
        return None;
    }
    out.expected_users = expected.into_iter().collect();
    Some(out)
}

/// The accessed object name a record resolves against: `object_name`, else the
/// `resource_path` fallback. Shared by [`Catalog::enrich`] and [`ObjectIndex`].
fn record_object_name(rec: &AuditRecord) -> Option<&str> {
    rec.action
        .object_name
        .as_deref()
        .or(rec.action.resource_path.as_deref())
}

/// Lower a [`ResolvedResource`] into an [`Enrichment`]. Shared so the linear and
/// indexed enrichment paths produce identical output.
fn enrichment_from(resolved: Option<ResolvedResource>) -> Enrichment {
    match resolved {
        Some(r) => Enrichment {
            data_classification: r.classification.map(|c| c.as_label()),
            sensitive_resource: r.sensitive,
            application: r.application,
            owner: r.owner,
            expected_users: r.expected_users,
        },
        None => Enrichment::default(),
    }
}

/// Apply an [`Enrichment`] to a record in place — additive only (sets
/// `data_classification`, raises but never clears `sensitive_resource`). Shared by
/// [`Catalog::stamp`] and [`ObjectIndex::stamp`].
fn apply_enrichment(rec: &mut AuditRecord, enr: Enrichment) {
    if let Some(c) = enr.data_classification {
        rec.classification.data_classification = Some(c);
    }
    if enr.sensitive_resource {
        rec.classification.sensitive_resource = true;
    }
}

/// A prebuilt, case-folded index of a [`Catalog`]'s object-bearing entry PATTERNS,
/// so per-event object resolution is **O(matching entries + wildcards)** instead of
/// a full O(entries) scan. It owns its keys + entry indices (no borrow of the
/// catalog), so a hot caller (the app-audit plane) builds it ONCE via
/// [`Catalog::object_index`] and reuses it across events, passing
/// `&catalog.entries` back in at query time. Rebuild it whenever the catalog's
/// entries change (it is a snapshot of their patterns by position).
#[derive(Debug, Clone, Default)]
pub struct ObjectIndex {
    /// lower(pattern) → entry indices, for dotted non-wildcard patterns (match
    /// requires `lower(obj) == pattern`).
    exact: std::collections::HashMap<String, Vec<u32>>,
    /// lower(pattern) → entry indices, for unqualified (no-dot) patterns (match
    /// requires the object's LAST dotted segment == pattern).
    unqualified: std::collections::HashMap<String, Vec<u32>>,
    /// (lower(prefix), entry index) for `prefix.*` wildcard patterns (few).
    wildcards: Vec<(String, u32)>,
}

impl ObjectIndex {
    /// Resolve an accessed object name against the entries this index was built
    /// from — byte-identical to [`Catalog::resolve_object_at`], but only the
    /// name-matching candidates are folded. `entries` MUST be the same slice the
    /// index was built from (same order/length).
    pub fn resolve_object_at(
        &self,
        entries: &[CatalogEntry],
        name: &str,
        at: Option<DateTime<Utc>>,
    ) -> Option<ResolvedResource> {
        let o = name.to_ascii_lowercase();
        let last = o.rsplit('.').next().unwrap_or(o.as_str());
        let mut cand: Vec<u32> = Vec::new();
        if let Some(v) = self.exact.get(&o) {
            cand.extend_from_slice(v);
        }
        if let Some(v) = self.unqualified.get(last) {
            cand.extend_from_slice(v);
        }
        for (prefix, i) in &self.wildcards {
            let (ob, pb) = (o.as_bytes(), prefix.as_bytes());
            let hit = o == *prefix
                || (ob.len() > pb.len() && ob[pb.len()] == b'.' && &ob[..pb.len()] == pb);
            if hit {
                cand.push(*i);
            }
        }
        // Fold in ORIGINAL entries order so the first-seen application/owner picks
        // match the linear scan exactly; dedup guards a name that hits two buckets.
        cand.sort_unstable();
        cand.dedup();
        reduce_object_matches(cand.iter().map(|&i| &entries[i as usize]), name, at)
    }

    /// Time-agnostic [`ObjectIndex::resolve_object_at`] (`at = None`) — the
    /// enrichment path, mirroring [`Catalog::resolve_object`].
    pub fn resolve_object(
        &self,
        entries: &[CatalogEntry],
        name: &str,
    ) -> Option<ResolvedResource> {
        self.resolve_object_at(entries, name, None)
    }

    /// Index-backed [`Catalog::enrich`].
    pub fn enrich(&self, entries: &[CatalogEntry], rec: &AuditRecord) -> Enrichment {
        match record_object_name(rec) {
            Some(name) => enrichment_from(self.resolve_object(entries, name)),
            None => Enrichment::default(),
        }
    }

    /// Index-backed [`Catalog::stamp`] — identical additive effect, O(matches).
    pub fn stamp(&self, entries: &[CatalogEntry], rec: &mut AuditRecord) {
        let enr = self.enrich(entries, rec);
        apply_enrichment(rec, enr);
    }
}

// =========================================================================
// resource kinds
// =========================================================================

/// A named application — the top-level unit the catalog is organized around.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Application {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The people or teams responsible for the application.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub team: Vec<String>,
}

/// A concrete running instance of an [`Application`] in some environment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationInstance {
    /// The parent application name.
    pub application: String,
    /// An instance label (e.g. `prod-eu-1`).
    pub instance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// A data source an application reads from or writes to (a Postgres cluster, an
/// object store, an HTTP API, …).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSource {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// The kind of source (`postgres`, `s3`, `http`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// A database within a [`DataSource`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Database {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// A schema within a [`Database`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// A table — a resolvable object that can carry a classification, a sensitive
/// flag, and an expected-users set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    /// The object name; may be schema-qualified (`raw.persons`) or a pattern
    /// (`raw.*`) understood by [`object_pattern_matches`].
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<DataClassification>,
    #[serde(default)]
    pub sensitive: bool,
    /// Users/roles expected to access this object.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
    /// The category of data subject this object concerns (e.g. `person`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_subject_type: Option<String>,
}

/// A view — the same resolvable shape as a [`Table`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct View {
    /// The object name; may be schema-qualified or a `schema.*` pattern.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<DataClassification>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_subject_type: Option<String>,
}

/// An HTTP API endpoint — a resolvable object keyed by its path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiEndpoint {
    /// The endpoint path (also the object key for resolution).
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<DataClassification>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
}

/// A document collection (a bucket, an index, a folder of records).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentCollection {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<DataClassification>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
}

/// An explicitly sensitive resource with a mandatory [`DataClassification`].
/// Distinct from a merely `sensitive`-flagged table so an analyst can register a
/// cross-object sensitivity (e.g. a whole `raw.*` namespace) with its data
/// classification and its expected accessors in one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveResource {
    /// The object name or pattern the sensitivity applies to.
    pub object: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The classification of the data behind this resource.
    pub classification: DataClassification,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_subject_type: Option<String>,
}

/// A named user role and its members — an expected-users source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRole {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A peer group — actors expected to behave alike, used by peer-outlier
/// detection and as an expected-users source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerGroup {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
}

/// A client identity (a client application or an actor id) approved for an
/// application, optionally constrained to a set of client-IP prefixes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedClient {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_ip_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A maintenance window — a time range during which otherwise-unusual
/// administrative activity is expected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// An automation identity (a service account / bot) expected for an
/// application — the "known-good robots" list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedAutomationIdentity {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default)]
    pub service_account: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The tagged union of everything a [`CatalogEntry`] can describe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    Application(Application),
    ApplicationInstance(ApplicationInstance),
    DataSource(DataSource),
    Database(Database),
    Schema(Schema),
    Table(Table),
    View(View),
    ApiEndpoint(ApiEndpoint),
    DocumentCollection(DocumentCollection),
    SensitiveResource(SensitiveResource),
    UserRole(UserRole),
    PeerGroup(PeerGroup),
    ApprovedClient(ApprovedClient),
    MaintenanceWindow(MaintenanceWindow),
    ExpectedAutomationIdentity(ExpectedAutomationIdentity),
}

/// The resolvable facts a data-bearing resource contributes to a lookup. Only
/// the object-like kinds (table, view, API endpoint, document collection,
/// sensitive resource) produce these.
struct ObjectFacts<'a> {
    pattern: &'a str,
    application: Option<&'a str>,
    owner: Option<&'a str>,
    classification: Option<DataClassification>,
    sensitive: bool,
    expected_users: &'a [String],
}

impl Resource {
    /// The application this resource belongs to, if any.
    pub fn application(&self) -> Option<&str> {
        match self {
            Resource::Application(a) => Some(a.name.as_str()),
            Resource::ApplicationInstance(a) => Some(a.application.as_str()),
            Resource::DataSource(r) => r.application.as_deref(),
            Resource::Database(r) => r.application.as_deref(),
            Resource::Schema(r) => r.application.as_deref(),
            Resource::Table(r) => r.application.as_deref(),
            Resource::View(r) => r.application.as_deref(),
            Resource::ApiEndpoint(r) => r.application.as_deref(),
            Resource::DocumentCollection(r) => r.application.as_deref(),
            Resource::SensitiveResource(r) => r.application.as_deref(),
            Resource::UserRole(r) => r.application.as_deref(),
            Resource::PeerGroup(r) => r.application.as_deref(),
            Resource::ApprovedClient(r) => r.application.as_deref(),
            Resource::MaintenanceWindow(r) => r.application.as_deref(),
            Resource::ExpectedAutomationIdentity(r) => r.application.as_deref(),
        }
    }

    /// The snake_case kind tag — identical to the serde `kind` discriminant, so a
    /// resource-inventory row can label the kind without re-serializing.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Resource::Application(_) => "application",
            Resource::ApplicationInstance(_) => "application_instance",
            Resource::DataSource(_) => "data_source",
            Resource::Database(_) => "database",
            Resource::Schema(_) => "schema",
            Resource::Table(_) => "table",
            Resource::View(_) => "view",
            Resource::ApiEndpoint(_) => "api_endpoint",
            Resource::DocumentCollection(_) => "document_collection",
            Resource::SensitiveResource(_) => "sensitive_resource",
            Resource::UserRole(_) => "user_role",
            Resource::PeerGroup(_) => "peer_group",
            Resource::ApprovedClient(_) => "approved_client",
            Resource::MaintenanceWindow(_) => "maintenance_window",
            Resource::ExpectedAutomationIdentity(_) => "expected_automation_identity",
        }
    }

    /// The object-facts this resource contributes to name resolution, if it is a
    /// data-bearing (object-like) kind.
    fn object_facts(&self) -> Option<ObjectFacts<'_>> {
        match self {
            Resource::Table(t) => Some(ObjectFacts {
                pattern: &t.name,
                application: t.application.as_deref(),
                owner: t.owner.as_deref(),
                classification: t.classification.clone(),
                sensitive: t.sensitive,
                expected_users: &t.expected_users,
            }),
            Resource::View(v) => Some(ObjectFacts {
                pattern: &v.name,
                application: v.application.as_deref(),
                owner: v.owner.as_deref(),
                classification: v.classification.clone(),
                sensitive: v.sensitive,
                expected_users: &v.expected_users,
            }),
            Resource::ApiEndpoint(e) => Some(ObjectFacts {
                pattern: &e.path,
                application: e.application.as_deref(),
                owner: e.owner.as_deref(),
                classification: e.classification.clone(),
                sensitive: e.sensitive,
                expected_users: &e.expected_users,
            }),
            Resource::DocumentCollection(c) => Some(ObjectFacts {
                pattern: &c.name,
                application: c.application.as_deref(),
                owner: c.owner.as_deref(),
                classification: c.classification.clone(),
                sensitive: c.sensitive,
                expected_users: &c.expected_users,
            }),
            Resource::SensitiveResource(s) => Some(ObjectFacts {
                pattern: &s.object,
                application: s.application.as_deref(),
                owner: s.owner.as_deref(),
                classification: Some(s.classification.clone()),
                // A SensitiveResource is sensitive by definition.
                sensitive: true,
                expected_users: &s.expected_users,
            }),
            _ => None,
        }
    }

    /// The members/expected-users this resource contributes for an application.
    fn expected_members(&self) -> &[String] {
        match self {
            Resource::Table(t) => &t.expected_users,
            Resource::View(v) => &v.expected_users,
            Resource::ApiEndpoint(e) => &e.expected_users,
            Resource::DocumentCollection(c) => &c.expected_users,
            Resource::SensitiveResource(s) => &s.expected_users,
            Resource::UserRole(r) => &r.members,
            Resource::PeerGroup(g) => &g.members,
            _ => &[],
        }
    }
}

// =========================================================================
// governance
// =========================================================================

/// Where a catalog entry came from. Discovery sources (everything except
/// [`CatalogSource::Manual`]) always enter as [`ApprovalState::Candidate`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogSource {
    /// Hand-authored by an operator.
    #[default]
    Manual,
    /// Imported from a catalog file ([`Catalog::from_toml`]).
    FileImport,
    /// Imported from an external catalog/CMDB API.
    ApiImport,
    /// Discovered by reading the Postgres system catalog.
    PgCatalogDiscovery,
    /// Inferred from observed traffic.
    Observation,
}

/// The approval lifecycle of a catalog fact. Only [`ApprovalState::Trusted`]
/// entries resolve for a security decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Proposed but not yet human-approved. Visible; confers nothing.
    #[default]
    Candidate,
    /// Human-promoted; the authoritative truth for resolution.
    Trusted,
    /// Withdrawn; inactive and never resolves.
    Retired,
}

/// One governed catalog fact: a [`Resource`] wrapped in its approval lifecycle,
/// versioning, validity window, authorship and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// Stable id for the fact (used for digest ordering and promotion).
    pub id: String,
    pub resource: Resource,
    #[serde(default)]
    pub approval: ApprovalState,
    #[serde(default)]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// Immutable audit-ledger references justifying the entry / its promotion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_refs: Vec<String>,
    #[serde(default)]
    pub source: CatalogSource,
}

impl CatalogEntry {
    /// A new Candidate entry from a discovery/import source.
    pub fn candidate(id: impl Into<String>, resource: Resource, source: CatalogSource) -> Self {
        CatalogEntry {
            id: id.into(),
            resource,
            approval: ApprovalState::Candidate,
            version: 0,
            valid_from: None,
            valid_until: None,
            created_by: String::new(),
            approved_by: None,
            audit_refs: Vec::new(),
            source,
        }
    }

    /// Is this entry trusted? (The sole gate for security resolution.)
    pub fn is_trusted(&self) -> bool {
        self.approval == ApprovalState::Trusted
    }

    /// Is this entry effective at `at` — trusted and (if a validity window is
    /// set) within `[valid_from, valid_until)`? With `at == None` only the
    /// approval state is checked. A Candidate or Retired entry is never
    /// effective, whatever the window.
    pub fn is_effective(&self, at: Option<DateTime<Utc>>) -> bool {
        if !self.is_trusted() {
            return false;
        }
        match at {
            None => true,
            Some(t) => {
                self.valid_from.is_none_or(|f| t >= f) && self.valid_until.is_none_or(|u| t < u)
            }
        }
    }

    /// Promote a Candidate to Trusted, recording the approver and bumping the
    /// version. Human promotion is the ONLY path to Trusted.
    pub fn promote(&mut self, approved_by: impl Into<String>) {
        self.approval = ApprovalState::Trusted;
        self.approved_by = Some(approved_by.into());
        self.version = self.version.saturating_add(1);
    }

    /// Retire the entry (it stops resolving).
    pub fn retire(&mut self) {
        self.approval = ApprovalState::Retired;
        self.version = self.version.saturating_add(1);
    }

    /// The object name/pattern this entry resolves against, if it is a
    /// data-bearing (object-like) resource; `None` for hierarchy/identity kinds
    /// (Application, Schema, UserRole, …). This is the same pattern the resolver
    /// and [`object_pattern_matches`] use, so a caller can attribute an accessed
    /// object to a resource with identical semantics to enforcement.
    pub fn object_pattern(&self) -> Option<&str> {
        self.resource.object_facts().map(|f| f.pattern)
    }

    /// A normalized, serializable summary of a data-bearing entry — the fields a
    /// resource inventory needs — without exposing the internal `ObjectFacts` or
    /// the per-kind field names. `None` for non-object kinds.
    pub fn object_summary(&self) -> Option<ObjectSummary> {
        let f = self.resource.object_facts()?;
        Some(ObjectSummary {
            kind: self.resource.kind_label(),
            pattern: f.pattern.to_string(),
            application: f.application.map(str::to_string),
            owner: f.owner.map(str::to_string),
            classification: f.classification.map(|c| c.as_label()),
            sensitive: f.sensitive,
            expected_users: f.expected_users.len(),
        })
    }

    /// The application this entry DECLARES (its governance facts) when the entry is
    /// an `Application` kind; `None` for every other resource kind. Lets a product
    /// surface list the declared application inventory and reconcile it against
    /// observed activity.
    pub fn application_declaration(&self) -> Option<AppDecl> {
        match &self.resource {
            Resource::Application(a) => Some(AppDecl {
                name: a.name.clone(),
                owner: a.owner.clone(),
                business_purpose: a.business_purpose.clone(),
                description: a.description.clone(),
                team: a.team.clone(),
            }),
            _ => None,
        }
    }
}

/// The governance facts a catalog `Application` entry declares.
#[derive(Debug, Clone, Serialize)]
pub struct AppDecl {
    pub name: String,
    pub owner: Option<String>,
    pub business_purpose: Option<String>,
    pub description: Option<String>,
    pub team: Vec<String>,
}

/// A normalized, public summary of a data-bearing [`CatalogEntry`] — the resource
/// facts an inventory / API needs, flattened across the per-kind `Resource`
/// variants so a consumer needn't know which field holds the object name.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectSummary {
    /// The `Resource` kind tag (`table` / `view` / `api_endpoint` / …).
    pub kind: &'static str,
    /// The object name/pattern it resolves against.
    pub pattern: String,
    pub application: Option<String>,
    pub owner: Option<String>,
    /// The data-classification label, if classified.
    pub classification: Option<String>,
    pub sensitive: bool,
    /// How many users are declared expected on this resource.
    pub expected_users: usize,
}

// =========================================================================
// resolution result & enrichment
// =========================================================================

/// The resolved facts about an accessed object, drawn from Trusted entries only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedResource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<DataClassification>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
}

/// The classification + sensitivity a caller can stamp onto an [`AuditRecord`]
/// before policy evaluation. Mirrors the two fields that live on
/// `AuditRecord::classification`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrichment {
    /// The canonical data-classification label, if the object resolved to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
    /// Whether the object resolved to a sensitive resource.
    #[serde(default)]
    pub sensitive_resource: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_users: Vec<String>,
}

// =========================================================================
// the catalog aggregate
// =========================================================================

/// The catalog aggregate: a set of governed [`CatalogEntry`] facts with the
/// resolution the policy engine and detectors call. Resolution reads Trusted
/// entries **only** — a Candidate is visible via [`Catalog::candidates`] but
/// confers no sensitivity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    /// A catalog over the given entries.
    pub fn new(entries: Vec<CatalogEntry>) -> Self {
        Catalog { entries }
    }

    /// Append an entry.
    pub fn push(&mut self, entry: CatalogEntry) {
        self.entries.push(entry);
    }

    /// The Trusted entries — the only ones that resolve.
    pub fn trusted(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(|e| e.is_trusted())
    }

    /// The Candidate entries — visible for review; they confer nothing.
    pub fn candidates(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries
            .iter()
            .filter(|e| e.approval == ApprovalState::Candidate)
    }

    /// Resolve an accessed object name against Trusted entries. Returns `None`
    /// when nothing (Trusted) matches. `at == None` ignores validity windows.
    pub fn resolve_object(&self, name: &str) -> Option<ResolvedResource> {
        self.resolve_object_at(name, None)
    }

    /// Time-aware [`Catalog::resolve_object`]: only entries effective at `at`
    /// (Trusted and inside their validity window) contribute.
    pub fn resolve_object_at(
        &self,
        name: &str,
        at: Option<DateTime<Utc>>,
    ) -> Option<ResolvedResource> {
        // The linear path: every entry is a candidate. For a hot, large catalog
        // build an [`ObjectIndex`] once and use its `resolve_object_at`, which
        // narrows the candidates to O(matches) via a pre-folded name index and
        // then runs this SAME reduction.
        reduce_object_matches(self.entries.iter(), name, at)
    }

    /// Is the named object sensitive? True only if a Trusted entry says so.
    /// A Candidate sensitive resource does NOT make this true.
    pub fn is_sensitive(&self, name: &str) -> bool {
        self.resolve_object(name).is_some_and(|r| r.sensitive)
    }

    /// The canonical classification label of the named object, from Trusted
    /// entries only.
    pub fn classification_of(&self, name: &str) -> Option<String> {
        self.resolve_object(name)
            .and_then(|r| r.classification)
            .map(|c| c.as_label())
    }

    /// The union of users expected to touch a given application, drawn from
    /// Trusted user-roles, peer-groups and object expected-users sets whose
    /// application matches (case-insensitive). Sorted and de-duplicated.
    pub fn expected_users_of(&self, application: &str) -> Vec<String> {
        let mut users: BTreeSet<String> = BTreeSet::new();
        for entry in self.trusted() {
            if entry
                .resource
                .application()
                .is_some_and(|a| a.eq_ignore_ascii_case(application))
            {
                users.extend(entry.resource.expected_members().iter().cloned());
            }
        }
        users.into_iter().collect()
    }

    /// Resolve the object an [`AuditRecord`] accessed (its `object_name`, falling
    /// back to `resource_path`) and return the classification + sensitivity the
    /// caller can stamp onto the record before policy evaluation.
    pub fn enrich(&self, rec: &AuditRecord) -> Enrichment {
        match record_object_name(rec) {
            Some(name) => enrichment_from(self.resolve_object(name)),
            None => Enrichment::default(),
        }
    }

    /// Build a reusable [`ObjectIndex`] over this catalog's object-bearing entries
    /// so a hot caller can resolve names in O(matches) instead of O(entries) per
    /// event. Snapshot by position — rebuild if `entries` changes.
    pub fn object_index(&self) -> ObjectIndex {
        let mut idx = ObjectIndex::default();
        for (i, entry) in self.entries.iter().enumerate() {
            let Some(f) = entry.resource.object_facts() else {
                continue;
            };
            let i = i as u32;
            let p = f.pattern.to_ascii_lowercase();
            if let Some(prefix) = p.strip_suffix(".*") {
                idx.wildcards.push((prefix.to_string(), i));
            } else if p.contains('.') {
                idx.exact.entry(p).or_default().push(i);
            } else {
                idx.unqualified.entry(p).or_default().push(i);
            }
        }
        idx
    }

    /// Stamp the resolved classification + sensitive flag onto `rec`, in place,
    /// so downstream policy evaluation sees them. This only ever *adds*
    /// information: it sets `data_classification` when the catalog resolves one,
    /// and raises (never clears) `sensitive_resource` — a Candidate can never
    /// downgrade an already-sensitive record.
    pub fn stamp(&self, rec: &mut AuditRecord) {
        let enr = self.enrich(rec);
        apply_enrichment(rec, enr);
    }

    /// A content digest of the catalog — the version anchor for the set. Prefix
    /// `cat1:` + an order-independent blake3 over every entry (sorted by id).
    pub fn digest(&self) -> String {
        let mut entries: Vec<&CatalogEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        let json = serde_json::to_vec(&entries).unwrap_or_default();
        format!("cat1:{}", &blake3::hash(&json).to_hex()[..32])
    }

    /// Parse a documented catalog file (TOML text) into a catalog of
    /// **Candidate** entries with [`CatalogSource::FileImport`]. Imported facts
    /// require human promotion before they resolve.
    ///
    /// The file shape is an array-of-tables per resource kind plus an optional
    /// top-level `created_by`:
    ///
    /// ```toml
    /// created_by = "alice"
    ///
    /// [[application]]
    /// name = "registry"
    /// owner = "team-registry"
    /// business_purpose = "Population register"
    ///
    /// [[table]]
    /// name = "raw.raw_persons"
    /// application = "registry"
    /// classification = "restricted"
    /// sensitive = true
    /// expected_users = ["anna", "bruno"]
    ///
    /// [[sensitive_resource]]
    /// object = "curated.persons"
    /// classification = "confidential"
    /// expected_users = ["anna"]
    /// ```
    pub fn from_toml(text: &str) -> Result<Catalog, String> {
        let file: CatalogFile = toml::from_str(text).map_err(|e| e.to_string())?;
        Ok(file.into_catalog())
    }
}

// =========================================================================
// TOML import shape
// =========================================================================

/// The on-disk catalog-file shape consumed by [`Catalog::from_toml`]. Each field
/// is an array of the corresponding resource; every one becomes a Candidate.
#[derive(Debug, Clone, Default, Deserialize)]
struct CatalogFile {
    #[serde(default)]
    created_by: Option<String>,
    #[serde(default)]
    application: Vec<Application>,
    #[serde(default)]
    application_instance: Vec<ApplicationInstance>,
    #[serde(default)]
    data_source: Vec<DataSource>,
    #[serde(default)]
    database: Vec<Database>,
    #[serde(default)]
    schema: Vec<Schema>,
    #[serde(default)]
    table: Vec<Table>,
    #[serde(default)]
    view: Vec<View>,
    #[serde(default)]
    api_endpoint: Vec<ApiEndpoint>,
    #[serde(default)]
    document_collection: Vec<DocumentCollection>,
    #[serde(default)]
    sensitive_resource: Vec<SensitiveResource>,
    #[serde(default)]
    user_role: Vec<UserRole>,
    #[serde(default)]
    peer_group: Vec<PeerGroup>,
    #[serde(default)]
    approved_client: Vec<ApprovedClient>,
    #[serde(default)]
    maintenance_window: Vec<MaintenanceWindow>,
    #[serde(default)]
    expected_automation_identity: Vec<ExpectedAutomationIdentity>,
}

impl CatalogFile {
    fn into_catalog(self) -> Catalog {
        let created_by = self.created_by.unwrap_or_default();
        let mut entries = Vec::new();
        let mut push = |kind: &str, key: &str, resource: Resource| {
            let mut e = CatalogEntry::candidate(
                format!("{kind}:{key}"),
                resource,
                CatalogSource::FileImport,
            );
            e.created_by = created_by.clone();
            entries.push(e);
        };

        for a in self.application {
            let key = a.name.clone();
            push("application", &key, Resource::Application(a));
        }
        for a in self.application_instance {
            let key = format!("{}/{}", a.application, a.instance);
            push(
                "application_instance",
                &key,
                Resource::ApplicationInstance(a),
            );
        }
        for r in self.data_source {
            let key = r.name.clone();
            push("data_source", &key, Resource::DataSource(r));
        }
        for r in self.database {
            let key = r.name.clone();
            push("database", &key, Resource::Database(r));
        }
        for r in self.schema {
            let key = r.name.clone();
            push("schema", &key, Resource::Schema(r));
        }
        for r in self.table {
            let key = r.name.clone();
            push("table", &key, Resource::Table(r));
        }
        for r in self.view {
            let key = r.name.clone();
            push("view", &key, Resource::View(r));
        }
        for r in self.api_endpoint {
            let key = r.path.clone();
            push("api_endpoint", &key, Resource::ApiEndpoint(r));
        }
        for r in self.document_collection {
            let key = r.name.clone();
            push("document_collection", &key, Resource::DocumentCollection(r));
        }
        for r in self.sensitive_resource {
            let key = r.object.clone();
            push("sensitive_resource", &key, Resource::SensitiveResource(r));
        }
        for r in self.user_role {
            let key = r.name.clone();
            push("user_role", &key, Resource::UserRole(r));
        }
        for r in self.peer_group {
            let key = r.name.clone();
            push("peer_group", &key, Resource::PeerGroup(r));
        }
        for r in self.approved_client {
            let key = r.identity.clone();
            push("approved_client", &key, Resource::ApprovedClient(r));
        }
        for r in self.maintenance_window {
            let key = r.id.clone();
            push("maintenance_window", &key, Resource::MaintenanceWindow(r));
        }
        for r in self.expected_automation_identity {
            let key = r.identity.clone();
            push(
                "expected_automation_identity",
                &key,
                Resource::ExpectedAutomationIdentity(r),
            );
        }

        Catalog::new(entries)
    }
}

#[cfg(test)]
mod tests;