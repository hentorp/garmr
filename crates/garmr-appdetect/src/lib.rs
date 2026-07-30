// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 8 — application-audit / insider-risk detectors.
//!
//! Pure functions that turn one canonical audit access ([`Event`] +
//! [`AuditRecord`]) plus its [`PolicyDecision`] into zero or more
//! [`SecurityFinding`]s. Each finding lowers into the existing
//! `SecurityFinding → Detection → case` pipeline and inherits the ensemble
//! fusion, floor-safety, provenance, dedup, and learning-plane replay for free.
//!
//! ## What lives here vs. Phase 7
//!
//! This module implements the **stateless** detectors — the ones decidable from
//! a single access and its policy decision:
//!
//! 1. explicit forbidden access (policy `Deny`)
//! 2. missing justification (policy `RequireJustification`/`RequireApproval` unmet)
//! 3. self-access
//! 4. watched-subject access
//! 5. privilege change (`GRANT`/`REVOKE`/`SET ROLE`/security DDL)
//! 6. export (`COPY … TO`, unload, large paginated extraction)
//! 7. bulk access (unbounded read heuristic; refined by row counts)
//! 8. service-account misuse (interactive client on a service account)
//! 9. failed access (the DB itself denied/failed the operation)
//!
//! The **history/baseline-dependent** detectors — new query fingerprint, new
//! client, new source host, new object, and statistical off-hours / volume
//! deviation — live in [`detect_behavioral`], which consults the Phase-7
//! [`BaselineStore`]. They are **Trusted-only by construction**: the store never
//! reports a novelty/off-hours/deviation against a Candidate (still-learning)
//! baseline, so a flood of a new pattern cannot make itself "normal" and a
//! learning entity never produces a false finding. A single novelty is a *weak
//! indicator*, not an incident — the ensemble + RBA accumulate them.
//!
//! The remaining history detectors that need cross-event or ledger state —
//! sequential / low-and-slow enumeration, cross-domain join, source silence,
//! audit-config change, audit gap, and tamper — belong to the correlation and
//! collector/ledger planes (Phases 9/14/16), not to this per-access module, and
//! are intentionally NOT stubbed here (a stub would report "clear" and hide
//! misuse).
//!
//! A policy violation is NOT an anomaly: forbidden-access and missing-
//! justification findings come from the deterministic [`garmr_policy`] decision,
//! not from behavioral scoring; a novelty/deviation is an anomaly and never
//! promoted to a policy violation. This preserves the platform's core distinction.

use chrono::Timelike;
use garmr_baseline::{
    actor_entity, categorical_value, BaselineStore, Dimension, Entity, EntityKind,
};
use garmr_core::{
    AccessProjection, AuditRecord, DetectorFamily, EnvBasis, Event, FindingSignal, SecurityFinding,
    SeverityBand,
};
use garmr_policy::{Effect, PolicyDecision};

pub mod stateful;

/// The **deterministic policy** detectors: a policy verdict, not an anomaly.
/// These stay their own case and are NEVER blended into a behavioral score — "a
/// forbidden action stays forbidden no matter how frequent." Kept as the single
/// source of truth for the ensemble's policy≠anomaly partition.
pub const POLICY_DETECTORS: &[&str] = &[
    "app-forbidden-access",
    "app-missing-justification",
    "app-missing-approval",
];

/// **Standalone-notable** detectors: high-value, independently case-worthy facts
/// (a watched subject, a privilege change, a service account used interactively).
/// They keep their own explainable case rather than being fused into the generic
/// behavioral-risk bucket.
pub const STANDALONE_DETECTORS: &[&str] = &[
    "app-watched-subject-access",
    "app-privilege-change",
    "app-service-account-misuse",
];

/// True for a deterministic policy finding (see [`POLICY_DETECTORS`]).
pub fn is_deterministic_policy(detector: &str) -> bool {
    POLICY_DETECTORS.contains(&detector)
}

/// True for a standalone-notable finding: the explicit [`STANDALONE_DETECTORS`]
/// plus every cross-event episode from the [`stateful`] plane
/// ([`stateful::STATEFUL_DETECTORS`]). A stateful enumeration/probing/cross-domain
/// episode is independently case-worthy — it keeps its own explainable case rather
/// than being blended into the generic behavioral-risk bucket.
pub fn is_standalone(detector: &str) -> bool {
    STANDALONE_DETECTORS.contains(&detector) || stateful::STATEFUL_DETECTORS.contains(&detector)
}

/// Asset-criticality `c ∈ [0,1]` for an access, from the (Trusted, catalog-
/// stamped) data classification — the ensemble's `crit_mult` driver. Mirrors
/// [`garmr_core::role_criticality`] but over data-sensitivity labels, and is
/// floored to 0.6 for a `sensitive_resource` or `watched_subject` access so a
/// sensitive touch always carries weight even when the label is absent/custom.
/// Monotonic + poison-bounded: it only ever RAISES attention (assess clamps the
/// multiplier `.max(1.0)`), and the classification comes from Trusted catalog
/// entries (a Candidate-sensitive entry is not stamped).
pub fn classification_criticality(rec: &AuditRecord) -> f32 {
    let base: f32 = match rec
        .classification
        .data_classification
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("secret" | "top_secret" | "top-secret") => 1.0,
        Some("restricted") => 0.8,
        Some("confidential") => 0.6,
        Some("internal") => 0.2,
        Some("public") => 0.0,
        Some("") | None => 0.0,
        // A custom/unknown label is treated as moderately sensitive, not ignored.
        Some(_) => 0.4,
    };
    let floor: f32 = if rec.classification.sensitive_resource || rec.classification.watched_subject
    {
        0.6
    } else {
        0.0
    };
    base.max(floor)
}

/// Clients that indicate a human at an interactive SQL prompt — unusual for a
/// service account, which should only ever run its application's queries.
const INTERACTIVE_CLIENTS: &[&str] = &[
    "psql",
    "pgcli",
    "dbeaver",
    "datagrip",
    "pgadmin",
    "beekeeper",
    "tableplus",
    "adminer",
];

/// Stamp the caller's stable (content-addressed) evidence id onto the event so
/// `finding_id` and the embedded event carry it instead of the colliding
/// timestamp fallback. Borrows when the id already matches (no clone on the hot
/// path); clones only when it must rewrite the field.
fn stamp_evidence<'a>(ev: &'a Event, evidence_id: Option<&str>) -> std::borrow::Cow<'a, Event> {
    match evidence_id {
        Some(id) if ev.field("event_id") != Some(id) => {
            let mut e = ev.clone();
            e.fields.insert("event_id".to_string(), id.to_string());
            std::borrow::Cow::Owned(e)
        }
        _ => std::borrow::Cow::Borrowed(ev),
    }
}

fn finding(
    ev: &Event,
    detector: &str,
    title: &str,
    base_level: &str,
    attack: &[&str],
) -> SecurityFinding {
    let weight = garmr_core::level_weight(base_level);
    let evidence = ev
        .field("event_id")
        .map(str::to_string)
        .unwrap_or_else(|| ev.ts.timestamp_micros().to_string());
    SecurityFinding {
        finding_id: format!("{detector}:{evidence}"),
        detector: detector.to_string(),
        title: title.to_string(),
        base_level: base_level.to_string(),
        attack: attack.iter().map(|s| s.to_string()).collect(),
        event: ev.clone(),
        observed_at: ev.ts,
        signals: vec![FindingSignal {
            family: DetectorFamily::AppAudit,
            rule_id: detector.to_string(),
            level: base_level.to_string(),
            weight,
        }],
        score: weight,
        band: SeverityBand::from_level(base_level),
        level: base_level.to_string(),
        env_basis: EnvBasis::default(),
        subject: AccessProjection::from_event(ev),
    }
}

/// Run the stateless application-audit detectors over one access. `decision` is
/// the [`garmr_policy`] verdict for the same access. Returns every finding that
/// fired (possibly several — a single access can be both a policy violation and
/// a bulk export).
pub fn detect_access(
    ev: &Event,
    record: &AuditRecord,
    decision: &PolicyDecision,
    evidence_id: Option<&str>,
) -> Vec<SecurityFinding> {
    if !AuditRecord::is_audit_event(ev) {
        return Vec::new();
    }
    // Use the record the caller already built for policy evaluation — no
    // re-projection on the ingest hot path.
    let rec = record;
    // Stamp the caller's stable (content-addressed) evidence id so finding_id and
    // the embedded event carry it, instead of the colliding timestamp fallback.
    let stamped = stamp_evidence(ev, evidence_id);
    let ev: &Event = &stamped;
    let mut out = Vec::new();

    // 1. Explicit forbidden access — the deterministic policy Deny. Critical, and
    //    (by construction of the policy engine) never suppressible by frequency.
    if decision.decision == Effect::Deny {
        out.push(finding(
            ev,
            "app-forbidden-access",
            "Access forbidden by explicit policy",
            "critical",
            &[],
        ));
    }

    // 2. Missing justification / approval for a policy-required access.
    if decision
        .missing_requirements
        .iter()
        .any(|r| r == "justification")
    {
        out.push(finding(
            ev,
            "app-missing-justification",
            "Sensitive access without a required justification",
            "high",
            &[],
        ));
    }
    if decision
        .missing_requirements
        .iter()
        .any(|r| r == "approval")
    {
        out.push(finding(
            ev,
            "app-missing-approval",
            "Access requires an approval reference that is absent",
            "high",
            &[],
        ));
    }

    // 3. Self-access — the actor accessed their own record.
    if rec.classification.self_access {
        out.push(finding(
            ev,
            "app-self-access",
            "Actor accessed their own record",
            "medium",
            &[],
        ));
    }

    // 4. Watched-subject access.
    if rec.classification.watched_subject {
        out.push(finding(
            ev,
            "app-watched-subject-access",
            "Access to a watched subject",
            "high",
            &[],
        ));
    }

    // 5. Privilege change.
    if rec.action.privilege_operation {
        out.push(finding(
            ev,
            "app-privilege-change",
            "Privilege or role change",
            "high",
            &["T1098"],
        ));
    }

    // 6. Export.
    if rec.action.export_operation {
        out.push(finding(
            ev,
            "app-export",
            "Data export / bulk extraction",
            "medium",
            &["T1005", "T1567"],
        ));
    }

    // 7. Bulk access (heuristic; the ensemble + row counts refine severity).
    if rec.action.bulk_operation && !rec.action.export_operation {
        out.push(finding(
            ev,
            "app-bulk-access",
            "Unbounded / bulk read",
            "medium",
            &["T1213"],
        ));
    }

    // 8. Service-account misuse — interactive client on a service account.
    if rec.actor.service_account {
        let interactive = rec.context.client_application.as_deref().is_some_and(|c| {
            INTERACTIVE_CLIENTS
                .iter()
                .any(|i| c.eq_ignore_ascii_case(i))
        });
        if interactive {
            out.push(finding(
                ev,
                "app-service-account-misuse",
                "Interactive use of a service account",
                "high",
                &["T1078"],
            ));
        }
    }

    // 9. Failed access — the database itself denied or errored the operation. A
    //    single one is a weak signal (low); the RBA accumulator turns repeated
    //    ones into a probing finding.
    if rec.action.outcome.is_negative() {
        out.push(finding(
            ev,
            "app-failed-access",
            "Denied or failed access",
            "low",
            &[],
        ));
    }

    out
}

/// The novelty dimensions that raise a finding, with their detector id / title /
/// base level / ATT&CK mapping. A single novelty is a *weak-to-medium* indicator
/// — the ensemble + RBA turn a cluster of them into an incident. Only the
/// UEBA-meaningful dimensions are surfaced; the rest (database/schema/operation/
/// subject-type) are still learned and available to search + the ensemble, but
/// do not each spawn their own finding (that would be noise).
const NOVELTY_DETECTORS: &[(Dimension, &str, &str, &str, &[&str])] = &[
    (
        Dimension::QueryFingerprint,
        "app-new-query-pattern",
        "New query pattern for this actor",
        "low",
        &[],
    ),
    (
        Dimension::Client,
        "app-new-client",
        "New client application for this actor",
        "medium",
        &["T1078"],
    ),
    (
        Dimension::SourceHost,
        "app-new-source-host",
        "New source host for this actor",
        "medium",
        &["T1078"],
    ),
    (
        Dimension::Object,
        "app-new-object-access",
        "Actor accessed an object never seen in their baseline",
        "medium",
        &["T1213"],
    ),
];

/// Run the **history/baseline-dependent** detectors over one access, consulting
/// the Phase-7 [`BaselineStore`]. Trusted-only by construction: a Candidate /
/// still-learning baseline yields no findings, so this cannot fire on an entity
/// that has not yet earned a trusted profile, and frequency alone never makes a
/// pattern "normal".
///
/// The caller runs this alongside [`detect_access`] (stateless) and concatenates
/// the results; both share the same `evidence_id` stamping so findings for one
/// access dedup and fuse in the ensemble. This function does NOT learn — the
/// caller observes non-denied accesses into the store separately, so a
/// policy-denied access is never folded into a baseline.
pub fn detect_behavioral(
    ev: &Event,
    record: &AuditRecord,
    baselines: &BaselineStore,
    evidence_id: Option<&str>,
) -> Vec<SecurityFinding> {
    if !AuditRecord::is_audit_event(ev) {
        return Vec::new();
    }
    let Some(actor) = actor_entity(record) else {
        return Vec::new();
    };
    let stamped = stamp_evidence(ev, evidence_id);
    let ev: &Event = &stamped;
    let mut out = Vec::new();

    // Categorical novelty — a value the trusted baseline has never seen.
    for &(dim, detector, title, level, attack) in NOVELTY_DETECTORS {
        if let Some(value) = categorical_value(record, dim) {
            if baselines.novelty(&actor, dim, &value).novel {
                out.push(finding(ev, detector, title, level, attack));
            }
        }
    }

    // Statistical off-hours — active at an hour that is rare for this actor.
    if baselines.off_hours(&actor, ev.ts.hour() as u8).off_hours {
        out.push(finding(
            ev,
            "app-off-hours",
            "Access at an hour that is unusual for this actor",
            "medium",
            &[],
        ));
    }

    // Volume deviation — a read far above the actor's normal row count.
    if let Some(rows) = record.action.rows_read {
        if baselines
            .deviation(&actor, Dimension::RowsRead, rows as f64)
            .deviating
        {
            out.push(finding(
                ev,
                "app-volume-deviation",
                "Read volume far above this actor's baseline",
                "high",
                &["T1213"],
            ));
        }
    }

    // Peer-group deviation — the CURRENT access uses a value that is established
    // for this actor but that NO trusted peer in their role uses. The peer group
    // is the actor's role (its aggregate baseline, learned alongside the actor's
    // via `derived_entities`). Trusted-only by construction: `peer_novelty`
    // abstains unless BOTH the actor and the role baseline are Trusted, so a
    // still-learning peer group never fires and a role becomes a peer *norm* only
    // once an analyst promotes it — clustering never silently defines the norm.
    // A weak indicator the ensemble corroborates, never a policy verdict.
    if let Some(role) = record
        .actor
        .actor_role
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let peer = Entity::new(EntityKind::Role, role);
        for &(dim, label) in PEER_DIMENSIONS {
            let Some(value) = categorical_value(record, dim) else {
                continue;
            };
            if baselines
                .peer_novelty(&actor, &peer, dim)
                .iter()
                .any(|v| v == &value)
            {
                out.push(finding(
                    ev,
                    "app-peer-deviation",
                    &format!(
                        "Actor uses a {label} ('{value}') unseen among peers in role '{role}'"
                    ),
                    "medium",
                    &["T1078"],
                ));
                break;
            }
        }
    }

    out
}

/// The dimensions on which a per-access peer-group deviation is surfaced: the
/// actor uses THIS value, but no trusted peer in their role does. Client and
/// object are the UEBA-meaningful ones (a tool or a resource the peer group never
/// touches). The full per-dimension comparison is available through the read
/// surface (`GET /api/appaudit/peers`).
const PEER_DIMENSIONS: &[(Dimension, &str)] = &[
    (Dimension::Client, "client application"),
    (Dimension::Object, "resource"),
];

#[cfg(test)]
mod tests;
