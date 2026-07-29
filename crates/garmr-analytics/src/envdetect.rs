// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 — environment-aware detection: the `TrustedView` (the SINGLE gate
//! through which any detector reads the environment model) and the `env_edge`
//! detector (new-edge / new-identity vs the Trusted baseline).
//!
//! THE TRUSTED-ONLY DISCIPLINE: every environment read for detection goes through
//! [`TrustedView`], which filters to `FactState::Trusted`. So a Candidate,
//! Suspicious, KnownMalicious, or forged (empty-audit) fact can NEVER be read as
//! "normal" — the entire poison-safety of the plane reduces to this one filter
//! plus the Phase-5 promotion discipline (a fact reaches Trusted only via human
//! promotion unless `environment.learn` is on, default off).

use chrono::{DateTime, Utc};
use garmr_core::{
    frame, role_criticality, AccessProjection, DetectorFamily, EntityKind, EnvBasis, EnvFact,
    Event, FactState, FindingSignal, RelationKind, SecurityFinding,
};
use garmr_store::Store;

use crate::ensemble::{assess, EnsemblePolicy};

/// A read-only, Trusted-only view of the environment model. Every accessor
/// answers from Trusted facts ONLY.
pub struct TrustedView {
    facts: Vec<EnvFact>,
}

impl TrustedView {
    /// Load the Trusted facts from the store (the single gate). `ttl`/`now` are
    /// forwarded to materialization; Trusted facts are protected and never
    /// expire, so `None` is a fine `ttl`.
    pub fn load(
        store: &Store,
        ttl: Option<chrono::Duration>,
        now: DateTime<Utc>,
    ) -> garmr_core::Result<Self> {
        let facts = store
            .state
            .list_env_facts(ttl, now)?
            .into_iter()
            .filter(|f| f.state == FactState::Trusted)
            .collect();
        Ok(Self { facts })
    }

    /// Construct from an explicit fact set (tests / callers that already hold a
    /// materialized set). Filters to Trusted defensively.
    pub fn from_facts(facts: Vec<EnvFact>) -> Self {
        Self {
            facts: facts
                .into_iter()
                .filter(|f| f.state == FactState::Trusted)
                .collect(),
        }
    }

    fn host_facts<'a>(&'a self, host: &'a str) -> impl Iterator<Item = &'a EnvFact> {
        self.facts
            .iter()
            .filter(move |f| f.entity.kind == EntityKind::Host && f.entity.id == host)
    }

    /// How many Trusted facts we hold about a host (0 ⇒ no baseline ⇒ abstain).
    pub fn baseline_size(&self, host: &str) -> usize {
        self.host_facts(host).count()
    }

    /// Is `ip` a KNOWN (Trusted) communication peer of `host`?
    pub fn knows_edge(&self, host: &str, ip: &str) -> bool {
        self.host_facts(host).any(|f| {
            f.relation == Some(RelationKind::CommunicatesWith) && f.target_id.as_deref() == Some(ip)
        })
    }

    /// Is `ident` a Trusted identity anywhere in the model (a known account)?
    pub fn knows_identity(&self, ident: &str) -> bool {
        self.facts
            .iter()
            .any(|f| f.entity.kind == EntityKind::Identity && f.entity.id == ident)
    }

    /// How many DISTINCT Trusted identities the model knows — the baseline for the
    /// new-identity axis. `0` ⇒ no identity baseline ⇒ abstain, else the rarity
    /// detector would flag EVERY account as "new". Identities are high-impact and
    /// never auto-promote (analyst approval only), so this is `0` until a human
    /// blesses / imports an account set — which is exactly when judging novelty is
    /// meaningful.
    pub fn identity_baseline_size(&self) -> usize {
        self.facts
            .iter()
            .filter(|f| f.entity.kind == EntityKind::Identity)
            .map(|f| f.entity.id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// A host's role — from a TRUSTED role fact ONLY. NEVER the heuristic (which
    /// reads attacker-influenceable host/source/log_type); detector scoring must
    /// not route through attacker-controlled signal. `None` when no Trusted role.
    pub fn role_of(&self, host: &str) -> Option<String> {
        self.host_facts(host)
            .find(|f| f.attribute == "role" && !f.value.is_empty())
            .map(|f| f.value.clone())
    }

    /// A host's asset-criticality in `[0,1]` from its Trusted role only (0 when
    /// unknown → a neutral, monotonic-up multiplier).
    pub fn criticality_of(&self, host: &str) -> f32 {
        self.role_of(host)
            .map(|r| role_criticality(&r))
            .unwrap_or(0.0)
    }

    /// The Trusted fact ids about a host — provenance for a finding's env_basis.
    fn fact_ids_for(&self, host: &str) -> Vec<String> {
        self.host_facts(host).map(|f| f.fact_id.clone()).collect()
    }
}

/// Run the env-edge / env-new-identity detector over a window of events against a
/// Trusted view. Emits a `SecurityFinding` per event that talks to an IP absent
/// from the host's Trusted peer set, or acts as an identity the model does not
/// know. Each rarity axis abstains until it has its OWN established baseline so it
/// can't flag everything:
///   * new-edge needs the host's Trusted host-fact baseline (`>= min_baseline`);
///   * new-identity ALSO needs a Trusted identity baseline (`>= min_baseline`
///     distinct known accounts) — the host-fact count says nothing about whether
///     the model knows any accounts, and identities never auto-promote, so without
///     this gate every `db_user` would flag as "new" and flood the case queue.
///
/// With the env model off/unused both baselines are empty and the detector is
/// inert.
pub fn env_edge_findings(
    events: &[Event],
    view: &TrustedView,
    policy: &EnsemblePolicy,
    min_baseline: usize,
    now: DateTime<Utc>,
) -> Vec<SecurityFinding> {
    let mut out = Vec::new();
    // Compute the identity baseline once — it is model-wide, not per-host.
    let has_identity_baseline = view.identity_baseline_size() >= min_baseline;
    for ev in events {
        if ev.host.is_empty() || view.baseline_size(&ev.host) < min_baseline {
            continue; // no host, or no host baseline → abstain
        }
        // New edge: the host talks to an IP not in its Trusted peer set.
        if let Some(ip) = ev.src_ip().filter(|s| !s.is_empty()) {
            if !view.knows_edge(&ev.host, ip) {
                if let Some(f) = build_finding(
                    ev,
                    "env-new-edge",
                    "host communicates with a new peer (not in the Trusted baseline)",
                    ip,
                    view,
                    policy,
                    now,
                ) {
                    out.push(f);
                }
            }
        }
        // New identity: an account the model has never trusted acts on the host —
        // but only judged against an established identity baseline, else abstain.
        if has_identity_baseline {
            if let Some(ident) = ev
                .field("db_user")
                .or_else(|| ev.field("user"))
                .filter(|s| !s.is_empty())
            {
                if !view.knows_identity(ident) {
                    if let Some(f) = build_finding(
                        ev,
                        "env-new-identity",
                        "a new identity acts on a host with an established baseline",
                        ident,
                        view,
                        policy,
                        now,
                    ) {
                        out.push(f);
                    }
                }
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn build_finding(
    ev: &Event,
    detector: &str,
    title: &str,
    principal: &str,
    view: &TrustedView,
    policy: &EnsemblePolicy,
    now: DateTime<Utc>,
) -> Option<SecurityFinding> {
    let host = &ev.host;
    let finding_id = frame(&[
        b"finding",
        detector.as_bytes(),
        host.as_bytes(),
        principal.as_bytes(),
    ]);
    let shell = SecurityFinding {
        finding_id,
        detector: detector.to_string(),
        title: title.to_string(),
        base_level: "medium".to_string(),
        attack: Vec::new(),
        event: ev.clone(),
        observed_at: now,
        signals: vec![FindingSignal {
            family: DetectorFamily::EnvEdge,
            rule_id: detector.to_string(),
            level: "medium".to_string(),
            weight: 0.0,
        }],
        score: 0.0,
        band: garmr_core::SeverityBand::Informational,
        level: String::new(),
        env_basis: EnvBasis {
            trusted_facts_consulted: view.fact_ids_for(host),
            baseline_size: view.baseline_size(host),
            asset_role: view.role_of(host),
            criticality: view.criticality_of(host),
        },
        subject: AccessProjection::from_event(ev),
    };
    assess(shell, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::EntityRef;
    use std::collections::BTreeMap;

    fn fact(kind: EntityKind, id: &str, attr: &str, value: &str, state: FactState) -> EnvFact {
        EnvFact {
            fact_id: format!("{}-{id}-{attr}", kind.tag()),
            entity: EntityRef::new(kind, id),
            attribute: attr.into(),
            value: value.into(),
            state,
            ..Default::default()
        }
    }

    fn edge_fact(host: &str, ip: &str, state: FactState) -> EnvFact {
        let mut f = fact(EntityKind::Host, host, "", ip, state);
        f.relation = Some(RelationKind::CommunicatesWith);
        f.target_id = Some(ip.into());
        f
    }

    fn ev(host: &str, ip: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("src_ip".to_string(), ip.to_string());
        Event {
            ts: Utc::now(),
            host: host.into(),
            service: "s".into(),
            source: "src".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields,
        }
    }

    fn ev_user(host: &str, user: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("db_user".to_string(), user.to_string());
        Event {
            ts: Utc::now(),
            host: host.into(),
            service: "s".into(),
            source: "src".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields,
        }
    }

    fn base_host(host: &str) -> Vec<EnvFact> {
        vec![
            fact(
                EntityKind::Host,
                host,
                "role",
                "database",
                FactState::Trusted,
            ),
            edge_fact(host, "10.0.0.1", FactState::Trusted),
            edge_fact(host, "10.0.0.2", FactState::Trusted),
        ]
    }

    #[test]
    fn trusted_view_excludes_non_trusted_and_forged() {
        let facts = vec![
            edge_fact("web01", "10.0.0.1", FactState::Trusted),
            edge_fact("web01", "10.0.0.2", FactState::Candidate), // must NOT count
            edge_fact("web01", "10.0.0.3", FactState::Suspicious),
            edge_fact("web01", "10.0.0.4", FactState::KnownMalicious),
        ];
        let v = TrustedView::from_facts(facts);
        assert!(v.knows_edge("web01", "10.0.0.1"));
        assert!(
            !v.knows_edge("web01", "10.0.0.2"),
            "a Candidate edge is not known"
        );
        assert!(!v.knows_edge("web01", "10.0.0.3"));
        assert_eq!(v.baseline_size("web01"), 1);
    }

    #[test]
    fn empty_view_is_inert() {
        let v = TrustedView::from_facts(vec![]);
        let findings = env_edge_findings(
            &[ev("web01", "203.0.113.9")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now(),
        );
        assert!(findings.is_empty(), "no baseline → no findings");
    }

    #[test]
    fn new_edge_fires_only_with_a_baseline() {
        // A host with 3 Trusted facts (baseline met) talking to a NEW ip.
        let facts = vec![
            fact(
                EntityKind::Host,
                "web01",
                "role",
                "server",
                FactState::Trusted,
            ),
            edge_fact("web01", "10.0.0.1", FactState::Trusted),
            edge_fact("web01", "10.0.0.2", FactState::Trusted),
        ];
        let v = TrustedView::from_facts(facts);
        // Known peer → no finding.
        assert!(env_edge_findings(
            &[ev("web01", "10.0.0.1")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now()
        )
        .is_empty());
        // New peer → one finding.
        let f = env_edge_findings(
            &[ev("web01", "203.0.113.9")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now(),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector, "env-new-edge");
    }

    #[test]
    fn a_poisoned_candidate_edge_neither_fires_nor_suppresses() {
        // The attacker injected a Candidate "known edge" to HIDE its new peer — it
        // must NOT suppress (Candidate is filtered out of the Trusted view).
        let facts = vec![
            fact(
                EntityKind::Host,
                "web01",
                "role",
                "server",
                FactState::Trusted,
            ),
            edge_fact("web01", "10.0.0.1", FactState::Trusted),
            edge_fact("web01", "10.0.0.2", FactState::Trusted),
            edge_fact("web01", "203.0.113.9", FactState::Candidate), // forged allowlist entry
        ];
        let v = TrustedView::from_facts(facts);
        let f = env_edge_findings(
            &[ev("web01", "203.0.113.9")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now(),
        );
        assert_eq!(
            f.len(),
            1,
            "a Candidate 'known edge' cannot suppress a real new edge"
        );
    }

    #[test]
    fn new_identity_abstains_without_an_identity_baseline() {
        // The host baseline is met (role + 2 edges), but the model knows ZERO
        // Trusted identities — the normal posture, since identities never
        // auto-promote (high-impact, analyst approval only). The new-identity axis
        // MUST abstain, or every db_user floods the case queue (the Phase-7 review
        // finding). This is exactly the registerkontroll flagship shape: a
        // caseworker db_user acting on the Postgres host.
        let v = TrustedView::from_facts(base_host("pg01"));
        assert_eq!(v.identity_baseline_size(), 0);
        let f = env_edge_findings(
            &[ev_user("pg01", "caseworker_42")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now(),
        );
        assert!(
            f.is_empty(),
            "no identity baseline → the new-identity axis must not flag every account"
        );
    }

    #[test]
    fn new_identity_fires_only_against_an_identity_baseline() {
        // The model knows 3 distinct Trusted identities (an established account
        // baseline) and the host baseline is met. Only then is an unknown account
        // genuinely novel.
        let mut facts = base_host("pg01");
        facts.extend([
            fact(
                EntityKind::Identity,
                "svc_backup",
                "kind",
                "service",
                FactState::Trusted,
            ),
            fact(
                EntityKind::Identity,
                "caseworker_1",
                "kind",
                "person",
                FactState::Trusted,
            ),
            fact(
                EntityKind::Identity,
                "caseworker_2",
                "kind",
                "person",
                FactState::Trusted,
            ),
        ]);
        let v = TrustedView::from_facts(facts);
        assert_eq!(v.identity_baseline_size(), 3);
        // A KNOWN identity → no finding.
        assert!(env_edge_findings(
            &[ev_user("pg01", "svc_backup")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now()
        )
        .is_empty());
        // An UNKNOWN identity → exactly one env-new-identity finding.
        let f = env_edge_findings(
            &[ev_user("pg01", "intruder")],
            &v,
            &EnsemblePolicy::default(),
            3,
            Utc::now(),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detector, "env-new-identity");
    }

    #[test]
    fn a_vault_criticality_scores_higher_than_a_plain_server() {
        let base = |role: &str| {
            let facts = vec![
                fact(EntityKind::Host, "h", "role", role, FactState::Trusted),
                edge_fact("h", "10.0.0.1", FactState::Trusted),
                edge_fact("h", "10.0.0.2", FactState::Trusted),
            ];
            let v = TrustedView::from_facts(facts);
            env_edge_findings(
                &[ev("h", "203.0.113.9")],
                &v,
                &EnsemblePolicy::default(),
                3,
                Utc::now(),
            )[0]
            .score
        };
        assert!(
            base("vault") > base("server"),
            "a vault's new edge scores higher"
        );
    }
}