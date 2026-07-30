// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 — a lightweight, DETECTION-ONLY drift signal. It surfaces when the
//! learned "normal" is contradicted by fresh evidence; it NEVER auto-retunes a
//! threshold or auto-promotes/demotes a fact (that is the Phase-8 learning plane
//! — invariant #3). Any correction remains a human Proposal.
//!
//! Two cheap sources, both READ over the Phase-5 machinery:
//!   * `verify_environment` already computes `trusted-value-drift` (a Trusted fact
//!     whose newest live observation disagrees with its blessed value), plus
//!     `unaudited-transition` / `dangling-transition` — a tamper/integrity signal.
//!   * the env_edge detector already surfaces novel relations vs the Trusted
//!     baseline (tagged [`DriftKind::NewEdge`] by the caller).

use garmr_core::{verify_environment, FactObservation, FactTransition};
use serde::Serialize;

/// The kind of drift observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// A Trusted fact's blessed value is contradicted by fresh evidence.
    TrustedValueDrift,
    /// A protected transition with no audit id (tamper signal).
    UnauditedTransition,
    /// A transition governing a fact with no observation.
    DanglingTransition,
    /// A relation not in the Trusted baseline (from env_edge).
    NewEdge,
    Other,
}

/// One drift observation.
#[derive(Debug, Clone, Serialize)]
pub struct DriftItem {
    pub kind: DriftKind,
    pub coord: String,
    pub detail: String,
}

/// A read-only drift report (surfaced to a human; drives no automatic change).
#[derive(Debug, Clone, Default, Serialize)]
pub struct DriftReport {
    pub items: Vec<DriftItem>,
}

impl DriftReport {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Assess environment drift by reusing the Phase-5 integrity fold. Pure; no
/// side effects, no retuning.
pub fn assess_drift(obs: &[FactObservation], transitions: &[FactTransition]) -> DriftReport {
    let items = verify_environment(obs, transitions)
        .into_iter()
        .map(|f| DriftItem {
            kind: match f.category.as_str() {
                "trusted-value-drift" => DriftKind::TrustedValueDrift,
                "unaudited-transition" => DriftKind::UnauditedTransition,
                "dangling-transition" => DriftKind::DanglingTransition,
                _ => DriftKind::Other,
            },
            coord: f.coord,
            detail: f.detail,
        })
        .collect();
    DriftReport { items }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::{EntityKind, EntityRef, FactState, FactTransition};

    fn obs(fid: &str, oid: &str, value: &str, at_secs: i64) -> FactObservation {
        FactObservation {
            observation_id: oid.into(),
            fact_id: fid.into(),
            entity: EntityRef::new(EntityKind::Host, "web01"),
            attribute: "role".into(),
            value: value.into(),
            recorded_at: chrono::DateTime::from_timestamp(at_secs, 0).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn surfaces_trusted_value_drift() {
        let fid = "f1";
        // Trusted, blessed to o1="server"; a newer o2="router" contradicts it.
        let o = vec![obs(fid, "o1", "server", 100), obs(fid, "o2", "router", 200)];
        let tr = vec![FactTransition {
            transition_id: "p".into(),
            fact_id: fid.into(),
            to_state: FactState::Trusted,
            target_observation_id: "o1".into(),
            audit_id: "aud".into(),
            recorded_at: chrono::DateTime::from_timestamp(100, 0).unwrap(),
            ..Default::default()
        }];
        let report = assess_drift(&o, &tr);
        assert!(report
            .items
            .iter()
            .any(|i| i.kind == DriftKind::TrustedValueDrift));
    }

    #[test]
    fn a_sound_model_has_no_drift() {
        assert!(assess_drift(&[], &[]).is_empty());
    }
}
