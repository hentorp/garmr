// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 — the domain-neutral core vocabulary.
//!
//! The generic types every access audit speaks — Actor, Identity, DataSubject,
//! Resource, Asset, Service, Session, Justification, AccessOperation — plus the
//! [`AccessProjection`] view over one event. Register-specific concepts (a
//! caseworker `db_user` reading a `target_person`) are just one *profile* of this
//! vocabulary, selected by config, never hardcoded in the core.
//!
//! NORMALIZATION HAPPENS ONCE, AT INGEST. `garmr-ingest`'s field folder maps ~30
//! source aliases onto the canonical keys (`db_user`, `target_person`,
//! `object_table`, `action`/`statement`, `ticket_ref`, `client_addr`,
//! `watched`/`is_self`). Events reaching the store/core already carry those keys,
//! so [`AccessProjection::from_event`] reads them DIRECTLY and MUST NOT
//! re-implement any alias folding — garmr-core is the no-I/O leaf and cannot
//! depend on garmr-ingest; a second normalizer here would be the very duplication
//! this workstream removes.

use serde::{Deserialize, Serialize};

use crate::Event;

/// Which domain profile a deployment runs. The generic core is ALWAYS compiled;
/// a profile only selects extra interpretation, never a different binary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainProfileKind {
    /// Actor/DataSubject/Resource with no register-specific semantics.
    #[default]
    Generic,
    /// The register-lookup flagship: caseworker (`db_user`) accesses a person
    /// record (`target_person`), justified by a case reference (`ticket_ref`).
    Register,
    #[serde(other)]
    Unknown,
}

/// Who acted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
}

/// Whose record / which principal was accessed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSubject {
    pub id: String,
}

/// The kind of thing accessed (a table, collection, resource type).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub class: String,
}

/// The stated justification (a ticket/case reference or free-text reason).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Justification {
    pub reference: String,
}

/// The operation verb (read/view/export/…), distinct from a raw SQL statement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessOperation {
    pub verb: String,
}

/// The client origin of the access.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub client: String,
}

/// A domain-neutral access event, projected from the canonical event fields. The
/// generic core and any domain profile read the SAME normalized data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessProjection {
    pub actor: Actor,
    pub subject: Option<DataSubject>,
    pub resource: Option<Resource>,
    pub operation: Option<AccessOperation>,
    pub justification: Option<Justification>,
    pub session: Option<Session>,
    /// The subject is on the app's watchlist (`watched: true`).
    pub watched: bool,
    /// The actor accessed their own record (`is_self: true`).
    pub is_self: bool,
}

impl AccessProjection {
    /// Project an access event from its ALREADY-canonical fields. Returns `None`
    /// when there is no actor (`db_user`) — i.e. the event is not an access audit.
    /// Reads canonical keys DIRECTLY; performs no alias folding (that is ingest's
    /// one and only job).
    pub fn from_event(ev: &Event) -> Option<AccessProjection> {
        let actor = ev.field("db_user").filter(|s| !s.is_empty())?;
        let flag = |k: &str| matches!(ev.field(k), Some("true" | "1" | "yes" | "t"));
        Some(AccessProjection {
            actor: Actor {
                id: actor.to_string(),
            },
            subject: ev
                .field("target_person")
                .filter(|s| !s.is_empty())
                .map(|s| DataSubject { id: s.to_string() }),
            resource: ev
                .field("object_table")
                .filter(|s| !s.is_empty())
                .map(|s| Resource {
                    class: s.to_string(),
                }),
            operation: ev
                .field("action")
                .or_else(|| ev.field("statement"))
                .filter(|s| !s.is_empty())
                .map(|s| AccessOperation {
                    verb: s.to_string(),
                }),
            justification: ev.field("ticket_ref").filter(|s| !s.is_empty()).map(|s| {
                Justification {
                    reference: s.to_string(),
                }
            }),
            session: ev
                .field("client_addr")
                .filter(|s| !s.is_empty())
                .map(|s| Session {
                    client: s.to_string(),
                }),
            watched: flag("watched"),
            is_self: flag("is_self"),
        })
    }
}

// ---- the unified asset-role classifier (the Trusted-view seam) ---------------

/// Where a resolved role came from (higher = more authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleSource {
    /// A Trusted role fact in the environment model (human-blessed / imported).
    Trusted,
    /// A low-confidence guess from event signals (no inventory/Trusted evidence).
    Heuristic,
}

/// A resolved asset role + how confident / where it came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleResolution {
    pub role: String,
    pub confidence: f32,
    pub source: RoleSource,
}

/// True if `name` starts with `prefix` immediately followed by a digit (so `sw1`
/// hits but `software` does not).
fn prefix_num(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|r| r.chars().next())
        .is_some_and(|c| c.is_ascii_digit())
}

/// The SINGLE host-role heuristic — the one canonical copy that replaces the
/// three divergent classifiers (garmr-graph `host_device_type`, garmr-map
/// `classify`, the env learner's `guess_host_role`). Derives a role from event
/// signals: firewall→router, cluster→cluster, then hostname conventions; else
/// `server`. NOTE: source/host/log_type are attacker-influenceable, so this is a
/// LOW-CONFIDENCE fallback only — a Trusted role fact must win (see
/// [`resolve_asset_role`]), and detector SCORING must never route through it.
pub fn heuristic_role(host: &str, source: &str, log_type: &str) -> &'static str {
    let h = host.to_ascii_lowercase();
    let s = source.to_ascii_lowercase();
    let lt = log_type.to_ascii_lowercase();
    if lt == "firewall" || s.contains("firewall") {
        return "router";
    }
    if s.contains("talos") || lt == "cluster" {
        return "cluster";
    }
    if h.contains("vault") || h.contains("bao") {
        return "vault";
    }
    if h.contains("switch") || prefix_num(&h, "sw") {
        return "switch";
    }
    if h.contains("router")
        || h.contains("gateway")
        || prefix_num(&h, "gw")
        || prefix_num(&h, "rtr")
    {
        return "router";
    }
    "server"
}

/// Resolve an asset's role: a Trusted role fact wins at high confidence; the
/// heuristic is the low-confidence fallback ONLY when there is no Trusted
/// evidence. This is used by the classifier-unification / display consumers —
/// never by detector scoring (which reads Trusted facts ONLY).
pub fn resolve_asset_role(
    trusted_role: Option<&str>,
    host: &str,
    source: &str,
    log_type: &str,
) -> RoleResolution {
    match trusted_role.filter(|r| !r.is_empty()) {
        Some(r) => RoleResolution {
            role: r.to_string(),
            confidence: 0.95,
            source: RoleSource::Trusted,
        },
        None => RoleResolution {
            role: heuristic_role(host, source, log_type).to_string(),
            confidence: 0.3,
            source: RoleSource::Heuristic,
        },
    }
}

/// The security-criticality weight of an asset role, in `[0, 1]` — a trust-anchor
/// or cluster node is high, network gear medium, a plain server none. Used ONLY
/// with a Trusted role (never the heuristic), and only ever RAISES attention.
pub fn role_criticality(role: &str) -> f32 {
    match role.to_ascii_lowercase().as_str() {
        "vault" | "cluster" => 1.0,
        "router" | "switch" | "firewall" => 0.5,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ev(fields: &[(&str, &str)]) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "db01".into(),
            service: "postgres".into(),
            source: "pgaudit".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: String::new(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn access_projection_reads_canonical_register_keys() {
        // The register flagship: a caseworker reads a person record with a ticket.
        let e = ev(&[
            ("db_user", "caseworker7"),
            ("target_person", "pnr-abc"),
            ("object_table", "persons"),
            ("action", "select"),
            ("ticket_ref", "ARENDE-42"),
            ("client_addr", "10.0.0.5"),
            ("watched", "true"),
        ]);
        let p = AccessProjection::from_event(&e).unwrap();
        assert_eq!(p.actor.id, "caseworker7");
        assert_eq!(p.subject.unwrap().id, "pnr-abc");
        assert_eq!(p.resource.unwrap().class, "persons");
        assert_eq!(p.operation.unwrap().verb, "select");
        assert_eq!(p.justification.unwrap().reference, "ARENDE-42");
        assert!(p.watched);
        assert!(!p.is_self);
    }

    #[test]
    fn no_actor_means_not_an_access_event() {
        assert!(AccessProjection::from_event(&ev(&[("message", "x")])).is_none());
    }

    #[test]
    fn resolve_prefers_trusted_over_heuristic() {
        // A Trusted role wins even when the heuristic would say otherwise.
        let r = resolve_asset_role(Some("database"), "vault-1", "openbao", "app");
        assert_eq!(r.role, "database");
        assert_eq!(r.source, RoleSource::Trusted);
        // Absent Trusted → the heuristic fallback (low confidence).
        let h = resolve_asset_role(None, "vault-1", "openbao", "app");
        assert_eq!(h.role, "vault");
        assert_eq!(h.source, RoleSource::Heuristic);
        assert!(h.confidence < 0.5);
    }

    #[test]
    fn criticality_only_raises() {
        assert_eq!(role_criticality("vault"), 1.0);
        assert_eq!(role_criticality("router"), 0.5);
        assert_eq!(role_criticality("server"), 0.0);
        assert_eq!(role_criticality("unknown-role"), 0.0);
    }
}
