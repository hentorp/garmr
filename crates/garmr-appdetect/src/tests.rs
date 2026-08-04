// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic tests for the per-access detector planes. The stateless plane
//! ([`detect_access`]): every detector fires on its trigger and stays quiet on a
//! clean access, one access can fire several detectors, non-audit events are
//! ignored, and the policy/standalone buckets stay disjoint and cover
//! [`POLICY_DETECTORS`]. The behavioral plane ([`detect_behavioral`]): findings
//! are Trusted-only by construction — a Candidate (still-learning) baseline, an
//! actorless access, or an empty store never fires, while genuine novelty,
//! off-hours, volume and peer deviations do. Synthetic events only; no timing,
//! no randomness.

use super::*;
use garmr_core::app_audit::keys;
use garmr_policy::Effect;

fn ev(fields: &[(&str, &str)]) -> Event {
    Event {
        ts: chrono::Utc::now(),
        host: "db01".into(),
        service: "postgres".into(),
        source: "pgaudit".into(),
        environment: "prod".into(),
        severity: "info".into(),
        log_type: "audit".into(),
        message: "SELECT 1".into(),
        fields: fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

/// A clean access (actor + object, success) with no policy hit.
fn clean() -> Event {
    ev(&[
        (keys::ACTOR, "anna"),
        (keys::OBJECT_TYPE, "persons"),
        (keys::OUTCOME, "success"),
    ])
}

fn allow() -> PolicyDecision {
    PolicyDecision {
        decision: Effect::Allow,
        matched_policies: vec![],
        strongest_rule: None,
        subject: String::new(),
        resource: String::new(),
        action: String::new(),
        missing_requirements: vec![],
        reason: String::new(),
        evidence_references: vec![],
        policy_version: 0,
    }
}

fn decision(effect: Effect, missing: &[&str]) -> PolicyDecision {
    PolicyDecision {
        decision: effect,
        missing_requirements: missing.iter().map(|s| s.to_string()).collect(),
        ..allow()
    }
}

fn has(fs: &[SecurityFinding], name: &str) -> bool {
    fs.iter().any(|f| f.detector == name)
}

/// Project the record the caller would have built for policy eval, then detect.
fn run(e: &Event, d: &PolicyDecision) -> Vec<SecurityFinding> {
    let r = AuditRecord::from_event(e);
    detect_access(e, &r, d, e.field("event_id"))
}

#[test]
fn clean_access_produces_no_findings() {
    assert!(run(&clean(), &allow()).is_empty());
}

#[test]
fn forbidden_access_from_policy_deny() {
    let f = run(&clean(), &decision(Effect::Deny, &[]));
    assert!(has(&f, "app-forbidden-access"));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].base_level, "critical");
    assert_eq!(f[0].signals[0].family, DetectorFamily::AppAudit);
}

#[test]
fn missing_justification_and_approval() {
    let f = run(
        &clean(),
        &decision(Effect::RequireJustification, &["justification"]),
    );
    assert!(has(&f, "app-missing-justification"));
    let g = run(&clean(), &decision(Effect::RequireApproval, &["approval"]));
    assert!(has(&g, "app-missing-approval"));
}

#[test]
fn self_access_detected() {
    let e = ev(&[
        (keys::ACTOR, "anna"),
        (keys::OBJECT_TYPE, "persons"),
        (keys::IS_SELF, "true"),
    ]);
    assert!(has(&run(&e, &allow()), "app-self-access"));
}

#[test]
fn watched_subject_detected() {
    let e = ev(&[
        (keys::ACTOR, "anna"),
        (keys::SUBJECT, "p1"),
        (keys::WATCHED, "true"),
    ]);
    let f = run(&e, &allow());
    assert!(has(&f, "app-watched-subject-access"));
    assert_eq!(
        f.iter()
            .find(|x| x.detector == "app-watched-subject-access")
            .unwrap()
            .base_level,
        "high"
    );
}

#[test]
fn privilege_change_detected() {
    // privilege_operation is set by ingest; also inferred from a GRANT action.
    let e = ev(&[
        (keys::ACTOR, "dba"),
        (keys::ACTION, "GRANT"),
        (keys::OBJECT_TYPE, "roles"),
    ]);
    assert!(has(&run(&e, &allow()), "app-privilege-change"));
}

#[test]
fn export_and_bulk_are_distinct() {
    let exp = ev(&[
        (keys::ACTOR, "etl"),
        (keys::OBJECT_TYPE, "t"),
        (keys::EXPORT_OPERATION, "true"),
        (keys::BULK_OPERATION, "true"),
    ]);
    let f = run(&exp, &allow());
    // export wins; bulk is not double-counted when it's an export.
    assert!(has(&f, "app-export"));
    assert!(!has(&f, "app-bulk-access"));

    let bulk = ev(&[
        (keys::ACTOR, "u"),
        (keys::OBJECT_TYPE, "t"),
        (keys::BULK_OPERATION, "true"),
    ]);
    assert!(has(&run(&bulk, &allow()), "app-bulk-access"));
}

#[test]
fn service_account_interactive_misuse() {
    let svc = ev(&[
        (keys::ACTOR, "svc_etl"),
        (keys::OBJECT_TYPE, "t"),
        (keys::SERVICE_ACCOUNT, "true"),
        (keys::CLIENT_APPLICATION, "psql"),
    ]);
    assert!(has(&run(&svc, &allow()), "app-service-account-misuse"));

    // A service account on its own app client is fine.
    let ok = ev(&[
        (keys::ACTOR, "svc_etl"),
        (keys::OBJECT_TYPE, "t"),
        (keys::SERVICE_ACCOUNT, "true"),
        (keys::CLIENT_APPLICATION, "etl-runner"),
    ]);
    assert!(!has(&run(&ok, &allow()), "app-service-account-misuse"));
}

#[test]
fn failed_access_detected() {
    let denied = ev(&[
        (keys::ACTOR, "intern"),
        (keys::OBJECT_TYPE, "t"),
        (keys::OUTCOME, "denied"),
    ]);
    assert!(has(&run(&denied, &allow()), "app-failed-access"));
}

#[test]
fn a_single_access_can_fire_several_detectors() {
    // Watched subject + bulk + explicit policy deny on one access.
    let e = ev(&[
        (keys::ACTOR, "bruno"),
        (keys::SUBJECT, "p9"),
        (keys::OBJECT_TYPE, "raw_persons"),
        (keys::WATCHED, "true"),
        (keys::BULK_OPERATION, "true"),
    ]);
    let f = run(&e, &decision(Effect::Deny, &[]));
    assert!(has(&f, "app-forbidden-access"));
    assert!(has(&f, "app-watched-subject-access"));
    assert!(has(&f, "app-bulk-access"));
}

#[test]
fn non_audit_events_are_ignored() {
    let mut e = ev(&[("message", "kernel: oops")]);
    e.log_type = "system".into();
    e.fields.clear();
    assert!(run(&e, &decision(Effect::Deny, &[])).is_empty());
}

#[test]
fn detector_buckets_are_disjoint_and_cover_the_policy_set() {
    // No detector is both policy and standalone.
    for d in POLICY_DETECTORS {
        assert!(is_deterministic_policy(d));
        assert!(!is_standalone(d));
    }
    for d in STANDALONE_DETECTORS {
        assert!(is_standalone(d));
        assert!(!is_deterministic_policy(d));
    }
    // A weak/behavioral detector is in neither bucket → it fuses.
    for d in [
        "app-new-client",
        "app-off-hours",
        "app-volume-deviation",
        "app-bulk-access",
    ] {
        assert!(!is_deterministic_policy(d), "{d}");
        assert!(!is_standalone(d), "{d}");
    }
}

#[test]
fn classification_criticality_ladder_and_floors() {
    let mut r = AuditRecord::default();
    assert_eq!(classification_criticality(&r), 0.0); // no label
    r.classification.data_classification = Some("restricted".into());
    assert_eq!(classification_criticality(&r), 0.8);
    r.classification.data_classification = Some("SECRET".into()); // case-insensitive
    assert_eq!(classification_criticality(&r), 1.0);
    r.classification.data_classification = Some("weird-label".into());
    assert_eq!(classification_criticality(&r), 0.4); // custom → moderate
                                                     // sensitive_resource floors at 0.6 even with a low/absent label.
    r.classification.data_classification = Some("internal".into()); // 0.2
    r.classification.sensitive_resource = true;
    assert_eq!(classification_criticality(&r), 0.6);
    // watched_subject also floors.
    let mut w = AuditRecord::default();
    w.classification.watched_subject = true;
    assert_eq!(classification_criticality(&w), 0.6);
}

/// The history/baseline-dependent detectors ([`detect_behavioral`]) — proving
/// they are Trusted-only and fire on genuine novelty / off-hours / volume.
mod behavioral {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};
    use garmr_baseline::{BaselineStore, Entity, EntityKind, PromotionGuards, PromotionPolicy};
    use garmr_core::{AuditAction, AuditActor, AuditContext, QueryType};

    fn record(actor: &str, client: &str, object: &str, rows: u64) -> AuditRecord {
        AuditRecord {
            actor: AuditActor {
                actor_id: actor.into(),
                ..Default::default()
            },
            context: AuditContext {
                client_application: Some(client.into()),
                host: Some("db01".into()),
                database: Some("registry".into()),
                ..Default::default()
            },
            action: AuditAction {
                statement_fingerprint: Some(format!("sql1:{object}")),
                query_type: Some(QueryType::Select),
                object_name: Some(object.into()),
                rows_read: Some(rows),
                ..Default::default()
            },
            justification: Default::default(),
            classification: Default::default(),
        }
    }

    /// An audit event at a given hour, so `detect_behavioral` reads a controlled
    /// timestamp (the record it queries is passed separately).
    fn audit_ev(hour: u32) -> Event {
        let mut e = clean();
        e.ts = Utc.with_ymd_and_hms(2026, 6, 20, hour, 0, 0).unwrap();
        e
    }

    fn anna() -> Entity {
        Entity::new(EntityKind::User, "anna")
    }

    /// A store where "anna" has a TRUSTED baseline: client=jupyter,
    /// object=curated.persons, ~10 rows, all at 10:00 across many days.
    fn trained() -> BaselineStore {
        let mut s = BaselineStore::new(PromotionPolicy {
            min_observations: 5,
            min_span_secs: 0,
            min_distinct_sources: 1,
        });
        s.min_confidence = 5;
        let base = Utc.with_ymd_and_hms(2026, 6, 1, 10, 0, 0).unwrap();
        for i in 0..12 {
            let r = record("anna", "jupyter", "curated.persons", 8 + (i as u64 % 6));
            s.observe(&r, base + Duration::days(i), "pgaudit");
        }
        s
    }

    /// A store with the same observations still CANDIDATE (never promoted).
    fn learning() -> BaselineStore {
        let mut s = trained();
        // Rebuild without promoting.
        s.promote(&anna(), false, PromotionGuards::default()).ok();
        s
    }

    #[test]
    fn candidate_baseline_fires_nothing() {
        // Same observations, but NOT promoted → still learning → abstain.
        let mut s = BaselineStore::new(PromotionPolicy {
            min_observations: 5,
            min_span_secs: 0,
            min_distinct_sources: 1,
        });
        s.min_confidence = 5;
        let base = Utc.with_ymd_and_hms(2026, 6, 1, 10, 0, 0).unwrap();
        for i in 0..12 {
            s.observe(
                &record("anna", "jupyter", "curated.persons", 10),
                base + Duration::days(i),
                "pgaudit",
            );
        }
        assert_eq!(s.maturity(&anna()), garmr_baseline::Maturity::Candidate);
        // A wildly-anomalous access still yields nothing from a Candidate baseline.
        let anomaly = record("anna", "psql", "curated.salaries", 90_000);
        let f = detect_behavioral(&audit_ev(3), &anomaly, &s, None);
        assert!(f.is_empty(), "candidate baseline must not fire: {f:?}");
    }

    #[test]
    fn novelty_fires_on_trusted_baseline() {
        let s = learning();
        // New client + new object + (hence) new query fingerprint.
        let a = record("anna", "psql", "curated.salaries", 10);
        let f = detect_behavioral(&audit_ev(10), &a, &s, None);
        assert!(has(&f, "app-new-client"));
        assert!(has(&f, "app-new-object-access"));
        assert!(has(&f, "app-new-query-pattern"));
        // Source host db01 is known → no new-source-host finding.
        assert!(!has(&f, "app-new-source-host"));
        assert_eq!(
            f.iter()
                .find(|x| x.detector == "app-new-client")
                .unwrap()
                .signals[0]
                .family,
            DetectorFamily::AppAudit
        );
    }

    #[test]
    fn a_fully_known_access_is_quiet() {
        let s = learning();
        let known = record("anna", "jupyter", "curated.persons", 10);
        let f = detect_behavioral(&audit_ev(10), &known, &s, None);
        assert!(
            f.is_empty(),
            "a known access at a normal hour is quiet: {f:?}"
        );
    }

    #[test]
    fn off_hours_fires_at_an_unusual_hour() {
        let s = learning();
        let known = record("anna", "jupyter", "curated.persons", 10);
        // 03:00 is never in the baseline (all activity is at 10:00).
        assert!(has(
            &detect_behavioral(&audit_ev(3), &known, &s, None),
            "app-off-hours"
        ));
        // 10:00 is the normal hour → no off-hours finding.
        assert!(!has(
            &detect_behavioral(&audit_ev(10), &known, &s, None),
            "app-off-hours"
        ));
    }

    #[test]
    fn volume_deviation_fires_on_a_bulk_read() {
        let s = learning();
        let bulk = record("anna", "jupyter", "curated.persons", 90_000);
        let f = detect_behavioral(&audit_ev(10), &bulk, &s, None);
        let dev = f.iter().find(|x| x.detector == "app-volume-deviation");
        assert!(dev.is_some(), "expected a volume deviation: {f:?}");
        assert_eq!(dev.unwrap().base_level, "high");
        // A normal-sized read does not.
        let normal = record("anna", "jupyter", "curated.persons", 11);
        assert!(!has(
            &detect_behavioral(&audit_ev(10), &normal, &s, None),
            "app-volume-deviation"
        ));
    }

    #[test]
    fn an_actorless_access_is_ignored() {
        let s = learning();
        let a = record("", "psql", "curated.salaries", 90_000);
        assert!(detect_behavioral(&audit_ev(3), &a, &s, None).is_empty());
    }

    #[test]
    fn an_empty_store_never_fires() {
        let s = BaselineStore::default();
        let a = record("anna", "psql", "curated.salaries", 90_000);
        assert!(detect_behavioral(&audit_ev(3), &a, &s, None).is_empty());
    }

    // ---- peer-group deviation (Phase 9) -------------------------------------

    fn record_role(actor: &str, role: &str, client: &str, object: &str) -> AuditRecord {
        let mut r = record(actor, client, object, 10);
        r.actor.actor_role = Some(role.into());
        r
    }

    /// A store where the peer group (role `analyst`) is Trusted at {jupyter} — the
    /// team norm — while `anna` is Trusted at {jupyter, dbeaver}: she has an
    /// established client no trusted peer uses. Built with `observe_into` so the
    /// freeze is explicit — the role is promoted BEFORE anna's dbeaver is folded,
    /// so the peer norm never absorbs it (exactly how a real Trusted role behaves).
    /// `promote_role=false` leaves the peer group Candidate so peer_novelty abstains.
    fn peer_store(promote_role: bool) -> BaselineStore {
        let mut s = BaselineStore::new(PromotionPolicy {
            min_observations: 3,
            min_span_secs: 0,
            min_distinct_sources: 1,
        });
        s.min_confidence = 3;
        let base = Utc.with_ymd_and_hms(2026, 6, 1, 10, 0, 0).unwrap();
        let role = Entity::new(EntityKind::Role, "analyst");
        for i in 0..6 {
            s.observe_into(
                &role,
                &record("peer", "jupyter", "curated.persons", 10),
                base + Duration::days(i),
                "pgaudit",
            );
            s.observe_into(
                &anna(),
                &record("anna", "jupyter", "curated.persons", 10),
                base + Duration::days(i),
                "pgaudit",
            );
        }
        if promote_role {
            s.promote(&role, false, PromotionGuards::default()).unwrap();
        }
        for i in 0..4 {
            // If the role is Trusted it is frozen and never absorbs dbeaver.
            s.observe_into(
                &role,
                &record("peer2", "dbeaver", "curated.persons", 10),
                base + Duration::days(i),
                "pgaudit",
            );
            s.observe_into(
                &anna(),
                &record("anna", "dbeaver", "curated.persons", 10),
                base + Duration::days(i),
                "pgaudit",
            );
        }
        s.promote(&anna(), false, PromotionGuards::default())
            .unwrap();
        s
    }

    #[test]
    fn peer_deviation_fires_on_a_client_unique_to_the_actor() {
        let s = peer_store(true);
        // anna uses dbeaver NOW — established for her, unseen among trusted peers.
        let f = detect_behavioral(
            &audit_ev(10),
            &record_role("anna", "analyst", "dbeaver", "curated.persons"),
            &s,
            Some("e1"),
        );
        assert!(
            has(&f, "app-peer-deviation"),
            "got {:?}",
            f.iter().map(|x| &x.detector).collect::<Vec<_>>()
        );
    }

    #[test]
    fn peer_deviation_quiet_when_the_value_matches_the_peer_group() {
        let s = peer_store(true);
        // jupyter is the whole peer group's norm → no deviation.
        let f = detect_behavioral(
            &audit_ev(10),
            &record_role("anna", "analyst", "jupyter", "curated.persons"),
            &s,
            Some("e2"),
        );
        assert!(!has(&f, "app-peer-deviation"));
    }

    #[test]
    fn peer_deviation_abstains_when_the_peer_group_is_not_trusted() {
        // Same actor deviation, but the peer group baseline is still Candidate →
        // peer_novelty abstains (a still-learning group is never an authority).
        let s = peer_store(false);
        let f = detect_behavioral(
            &audit_ev(10),
            &record_role("anna", "analyst", "dbeaver", "curated.persons"),
            &s,
            Some("e3"),
        );
        assert!(
            !has(&f, "app-peer-deviation"),
            "peer_novelty must abstain unless the peer baseline is Trusted"
        );
    }

    #[test]
    fn no_role_means_no_peer_group_to_compare() {
        let s = peer_store(true);
        // The identical access WITHOUT a role: the peer plane can't name a group.
        let f = detect_behavioral(
            &audit_ev(10),
            &record("anna", "dbeaver", "curated.persons", 10),
            &s,
            Some("e4"),
        );
        assert!(!has(&f, "app-peer-deviation"));
    }
}
