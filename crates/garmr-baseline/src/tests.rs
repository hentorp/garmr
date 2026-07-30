// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use chrono::{TimeZone, Utc};
use garmr_core::{AuditAction, AuditActor, AuditContext, AuditRecord, QueryType};

fn base_ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 10, 0, 0).unwrap()
}

/// An access by `actor` with a given client / fingerprint / row count, at `hour`.
fn access(actor: &str, client: &str, fp: &str, rows: u64) -> AuditRecord {
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
            statement_fingerprint: Some(fp.into()),
            query_type: Some(QueryType::Select),
            object_name: Some("curated.persons".into()),
            rows_read: Some(rows),
            ..Default::default()
        },
        justification: Default::default(),
        classification: Default::default(),
    }
}

fn test_store() -> BaselineStore {
    let mut s = BaselineStore::new(PromotionPolicy {
        min_observations: 5,
        min_span_secs: 0,
        min_distinct_sources: 1,
    });
    s.min_confidence = 5;
    s
}

fn anna() -> Entity {
    Entity::new(EntityKind::User, "anna")
}

/// Feed `n` daytime accesses (hour 10) across `n` hours for one user.
fn seed_daytime(s: &mut BaselineStore, n: i64, client: &str, fp: &str, rows: u64) {
    for i in 0..n {
        let ts = base_ts() + Duration::hours(i);
        s.observe(&access("anna", client, fp, rows), ts, "pgaudit");
    }
}

#[test]
fn candidate_does_not_fire_only_trusted_does() {
    let mut s = test_store();
    seed_daytime(&mut s, 6, "jupyter", "fp1", 10);
    // Candidate: never fires, even for a genuinely-new value.
    assert!(!s.novelty(&anna(), Dimension::Client, "psql").novel);
    assert_eq!(s.maturity(&anna()), Maturity::Candidate);

    // Promote → Trusted.
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    assert_eq!(s.maturity(&anna()), Maturity::Stable);

    // Now novelty fires for the unseen client, not for the seen one.
    assert!(s.novelty(&anna(), Dimension::Client, "psql").novel);
    assert!(!s.novelty(&anna(), Dimension::Client, "jupyter").novel);
    assert!(
        s.novelty(&anna(), Dimension::QueryFingerprint, "fp-new")
            .novel
    );
}

#[test]
fn hard_blocks_forbid_promotion_even_for_an_analyst() {
    let mut s = test_store();
    seed_daytime(&mut s, 6, "jupyter", "fp1", 10);

    // A policy violation in the window is an inviolable hard block: neither auto
    // nor analyst may promote — a forbidden action is never learned as normal.
    let g = PromotionGuards {
        policy_violation_in_window: true,
        ..Default::default()
    };
    assert!(s.promote(&anna(), false, g).is_err());
    assert!(
        s.promote(&anna(), true, g).is_err(),
        "analyst must not override a policy violation"
    );

    // An open case is likewise a hard block.
    let g2 = PromotionGuards {
        entity_has_open_case: true,
        ..Default::default()
    };
    assert!(s.promote(&anna(), true, g2).is_err());

    // Clear → analyst (and auto) can promote.
    assert!(s
        .promote(&anna(), false, PromotionGuards::default())
        .is_ok());
}

#[test]
fn threshold_blocks_stop_auto_but_analyst_can_clear() {
    // Default policy needs 30 obs + 3-day span; feed only a few.
    let mut s = BaselineStore::default();
    seed_daytime(&mut s, 4, "jupyter", "fp1", 10);
    // Auto promotion blocked (insufficient observations/span).
    let blocks = s
        .promote(&anna(), false, PromotionGuards::default())
        .unwrap_err();
    assert!(blocks.contains(&PromotionBlock::InsufficientObservations));
    // Analyst may promote despite the threshold blocks (no hard block present).
    assert!(s.promote(&anna(), true, PromotionGuards::default()).is_ok());
}

#[test]
fn off_hours_fires_only_after_trust_and_history() {
    let mut s = test_store();
    // 10 accesses all at hour 10 (daytime).
    for i in 0..10 {
        let ts = base_ts() + Duration::days(i); // all at 10:00
        s.observe(&access("anna", "jupyter", "fp1", 10), ts, "pgaudit");
    }
    // Candidate → abstain.
    assert!(!s.off_hours(&anna(), 3).off_hours);
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    // 03:00 is rare (never seen); 10:00 is normal.
    assert!(s.off_hours(&anna(), 3).off_hours);
    assert!(!s.off_hours(&anna(), 10).off_hours);
}

#[test]
fn numeric_deviation_flags_a_bulk_read() {
    let mut s = test_store();
    // A history of small reads (5..15 rows).
    for i in 0..12 {
        let ts = base_ts() + Duration::hours(i);
        s.observe(
            &access("anna", "jupyter", "fp1", 5 + (i as u64 % 10)),
            ts,
            "pgaudit",
        );
    }
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    assert!(
        s.deviation(&anna(), Dimension::RowsRead, 50_000.0)
            .deviating
    );
    assert!(!s.deviation(&anna(), Dimension::RowsRead, 12.0).deviating);
}

#[test]
fn peer_novelty_flags_a_value_absent_from_the_group() {
    let mut s = test_store();
    let peer = Entity::new(EntityKind::PeerGroup, "analysts");
    // The group uses jupyter + metabase.
    for (i, c) in [
        "jupyter", "metabase", "jupyter", "metabase", "jupyter", "metabase",
    ]
    .iter()
    .enumerate()
    {
        let ts = base_ts() + Duration::hours(i as i64);
        s.observe_into(&peer, &access("someone", c, "fpx", 10), ts, "pgaudit");
    }
    // anna uses jupyter + psql.
    for (i, c) in ["jupyter", "psql", "jupyter", "psql", "jupyter", "psql"]
        .iter()
        .enumerate()
    {
        let ts = base_ts() + Duration::hours(i as i64);
        s.observe(&access("anna", c, "fp1", 10), ts, "pgaudit");
    }
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    s.promote(&peer, false, PromotionGuards::default()).unwrap();
    let novel = s.peer_novelty(&anna(), &peer, Dimension::Client);
    assert!(novel.contains(&"psql".to_string()));
    assert!(!novel.contains(&"jupyter".to_string()));
}

#[test]
fn maturity_progresses_empty_learning_candidate_stable() {
    let mut s = test_store();
    assert_eq!(s.maturity(&anna()), Maturity::Empty);
    seed_daytime(&mut s, 3, "jupyter", "fp1", 10); // below min_observations(5)
    assert_eq!(s.maturity(&anna()), Maturity::Learning);
    seed_daytime(&mut s, 3, "jupyter", "fp1", 10); // now >=5
    assert_eq!(s.maturity(&anna()), Maturity::Candidate);
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    assert_eq!(s.maturity(&anna()), Maturity::Stable);
}

#[test]
fn one_access_seeds_actor_application_and_role() {
    let mut s = test_store();
    let mut rec = access("svc_etl", "cron", "fp1", 10);
    rec.actor.service_account = true;
    rec.actor.actor_role = Some("etl".into());
    rec.context.application_name = Some("warehouse".into());
    s.observe(&rec, base_ts(), "pgaudit");
    assert!(s
        .get(&Entity::new(EntityKind::ServiceAccount, "svc_etl"))
        .is_some());
    assert!(s
        .get(&Entity::new(EntityKind::Application, "warehouse"))
        .is_some());
    assert!(s.get(&Entity::new(EntityKind::Role, "etl")).is_some());
    // A human (non-service) actor is a User.
    s.observe(&access("anna", "jupyter", "fp1", 10), base_ts(), "pgaudit");
    assert!(s.get(&Entity::new(EntityKind::User, "anna")).is_some());
}

#[test]
fn suspicious_profile_never_answers_queries() {
    let mut s = test_store();
    seed_daytime(&mut s, 6, "jupyter", "fp1", 10);
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    assert!(s.novelty(&anna(), Dimension::Client, "psql").novel);
    // Marking suspicious pulls it out of the trusted view.
    s.mark_suspicious(&anna());
    assert!(!s.novelty(&anna(), Dimension::Client, "psql").novel);
    assert_eq!(s.maturity(&anna()), Maturity::Suspicious);
}

#[test]
fn store_round_trips_through_json() {
    // A tuple-keyed profile map cannot serialize as a JSON object; the store
    // must round-trip via the flat-array representation (persistence relies on
    // this — see the app-audit reload path).
    let mut s = test_store();
    seed_daytime(&mut s, 6, "jupyter", "fp1", 10);
    s.promote(&anna(), false, PromotionGuards::default())
        .unwrap();
    let bytes = serde_json::to_vec(&s).expect("serialize");
    assert!(bytes.len() > 2, "serialized store must not be empty/`{{}}`");
    let back: BaselineStore = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(back.maturity(&anna()), Maturity::Stable);
    assert!(back.novelty(&anna(), Dimension::Client, "psql").novel);
    assert!(!back.novelty(&anna(), Dimension::Client, "jupyter").novel);
    assert_eq!(s.digest(), back.digest());
}

#[test]
fn digest_reflects_content() {
    let mut s = test_store();
    let empty_digest = s.digest();
    seed_daytime(&mut s, 6, "jupyter", "fp1", 10);
    // A populated store must NOT share the empty store's digest (the old bug:
    // serialization silently failed and every digest hashed empty bytes).
    assert_ne!(s.digest(), empty_digest);
}

#[test]
fn a_suspicious_profile_cannot_be_promoted_until_cleared() {
    let mut s = test_store();
    seed_daytime(&mut s, 6, "jupyter", "fp1", 10);
    s.mark_suspicious(&anna());
    // Suspicious → promotion refused, even for an analyst.
    let err = s
        .promote(&anna(), true, PromotionGuards::default())
        .unwrap_err();
    assert!(err.contains(&PromotionBlock::EntitySuspicious));
    // Human review clears it → back to Candidate → promotable again.
    s.clear_suspicion(&anna());
    assert_eq!(s.maturity(&anna()), Maturity::Candidate);
    assert!(s
        .promote(&anna(), false, PromotionGuards::default())
        .is_ok());
}

#[test]
fn digest_is_versioned_and_deterministic() {
    let mut a = test_store();
    let mut b = test_store();
    // Same observations in different order → same final BTreeMap → same digest.
    seed_daytime(&mut a, 4, "jupyter", "fp1", 10);
    for i in (0..4).rev() {
        let ts = base_ts() + Duration::hours(i);
        b.observe(&access("anna", "jupyter", "fp1", 10), ts, "pgaudit");
    }
    assert!(a.digest().starts_with("bl1:"));
    assert_eq!(a.digest(), b.digest());
}
