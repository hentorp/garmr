// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use garmr_core::{
    ActorType, AuditAction, AuditActor, AuditClassification, AuditContext, AuditJustification,
    AuditRecord, Outcome, QueryType,
};

/// A minimal access: actor reading an object in a database.
fn access(actor: &str, database: &str, object: &str, qt: QueryType) -> AuditRecord {
    AuditRecord {
        actor: AuditActor {
            actor_id: actor.into(),
            ..Default::default()
        },
        context: AuditContext {
            database: Some(database.into()),
            environment: Some("prod".into()),
            ..Default::default()
        },
        action: AuditAction {
            object_name: Some(object.into()),
            query_type: Some(qt),
            outcome: Outcome::Success,
            ..Default::default()
        },
        justification: AuditJustification::default(),
        classification: AuditClassification::default(),
    }
}

fn deny_raw_persons() -> Policy {
    Policy {
        id: "deny-raw-persons".into(),
        version: 1,
        title: "No raw person data".into(),
        description: String::new(),
        priority: 0,
        enabled: true,
        subject: SubjectMatch::default(),
        resource: ResourceMatch {
            objects: vec!["raw.*".into()],
            ..Default::default()
        },
        condition: ConditionMatch::default(),
        effect: Effect::Deny,
        created_by: "alice".into(),
        approved_by: Some("alice".into()),
    }
}

#[test]
fn explicit_deny_wins_and_repetition_never_legitimizes() {
    let policies = vec![deny_raw_persons()];
    let rec = access("bruno", "registry", "raw.raw_persons", QueryType::Select);
    let ctx = AccessContext::new(&rec).with_objects(vec!["raw.raw_persons".into()]);

    // First access: denied.
    let d = evaluate(&ctx, &policies);
    assert_eq!(d.decision, Effect::Deny);
    assert_eq!(d.strongest_rule.as_deref(), Some("deny-raw-persons"));

    // The engine is stateless: the 10_000th identical access is denied identically.
    // A forbidden action does not become permitted by frequency.
    for _ in 0..10_000 {
        assert_eq!(evaluate(&ctx, &policies).decision, Effect::Deny);
    }
}

#[test]
fn deny_overrides_a_matching_allow() {
    // An allow-everything policy plus a targeted deny: deny must win, whatever
    // the priority — deny outranks allow by effect, not by ordering.
    let allow_all = Policy {
        id: "allow-all".into(),
        priority: 1000,
        effect: Effect::Allow,
        enabled: true,
        version: 1,
        title: String::new(),
        description: String::new(),
        subject: SubjectMatch::default(),
        resource: ResourceMatch::default(),
        condition: ConditionMatch::default(),
        created_by: String::new(),
        approved_by: None,
    };
    let policies = vec![allow_all, deny_raw_persons()];
    let rec = access("x", "registry", "raw.raw_persons", QueryType::Select);
    let ctx = AccessContext::new(&rec).with_objects(vec!["raw.raw_persons".into()]);
    let d = evaluate(&ctx, &policies);
    assert_eq!(d.decision, Effect::Deny);
    assert!(d.matched_policies.contains(&"allow-all".to_string()));
    assert!(d.matched_policies.contains(&"deny-raw-persons".to_string()));
}

#[test]
fn missing_justification_is_flagged_and_satisfied_when_present() {
    let policy = Policy {
        id: "sensitive-needs-ticket".into(),
        effect: Effect::RequireJustification,
        resource: ResourceMatch {
            objects: vec!["curated.persons".into()],
            ..Default::default()
        },
        enabled: true,
        version: 1,
        priority: 0,
        title: String::new(),
        description: String::new(),
        subject: SubjectMatch::default(),
        condition: ConditionMatch::default(),
        created_by: String::new(),
        approved_by: None,
    };
    // No justification → require_justification + missing requirement.
    let mut rec = access("anna", "registry", "curated.persons", QueryType::Select);
    let ctx = AccessContext::new(&rec).with_objects(vec!["curated.persons".into()]);
    let d = evaluate(&ctx, std::slice::from_ref(&policy));
    assert_eq!(d.decision, Effect::RequireJustification);
    assert_eq!(d.missing_requirements, vec!["justification".to_string()]);

    // With a ticket → the requirement is satisfied → allow.
    rec.justification.ticket_ref = Some("ARENDE-1".into());
    let ctx2 = AccessContext::new(&rec).with_objects(vec!["curated.persons".into()]);
    let d2 = evaluate(&ctx2, std::slice::from_ref(&policy));
    assert_eq!(d2.decision, Effect::Allow);
    assert!(d2.missing_requirements.is_empty());
}

#[test]
fn default_is_allow_when_nothing_matches() {
    let rec = access(
        "anna",
        "registry",
        "curated.persons_view",
        QueryType::Select,
    );
    let ctx = AccessContext::new(&rec);
    let d = evaluate(&ctx, &[deny_raw_persons()]);
    assert_eq!(d.decision, Effect::Allow);
    assert!(d.strongest_rule.is_none());
    assert!(d.reason.contains("no policy matched"));
}

#[test]
fn off_hours_condition_via_hour_window() {
    let policy = Policy {
        id: "off-hours-sensitive".into(),
        effect: Effect::Alert,
        resource: ResourceMatch {
            objects: vec!["raw.*".into()],
            ..Default::default()
        },
        condition: ConditionMatch {
            hours: Some(HourWindow {
                start: 8,
                end: 18,
                outside: true,
            }),
            ..Default::default()
        },
        enabled: true,
        version: 1,
        priority: 0,
        title: String::new(),
        description: String::new(),
        subject: SubjectMatch::default(),
        created_by: String::new(),
        approved_by: None,
    };
    let rec = access("bruno", "registry", "raw.raw_persons", QueryType::Select);
    let objs = vec!["raw.raw_persons".to_string()];
    // 22:00 → outside working hours → alert.
    let night = AccessContext::new(&rec)
        .with_objects(objs.clone())
        .with_time(2, 22);
    assert_eq!(
        evaluate(&night, std::slice::from_ref(&policy)).decision,
        Effect::Alert
    );
    // 10:00 → inside working hours → no match → allow.
    let day = AccessContext::new(&rec).with_objects(objs).with_time(2, 10);
    assert_eq!(
        evaluate(&day, std::slice::from_ref(&policy)).decision,
        Effect::Allow
    );
}

#[test]
fn service_account_and_privilege_conditions() {
    let policy = Policy {
        id: "no-interactive-svc".into(),
        effect: Effect::Alert,
        subject: SubjectMatch {
            service_account: Some(true),
            ..Default::default()
        },
        condition: ConditionMatch {
            client_applications: vec!["psql".into()],
            ..Default::default()
        },
        enabled: true,
        version: 1,
        priority: 0,
        title: String::new(),
        description: String::new(),
        resource: ResourceMatch::default(),
        created_by: String::new(),
        approved_by: None,
    };
    let mut rec = access("svc_etl", "dwh", "dwh.customers", QueryType::Select);
    rec.actor.service_account = true;
    rec.actor.actor_type = ActorType::ServiceAccount;
    rec.context.client_application = Some("psql".into());
    let ctx = AccessContext::new(&rec);
    assert_eq!(
        evaluate(&ctx, std::slice::from_ref(&policy)).decision,
        Effect::Alert
    );

    // A human on psql does not match the service-account subject.
    let mut human = access("anna", "dwh", "dwh.customers", QueryType::Select);
    human.context.client_application = Some("psql".into());
    let hctx = AccessContext::new(&human);
    assert_eq!(
        evaluate(&hctx, std::slice::from_ref(&policy)).decision,
        Effect::Allow
    );
}

#[test]
fn simulation_reports_blast_radius() {
    let policy = deny_raw_persons();
    let recs: Vec<AuditRecord> = vec![
        access("a", "registry", "raw.raw_persons", QueryType::Select),
        access("b", "registry", "raw.other", QueryType::Select),
        access("c", "registry", "curated.persons", QueryType::Select), // no match
    ];
    // Give the first two matching objects; the third a non-raw object.
    let ctxs = vec![
        AccessContext::new(&recs[0])
            .with_objects(vec!["raw.raw_persons".into()])
            .with_evidence("ev1"),
        AccessContext::new(&recs[1])
            .with_objects(vec!["raw.other".into()])
            .with_evidence("ev2"),
        AccessContext::new(&recs[2])
            .with_objects(vec!["curated.persons".into()])
            .with_evidence("ev3"),
    ];
    let rep = simulate(&policy, &ctxs);
    assert_eq!(rep.evaluated, 3);
    assert_eq!(rep.matched, 2);
    assert_eq!(rep.deny, 2);
    assert_eq!(rep.affected_users, vec!["a".to_string(), "b".to_string()]);
    assert!(rep
        .affected_objects
        .contains(&"raw.raw_persons".to_string()));
    assert_eq!(
        rep.sample_event_ids,
        vec!["ev1".to_string(), "ev2".to_string()]
    );
}

#[test]
fn simulation_flags_likely_false_positives() {
    // A deny that also catches justified accesses → those count as likely FPs.
    let policy = deny_raw_persons();
    let mut justified = access("a", "registry", "raw.raw_persons", QueryType::Select);
    justified.justification.ticket_ref = Some("T-1".into());
    let ctxs = vec![AccessContext::new(&justified).with_objects(vec!["raw.raw_persons".into()])];
    let rep = simulate(&policy, &ctxs);
    assert_eq!(rep.deny, 1);
    assert_eq!(rep.likely_false_positives, 1);
}

#[test]
fn object_pattern_matching() {
    assert!(object_pattern_matches("raw.*", "raw.persons"));
    assert!(object_pattern_matches("raw.*", "raw"));
    assert!(!object_pattern_matches("raw.*", "curated.persons"));
    assert!(object_pattern_matches("persons", "public.persons")); // unqualified
    assert!(object_pattern_matches("public.persons", "PUBLIC.PERSONS")); // case-insensitive
    assert!(!object_pattern_matches("persons", "personseditor"));
}

#[test]
fn digest_is_stable_and_order_independent() {
    let a = deny_raw_persons();
    let mut b = a.clone();
    b.id = "z-other".into();
    let d1 = policy_set_digest(&[a.clone(), b.clone()]);
    let d2 = policy_set_digest(&[b, a]);
    assert_eq!(d1, d2, "digest must not depend on ordering");
    assert!(d1.starts_with("pol1:"));
}

#[test]
fn validate_accepts_a_well_scoped_policy() {
    assert!(deny_raw_persons().validate().is_ok());
}

#[test]
fn validate_rejects_an_empty_id() {
    let mut p = deny_raw_persons();
    p.id = "  ".into();
    assert!(p.validate().is_err());
}

#[test]
fn validate_rejects_an_empty_pattern_entry() {
    let mut p = deny_raw_persons();
    p.resource.objects = vec!["raw.*".into(), "".into()];
    let e = p.validate().unwrap_err();
    assert!(e.contains("resource.objects"), "{e}");
}

#[test]
fn validate_rejects_a_fully_unscoped_restrictive_policy() {
    // A deny with no subject/resource/condition matches every access.
    let p = Policy {
        id: "deny-everything".into(),
        version: 1,
        title: String::new(),
        description: String::new(),
        priority: 0,
        enabled: true,
        subject: SubjectMatch::default(),
        resource: ResourceMatch::default(),
        condition: ConditionMatch::default(),
        effect: Effect::Deny,
        created_by: "x".into(),
        approved_by: None,
    };
    let e = p.validate().unwrap_err();
    assert!(e.contains("match every access"), "{e}");
    // The same shape with a non-restrictive effect is fine (it documents an allow).
    let mut allow = p.clone();
    allow.id = "allow-all".into();
    allow.effect = Effect::Allow;
    assert!(allow.validate().is_ok());
    // Restrictive but scoped (by condition alone) is fine.
    let mut scoped = p;
    scoped.id = "deny-exports".into();
    scoped.condition = ConditionMatch {
        export: Some(true),
        ..Default::default()
    };
    assert!(scoped.validate().is_ok());
}

#[test]
fn matcher_is_empty_helpers() {
    assert!(SubjectMatch::default().is_empty());
    assert!(ResourceMatch::default().is_empty());
    assert!(ConditionMatch::default().is_empty());
    assert!(!ResourceMatch {
        objects: vec!["x".into()],
        ..Default::default()
    }
    .is_empty());
    assert!(!ConditionMatch {
        export: Some(true),
        ..Default::default()
    }
    .is_empty());
    assert!(!SubjectMatch {
        service_account: Some(true),
        ..Default::default()
    }
    .is_empty());
}

#[test]
fn policy_digest_distinguishes_content_even_when_disabled() {
    // policy_set_digest collapses disabled policies to the empty-set hash; the
    // per-policy digest must NOT — two different disabled policies differ.
    let mut a = deny_raw_persons();
    a.enabled = false;
    let mut b = a.clone();
    b.resource.objects = vec!["curated.*".into()];
    assert_ne!(
        policy_digest(&a),
        policy_digest(&b),
        "content must drive the digest"
    );
    // Identical content → identical digest (immutability guard relies on this).
    assert_eq!(policy_digest(&a), policy_digest(&a.clone()));
    // And it differs from the set digest's empty-set constant.
    assert_ne!(policy_digest(&a), policy_set_digest(&[a.clone()]));
}
