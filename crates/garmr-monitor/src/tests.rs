// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use chrono::{Duration, TimeZone, Utc};
use garmr_core::{AuditAction, AuditActor, AuditContext, AuditRecord, QueryType};

/// A fixed reference "now" so the time-window tests are deterministic.
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 26, 12, 0, 0).unwrap()
}

/// A minimal access with an actor, an optional role/group/application, and an
/// object.
fn access(actor: &str, object: &str) -> AuditRecord {
    AuditRecord {
        actor: AuditActor {
            actor_id: actor.into(),
            ..Default::default()
        },
        context: AuditContext::default(),
        action: AuditAction {
            object_name: Some(object.into()),
            query_type: Some(QueryType::Select),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn watch_user(user: &str, state: MonitoringState) -> UserMonitoringProfile {
    UserMonitoringProfile::new(
        MonitoringTarget::User(user.into()),
        state,
        now() - Duration::days(1),
        "alice",
    )
    .with_reason("insider-risk review")
    .with_risk_level("medium")
}

#[test]
fn monitoring_only_raises_attention_never_below_one() {
    // Every state's multiplier is >= 1.0 — monitoring never suppresses attention
    // and never manufactures guilt.
    for state in [
        MonitoringState::Normal,
        MonitoringState::Watched,
        MonitoringState::ElevatedMonitoring,
        MonitoringState::Investigation,
        MonitoringState::Restricted,
        MonitoringState::Retired,
        MonitoringState::Other,
    ] {
        assert!(
            sensitivity_multiplier(state) >= 1.0,
            "{} must never be below 1.0",
            state.as_str()
        );
    }
    // Normal / Retired / Other are exactly neutral.
    assert_eq!(sensitivity_multiplier(MonitoringState::Normal), 1.0);
    assert_eq!(sensitivity_multiplier(MonitoringState::Retired), 1.0);
    assert_eq!(sensitivity_multiplier(MonitoringState::Other), 1.0);
    // The active watch states escalate strictly.
    assert!(
        sensitivity_multiplier(MonitoringState::Watched)
            < sensitivity_multiplier(MonitoringState::ElevatedMonitoring)
    );
    assert!(
        sensitivity_multiplier(MonitoringState::ElevatedMonitoring)
            < sensitivity_multiplier(MonitoringState::Investigation)
    );
    assert!(
        sensitivity_multiplier(MonitoringState::Investigation)
            < sensitivity_multiplier(MonitoringState::Restricted)
    );
    // The registry surface agrees with the free function.
    assert_eq!(
        MonitoringRegistry::sensitivity_multiplier(MonitoringState::Investigation),
        2.0
    );
}

#[test]
fn expiry_deactivates_a_profile() {
    // A profile that expired yesterday is inactive today.
    let expired =
        watch_user("bruno", MonitoringState::Watched).with_valid_until(now() - Duration::hours(1));
    let reg = MonitoringRegistry::with_profiles(vec![expired]);
    assert!(reg.active_for_user("bruno", now()).is_none());
    assert_eq!(reg.multiplier_for_user("bruno", now()), 1.0);

    // The same profile, checked one hour before it expired, is active.
    let earlier = now() - Duration::hours(2);
    assert!(reg.active_for_user("bruno", earlier).is_some());
}

#[test]
fn future_dated_profile_is_not_yet_active() {
    let future = UserMonitoringProfile::new(
        MonitoringTarget::User("bruno".into()),
        MonitoringState::Watched,
        now() + Duration::days(1),
        "alice",
    );
    let reg = MonitoringRegistry::with_profiles(vec![future]);
    assert!(reg.active_for_user("bruno", now()).is_none());
}

#[test]
fn retired_is_inactive() {
    let retired = watch_user("bruno", MonitoringState::Retired);
    let reg = MonitoringRegistry::with_profiles(vec![retired]);
    assert!(reg.active_for_user("bruno", now()).is_none());
    assert_eq!(reg.multiplier_for_user("bruno", now()), 1.0);
}

#[test]
fn target_matching_user() {
    let reg =
        MonitoringRegistry::with_profiles(vec![watch_user("bruno", MonitoringState::Watched)]);
    // Case-insensitive user match.
    assert!(reg.active_for_user("BRUNO", now()).is_some());
    assert!(reg.active_for_user("anna", now()).is_none());
    // Also matches through an access.
    let rec = access("bruno", "public.persons");
    assert!(reg.active_for_access(&rec, &[], now()).is_some());
}

#[test]
fn target_matching_role_and_group() {
    let role = UserMonitoringProfile::new(
        MonitoringTarget::Role("dba".into()),
        MonitoringState::ElevatedMonitoring,
        now() - Duration::days(1),
        "alice",
    );
    let group = UserMonitoringProfile::new(
        MonitoringTarget::Group("finance".into()),
        MonitoringState::Watched,
        now() - Duration::days(1),
        "alice",
    );
    let reg = MonitoringRegistry::with_profiles(vec![role, group]);

    // A bare user lookup can never match a role/group target.
    assert!(reg.active_for_user("someone", now()).is_none());

    // An access carrying the role matches the role target.
    let mut rec = access("someone", "t");
    rec.actor.actor_role = Some("DBA".into());
    assert_eq!(
        reg.active_for_access(&rec, &[], now()).map(|p| p.state),
        Some(MonitoringState::ElevatedMonitoring)
    );

    // An access carrying the group matches the group target.
    let mut rec2 = access("other", "t");
    rec2.actor.actor_groups = vec!["ops".into(), "finance".into()];
    assert_eq!(
        reg.active_for_access(&rec2, &[], now()).map(|p| p.state),
        Some(MonitoringState::Watched)
    );
}

#[test]
fn target_matching_application_and_resource() {
    let app = UserMonitoringProfile::new(
        MonitoringTarget::Application("registry".into()),
        MonitoringState::Watched,
        now() - Duration::days(1),
        "alice",
    );
    let resource = UserMonitoringProfile::new(
        MonitoringTarget::Resource("raw.*".into()),
        MonitoringState::Investigation,
        now() - Duration::days(1),
        "alice",
    );
    let reg = MonitoringRegistry::with_profiles(vec![app, resource]);

    // Application target matches an access through that application.
    let mut rec = access("u", "curated.view");
    rec.context.application_name = Some("registry".into());
    assert!(reg.active_for_access(&rec, &[], now()).is_some());

    // Resource target matches via the schema wildcard, using resolved objects.
    let rec2 = access("u", "curated.view");
    let objs = vec!["raw.persons".to_string()];
    assert_eq!(
        reg.active_for_access(&rec2, &objs, now()).map(|p| p.state),
        Some(MonitoringState::Investigation)
    );

    // A non-raw access with no matching application is not monitored.
    let rec3 = access("u", "curated.view");
    assert!(reg.active_for_access(&rec3, &[], now()).is_none());
}

#[test]
fn strongest_profile_is_selected() {
    // Two active profiles apply to the same access; the stronger state wins.
    let watched = watch_user("bruno", MonitoringState::Watched);
    let investigation = UserMonitoringProfile::new(
        MonitoringTarget::Group("finance".into()),
        MonitoringState::Investigation,
        now() - Duration::days(1),
        "alice",
    );
    let reg = MonitoringRegistry::with_profiles(vec![watched, investigation]);

    let mut rec = access("bruno", "t");
    rec.actor.actor_groups = vec!["finance".into()];
    let selected = reg.active_for_access(&rec, &[], now()).unwrap();
    assert_eq!(selected.state, MonitoringState::Investigation);
    assert_eq!(reg.multiplier_for_access(&rec, &[], now()), 2.0);
}

#[test]
fn application_scope_narrows_a_user_profile() {
    // Watch bruno, but only in the "registry" application.
    let scoped = watch_user("bruno", MonitoringState::Watched)
        .with_application_scope(vec!["registry".into()]);
    let reg = MonitoringRegistry::with_profiles(vec![scoped]);

    let mut in_scope = access("bruno", "t");
    in_scope.context.application_name = Some("registry".into());
    assert!(reg.active_for_access(&in_scope, &[], now()).is_some());

    let mut out_of_scope = access("bruno", "t");
    out_of_scope.context.application_name = Some("warehouse".into());
    assert!(reg.active_for_access(&out_of_scope, &[], now()).is_none());
}

#[test]
fn start_monitoring_emits_audited_change_and_rejects_anonymous() {
    let mut reg = MonitoringRegistry::new();

    // Anonymous start (empty created_by) is rejected — no anonymous change.
    let mut anon = watch_user("bruno", MonitoringState::Watched);
    anon.created_by = String::new();
    assert_eq!(
        reg.start_monitoring(anon, now(), "ledger-1"),
        Err(MonitoringError::EmptyActor)
    );

    // A proper start emits a change Normal -> Watched, version 1, attributed.
    let profile = watch_user("bruno", MonitoringState::Watched);
    let change = reg.start_monitoring(profile, now(), "ledger-1").unwrap();
    assert_eq!(change.from_state, MonitoringState::Normal);
    assert_eq!(change.to_state, MonitoringState::Watched);
    assert_eq!(change.actor, "alice");
    assert_eq!(change.audit_ref, "ledger-1");
    assert!(change.change_id.starts_with("chg-"));
    assert_eq!(reg.profiles()[0].version, 1);
    assert_eq!(reg.profiles()[0].audit_refs, vec!["ledger-1".to_string()]);

    // Starting the same target twice is rejected.
    assert!(matches!(
        reg.start_monitoring(watch_user("bruno", MonitoringState::Watched), now(), "x"),
        Err(MonitoringError::AlreadyExists(_))
    ));
}

#[test]
fn update_bumps_version_and_records_transition() {
    let mut reg = MonitoringRegistry::new();
    let target = MonitoringTarget::User("bruno".into());
    reg.start_monitoring(watch_user("bruno", MonitoringState::Watched), now(), "l1")
        .unwrap();

    // Escalate to Investigation.
    let change = reg
        .update(
            &target,
            MonitoringState::Investigation,
            "escalated after finding",
            ChangeMeta::new("anna", now(), "l2"),
        )
        .unwrap();
    assert_eq!(change.from_state, MonitoringState::Watched);
    assert_eq!(change.to_state, MonitoringState::Investigation);
    assert_eq!(change.actor, "anna");
    assert_eq!(reg.profiles()[0].version, 2);
    assert_eq!(reg.profiles()[0].state, MonitoringState::Investigation);
    assert_eq!(
        reg.profiles()[0].audit_refs,
        vec!["l1".to_string(), "l2".to_string()]
    );

    // Anonymous update is rejected.
    assert_eq!(
        reg.update(
            &target,
            MonitoringState::Restricted,
            "x",
            ChangeMeta::new("", now(), "l3")
        ),
        Err(MonitoringError::EmptyActor)
    );

    // Updating an unknown target fails.
    assert!(matches!(
        reg.update(
            &MonitoringTarget::User("ghost".into()),
            MonitoringState::Watched,
            "x",
            ChangeMeta::new("anna", now(), "l4")
        ),
        Err(MonitoringError::NotFound(_))
    ));
}

#[test]
fn stop_monitoring_retires_and_deactivates() {
    let mut reg = MonitoringRegistry::new();
    let target = MonitoringTarget::User("bruno".into());
    reg.start_monitoring(watch_user("bruno", MonitoringState::Watched), now(), "l1")
        .unwrap();

    let change = reg
        .stop_monitoring(
            &target,
            "review closed",
            ChangeMeta::new("alice", now(), "l2"),
        )
        .unwrap();
    assert_eq!(change.to_state, MonitoringState::Retired);
    assert_eq!(reg.profiles()[0].version, 2);
    // Retired → no longer active.
    assert!(reg.active_for_user("bruno", now()).is_none());
}

#[test]
fn restrict_scope_narrows_without_changing_state() {
    let mut reg = MonitoringRegistry::new();
    let target = MonitoringTarget::User("bruno".into());
    reg.start_monitoring(watch_user("bruno", MonitoringState::Watched), now(), "l1")
        .unwrap();

    let change = reg
        .restrict_scope(
            &target,
            vec!["registry".into()],
            vec!["raw.*".into()],
            "limit to sensitive scope",
            ChangeMeta::new("alice", now(), "l2"),
        )
        .unwrap();
    // State unchanged: from == to.
    assert_eq!(change.from_state, change.to_state);
    assert_eq!(change.to_state, MonitoringState::Watched);
    assert_eq!(reg.profiles()[0].version, 2);
    assert_eq!(
        reg.profiles()[0].application_scope,
        vec!["registry".to_string()]
    );

    // Idempotent extension: repeating the same scope does not duplicate.
    reg.restrict_scope(
        &target,
        vec!["REGISTRY".into()],
        vec![],
        "again",
        ChangeMeta::new("alice", now(), "l3"),
    )
    .unwrap();
    assert_eq!(
        reg.profiles()[0].application_scope,
        vec!["registry".to_string()]
    );
}

#[test]
fn digest_is_stable_order_independent_and_ignores_retired() {
    let a = watch_user("bruno", MonitoringState::Watched);
    let mut b = watch_user("anna", MonitoringState::Investigation);
    b.user_id = "anna".into();

    let reg1 = MonitoringRegistry::with_profiles(vec![a.clone(), b.clone()]);
    let reg2 = MonitoringRegistry::with_profiles(vec![b.clone(), a.clone()]);
    assert_eq!(
        reg1.digest(),
        reg2.digest(),
        "digest must be order-independent"
    );
    assert!(reg1.digest().starts_with("mon1:"));

    // A retired profile does not contribute to the digest.
    let mut retired = watch_user("carl", MonitoringState::Retired);
    retired.user_id = "carl".into();
    let reg3 = MonitoringRegistry::with_profiles(vec![a, b, retired]);
    assert_eq!(
        reg1.digest(),
        reg3.digest(),
        "retired profiles must not change the active-set digest"
    );
}