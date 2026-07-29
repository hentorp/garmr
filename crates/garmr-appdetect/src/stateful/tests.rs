// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic tests for the stateful detector plane. Every test uses a small
//! purpose-built [`StatefulConfig`] so thresholds are hit with a handful of
//! events, and asserts on exact detector ids / stamped evidence — no timing, no
//! randomness.

use super::*;
use garmr_core::app_audit::keys;
use garmr_core::Event;
use std::collections::BTreeMap;

/// Small thresholds so an episode trips in a few events; everything else default.
fn cfg() -> StatefulConfig {
    StatefulConfig {
        slow_min_subjects: 5,
        slow_min_span_secs: 3600,
        slow_min_sessions: 2,
        slow_rearm_subjects: 2,
        seq_run_len: 5,
        bulk_min_rows: 1_000,
        bulk_min_queries: 3,
        bulk_rearm_rows: 100,
        denied_min_resources: 3,
        denied_rearm_resources: 1,
        xdomain_min_domains: 2,
        ..Default::default()
    }
}

fn base_ts() -> chrono::DateTime<chrono::Utc> {
    // A fixed instant so all event times are deterministic.
    chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

/// Build a sensitive audit access `secs` after the base instant, with a stable
/// `event_id` (evidence). `extra` sets any additional canonical fields.
fn ev(id: &str, secs: i64, extra: &[(&str, &str)]) -> Event {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    fields.insert("event_id".into(), id.into());
    fields.insert(keys::ACTOR.into(), "anna".into());
    fields.insert(keys::OBJECT_TYPE.into(), "persons".into());
    fields.insert(keys::OBJECT_NAME.into(), "curated.persons".into());
    fields.insert(keys::SENSITIVE_RESOURCE.into(), "true".into());
    fields.insert(keys::OUTCOME.into(), "success".into());
    for (k, v) in extra {
        fields.insert((*k).into(), (*v).into());
    }
    Event {
        ts: base_ts() + chrono::Duration::seconds(secs),
        host: "db01".into(),
        service: "postgres".into(),
        source: "pgaudit".into(),
        environment: "prod".into(),
        severity: "info".into(),
        log_type: "audit".into(),
        message: "SELECT ...".into(),
        fields,
    }
}

fn rec_of(e: &Event) -> AuditRecord {
    AuditRecord::from_event(e)
}

/// Feed a successful (non-forbidden, non-failed) sensitive read.
fn feed(d: &mut StatefulDetectors, e: &Event) -> Vec<SecurityFinding> {
    let r = rec_of(e);
    d.observe(e, &r, false, false)
}

fn ids(fs: &[SecurityFinding]) -> Vec<String> {
    fs.iter().map(|f| f.detector.clone()).collect()
}

fn fired(d: &mut StatefulDetectors, events: &[Event]) -> Vec<String> {
    let mut out = Vec::new();
    for e in events {
        out.extend(ids(&feed(d, e)));
    }
    out
}

// ---- low-and-slow enumeration --------------------------------------------

#[test]
fn low_and_slow_fires_across_sessions_and_span() {
    let mut d = StatefulDetectors::new(cfg());
    // 5 distinct subjects, across 2 sessions, spanning > 1h.
    let events: Vec<Event> = (0..5)
        .map(|i| {
            ev(
                &format!("e{i}"),
                i * 1200, // 20-min steps → last at 80min > 1h span
                &[
                    (keys::SUBJECT, &format!("person-{}", 100 + i)),
                    (keys::SESSION_ID, if i % 2 == 0 { "s1" } else { "s2" }),
                ],
            )
        })
        .collect();
    let f = fired(&mut d, &events);
    assert!(
        f.contains(&"app-enumeration-low-and-slow".to_string()),
        "expected low-and-slow, got {f:?}"
    );
    // Fires exactly once for the episode (edge-triggered).
    assert_eq!(
        f.iter()
            .filter(|x| *x == "app-enumeration-low-and-slow")
            .count(),
        1
    );
}

#[test]
fn low_and_slow_needs_multiple_sessions() {
    let mut d = StatefulDetectors::new(cfg());
    // 6 distinct subjects, spanning > 1h, but all in ONE session → no fire.
    let events: Vec<Event> = (0..6)
        .map(|i| {
            ev(
                &format!("e{i}"),
                i * 1200,
                &[
                    (keys::SUBJECT, &format!("person-{i}")),
                    (keys::SESSION_ID, "s1"),
                ],
            )
        })
        .collect();
    assert!(!fired(&mut d, &events).contains(&"app-enumeration-low-and-slow".to_string()));
}

#[test]
fn low_and_slow_needs_span_not_a_burst() {
    let mut d = StatefulDetectors::new(cfg());
    // 6 distinct subjects, 2 sessions, but all within 10s → a burst, not slow.
    let events: Vec<Event> = (0..6)
        .map(|i| {
            ev(
                &format!("e{i}"),
                i, // 1s apart → span 5s << 1h
                &[
                    (keys::SUBJECT, &format!("person-{i}")),
                    (keys::SESSION_ID, if i % 2 == 0 { "s1" } else { "s2" }),
                ],
            )
        })
        .collect();
    assert!(!fired(&mut d, &events).contains(&"app-enumeration-low-and-slow".to_string()));
}

#[test]
fn low_and_slow_finding_carries_contributing_evidence() {
    let mut d = StatefulDetectors::new(cfg());
    let events: Vec<Event> = (0..5)
        .map(|i| {
            ev(
                &format!("e{i}"),
                i * 1200,
                &[
                    (keys::SUBJECT, &format!("person-{i}")),
                    (keys::SESSION_ID, if i % 2 == 0 { "s1" } else { "s2" }),
                ],
            )
        })
        .collect();
    let mut finding = None;
    for e in &events {
        for f in feed(&mut d, e) {
            if f.detector == "app-enumeration-low-and-slow" {
                finding = Some(f);
            }
        }
    }
    let f = finding.expect("episode fired");
    assert_eq!(f.finding_id, "app-enumeration-low-and-slow:e4");
    let contributing = f.event.field("contributing").unwrap_or_default();
    assert!(
        contributing.contains("e0") && contributing.contains("e4"),
        "{contributing}"
    );
    assert_eq!(f.event.field("distinct_subjects"), Some("5"));
    assert!(f.event.field("span_hours").is_some());
}

// ---- sequential enumeration ----------------------------------------------

#[test]
fn sequential_run_fires_and_reports_direction() {
    let mut d = StatefulDetectors::new(cfg());
    // Ids 1000..1005 (a length-6 ascending run ≥ seq_run_len=5).
    let events: Vec<Event> = (0..6)
        .map(|i| {
            ev(
                &format!("e{i}"),
                i,
                &[(keys::SUBJECT, &format!("acct-{}", 1000 + i))],
            )
        })
        .collect();
    let mut f = None;
    for e in &events {
        for x in feed(&mut d, e) {
            if x.detector == "app-enumeration-sequential" {
                f = Some(x);
            }
        }
    }
    let f = f.expect("sequential fired");
    assert_eq!(f.event.field("direction"), Some("ascending"));
    assert_eq!(f.event.field("first_evidence"), Some("e0"));
    assert!(f.event.field("run_length").unwrap().parse::<u32>().unwrap() >= 5);
}

#[test]
fn sequential_ignores_non_adjacent_ids() {
    let mut d = StatefulDetectors::new(cfg());
    let events: Vec<Event> = [10, 55, 3, 900, 41, 7]
        .iter()
        .enumerate()
        .map(|(i, id)| {
            ev(
                &format!("e{i}"),
                i as i64,
                &[(keys::SUBJECT, &format!("acct-{id}"))],
            )
        })
        .collect();
    assert!(!fired(&mut d, &events).contains(&"app-enumeration-sequential".to_string()));
}

#[test]
fn sequential_run_break_resets() {
    let mut d = StatefulDetectors::new(cfg());
    // 1000..1003 (run 4, below 5), then a break, then 1..4 (run 4) — never reaches 5.
    let mut events: Vec<Event> = (0..4)
        .map(|i| {
            ev(
                &format!("a{i}"),
                i,
                &[(keys::SUBJECT, &format!("acct-{}", 1000 + i))],
            )
        })
        .collect();
    events.extend((0..4).map(|i| {
        ev(
            &format!("b{i}"),
            10 + i,
            &[(keys::SUBJECT, &format!("acct-{}", 1 + i))],
        )
    }));
    assert!(!fired(&mut d, &events).contains(&"app-enumeration-sequential".to_string()));
}

// ---- split-bulk extraction -----------------------------------------------

#[test]
fn split_bulk_fires_from_many_small_reads() {
    let mut d = StatefulDetectors::new(cfg());
    // 4 reads of 400 rows each = 1600 ≥ 1000, over ≥ 3 queries, none itself bulk.
    let events: Vec<Event> = (0..4)
        .map(|i| ev(&format!("e{i}"), i * 10, &[(keys::ROWS_READ, "400")]))
        .collect();
    assert!(fired(&mut d, &events).contains(&"app-split-bulk-extraction".to_string()));
}

#[test]
fn split_bulk_ignores_a_single_flagged_bulk_read() {
    let mut d = StatefulDetectors::new(cfg());
    // One read of 100000 rows, but explicitly bulk_operation → the stateless
    // detector's job, not this one. Never contributes to the split-bulk window.
    let e = ev(
        "e0",
        0,
        &[(keys::ROWS_READ, "100000"), (keys::BULK_OPERATION, "true")],
    );
    assert!(!ids(&feed(&mut d, &e)).contains(&"app-split-bulk-extraction".to_string()));
}

// ---- repeated denied probing ---------------------------------------------

#[test]
fn denied_probing_fires_on_distinct_resources() {
    let mut d = StatefulDetectors::new(cfg());
    // 3 distinct denied resources → probing.
    let mut out = Vec::new();
    for i in 0..3 {
        let e = ev(
            &format!("e{i}"),
            i,
            &[
                (keys::OBJECT_NAME, &format!("raw.table_{i}")),
                (keys::OUTCOME, "denied"),
            ],
        );
        let r = rec_of(&e);
        out.extend(ids(&d.observe(&e, &r, false, true))); // failed = true
    }
    assert!(out.contains(&"app-denied-probing".to_string()), "{out:?}");
}

#[test]
fn denied_probing_needs_distinct_resources_not_repeats() {
    let mut d = StatefulDetectors::new(cfg());
    // 5 denials of the SAME resource → only one distinct → no probing.
    let mut out = Vec::new();
    for i in 0..5 {
        let e = ev(
            &format!("e{i}"),
            i,
            &[(keys::OBJECT_NAME, "raw.same"), (keys::OUTCOME, "denied")],
        );
        let r = rec_of(&e);
        out.extend(ids(&d.observe(&e, &r, false, true)));
    }
    assert!(!out.contains(&"app-denied-probing".to_string()));
}

// ---- cross-domain access -------------------------------------------------

#[test]
fn cross_domain_fires_on_novel_combo_once() {
    let mut d = StatefulDetectors::new(cfg());
    let a = ev(
        "e0",
        0,
        &[
            (keys::SESSION_ID, "s1"),
            (keys::DATABASE_SCHEMA, "identity"),
        ],
    );
    let b = ev(
        "e1",
        1,
        &[(keys::SESSION_ID, "s1"), (keys::DATABASE_SCHEMA, "health")],
    );
    let first = fired(&mut d, &[a, b]);
    assert!(first.contains(&"app-cross-domain-access".to_string()));

    // Same combo in a NEW session → already seen → no re-fire.
    let a2 = ev(
        "e2",
        100,
        &[
            (keys::SESSION_ID, "s2"),
            (keys::DATABASE_SCHEMA, "identity"),
        ],
    );
    let b2 = ev(
        "e3",
        101,
        &[(keys::SESSION_ID, "s2"), (keys::DATABASE_SCHEMA, "health")],
    );
    assert!(!fired(&mut d, &[a2, b2]).contains(&"app-cross-domain-access".to_string()));

    // A NOVEL combo (identity + finance) fires again.
    let a3 = ev(
        "e4",
        200,
        &[
            (keys::SESSION_ID, "s3"),
            (keys::DATABASE_SCHEMA, "identity"),
        ],
    );
    let b3 = ev(
        "e5",
        201,
        &[(keys::SESSION_ID, "s3"), (keys::DATABASE_SCHEMA, "finance")],
    );
    assert!(fired(&mut d, &[a3, b3]).contains(&"app-cross-domain-access".to_string()));
}

// ---- mandatory security invariants ---------------------------------------

#[test]
fn forbidden_and_failed_are_never_counted_as_sensitive_reads() {
    let mut d = StatefulDetectors::new(cfg());
    // Feed 10 distinct sensitive subjects across 2 sessions over > 1h, but every
    // access is FORBIDDEN (policy Deny). Enumeration must NOT fire — a forbidden
    // action is never folded into a "normal" volume. (Probing is a different plane
    // and needs distinct resources; here object_name is constant.)
    let mut out = Vec::new();
    for i in 0..10 {
        let e = ev(
            &format!("e{i}"),
            i * 1200,
            &[
                (keys::SUBJECT, &format!("person-{i}")),
                (keys::SESSION_ID, if i % 2 == 0 { "s1" } else { "s2" }),
            ],
        );
        let r = rec_of(&e);
        out.extend(ids(&d.observe(&e, &r, true, false))); // forbidden = true
    }
    assert!(
        !out.contains(&"app-enumeration-low-and-slow".to_string()),
        "forbidden accesses must not accumulate into an enumeration episode"
    );
}

#[test]
fn sensitive_gate_blocks_unclassified_enumeration() {
    let mut d = StatefulDetectors::new(cfg()); // require_sensitive = true (default)
                                               // 6 distinct subjects, 2 sessions, > 1h span, but NOT sensitive → no fire.
    let events: Vec<Event> = (0..6)
        .map(|i| {
            let mut e = ev(
                &format!("e{i}"),
                i * 1200,
                &[
                    (keys::SUBJECT, &format!("person-{i}")),
                    (keys::SESSION_ID, if i % 2 == 0 { "s1" } else { "s2" }),
                ],
            );
            e.fields.remove(keys::SENSITIVE_RESOURCE); // strip the classification
            e
        })
        .collect();
    assert!(!fired(&mut d, &events).contains(&"app-enumeration-low-and-slow".to_string()));
}

#[test]
fn require_sensitive_false_allows_enumeration_without_a_catalog() {
    let mut d = StatefulDetectors::new(StatefulConfig {
        require_sensitive: false,
        ..cfg()
    });
    let events: Vec<Event> = (0..5)
        .map(|i| {
            let mut e = ev(
                &format!("e{i}"),
                i * 1200,
                &[
                    (keys::SUBJECT, &format!("person-{i}")),
                    (keys::SESSION_ID, if i % 2 == 0 { "s1" } else { "s2" }),
                ],
            );
            e.fields.remove(keys::SENSITIVE_RESOURCE);
            e
        })
        .collect();
    assert!(fired(&mut d, &events).contains(&"app-enumeration-low-and-slow".to_string()));
}

#[test]
fn state_survives_a_serialization_roundtrip() {
    // Build up a partial run (4 of 5 ids), snapshot, reload with the SAME config,
    // and the 5th id completes the episode — proving an in-progress episode
    // survives a restart.
    let mut d = StatefulDetectors::new(cfg());
    for i in 0..4 {
        let e = ev(
            &format!("e{i}"),
            i,
            &[(keys::SUBJECT, &format!("acct-{}", 1000 + i))],
        );
        assert!(!ids(&feed(&mut d, &e)).contains(&"app-enumeration-sequential".to_string()));
    }
    let bytes = serde_json::to_vec(d.state()).unwrap();
    let state: StatefulState = serde_json::from_slice(&bytes).unwrap();
    let mut d2 = StatefulDetectors::from_state(cfg(), state);

    let e = ev("e4", 4, &[(keys::SUBJECT, "acct-1004")]);
    assert!(
        ids(&feed(&mut d2, &e)).contains(&"app-enumeration-sequential".to_string()),
        "the episode must complete after a reload"
    );
}

#[test]
fn late_event_does_not_rewind_the_window_or_panic() {
    let mut d = StatefulDetectors::new(cfg());
    // Advance the watermark far, then feed a very-late (old-ts) event.
    let recent = ev(
        "e0",
        10_000_000,
        &[(keys::SUBJECT, "person-1"), (keys::SESSION_ID, "s1")],
    );
    feed(&mut d, &recent);
    let late = ev(
        "e1",
        0,
        &[(keys::SUBJECT, "person-2"), (keys::SESSION_ID, "s2")],
    );
    // Must not panic; the late event is simply outside the (watermark-anchored)
    // window and does not resurrect an episode.
    let _ = feed(&mut d, &late);
    assert_eq!(d.tracked_actors(), 1);
}

#[test]
fn actor_map_stays_bounded_under_the_cap() {
    let mut d = StatefulDetectors::new(StatefulConfig {
        max_actors: 2,
        ..cfg()
    });
    for a in ["u1", "u2", "u3", "u4"] {
        let mut e = ev("x", 0, &[(keys::SUBJECT, "person-1")]);
        e.fields.insert(keys::ACTOR.into(), a.into());
        let r = rec_of(&e);
        d.observe(&e, &r, false, false);
    }
    assert!(d.tracked_actors() <= 2, "actor map exceeded the hard cap");
}

#[test]
fn future_event_cannot_poison_global_pruning_watermark() {
    let mut d = StatefulDetectors::new(cfg());
    let received_at_us = base_ts().timestamp_micros();

    // Start an in-progress sequential episode for the victim.
    for i in 0..4 {
        let mut e = ev(
            &format!("victim-{i}"),
            i,
            &[(keys::SUBJECT, &format!("acct-{}", 1000 + i))],
        );
        e.fields.insert(keys::ACTOR.into(), "victim".into());
        let r = rec_of(&e);
        d.observe_at(&e, &r, false, false, received_at_us);
    }

    // A sender-supplied timestamp ten years ahead must not advance the global
    // watermark used to evict every actor.
    let mut poison = ev("poison", 10 * 365 * 24 * 3600, &[(keys::SUBJECT, "acct-1")]);
    poison.fields.insert(keys::ACTOR.into(), "attacker".into());
    let r = rec_of(&poison);
    d.observe_at(&poison, &r, false, false, received_at_us);
    assert_eq!(d.state.global_watermark_us, received_at_us);

    // States poisoned by an older version are repaired after deserialization.
    d.state.global_watermark_us = poison.ts.timestamp_micros();
    let bytes = serde_json::to_vec(d.state()).unwrap();
    let state = serde_json::from_slice(&bytes).unwrap();
    d = StatefulDetectors::from_state(cfg(), state);

    // Reach the periodic pruning boundary with ordinary actors.
    for i in 0..4091 {
        let mut e = ev("filler", 0, &[(keys::SUBJECT, "acct-50")]);
        e.fields.insert(keys::ACTOR.into(), format!("filler-{i}"));
        let r = rec_of(&e);
        d.observe_at(&e, &r, false, false, received_at_us);
        assert_eq!(d.state.global_watermark_us, received_at_us);
    }

    let mut final_event = ev("victim-4", 4, &[(keys::SUBJECT, "acct-1004")]);
    final_event
        .fields
        .insert(keys::ACTOR.into(), "victim".into());
    let r = rec_of(&final_event);
    assert!(
        ids(&d.observe_at(&final_event, &r, false, false, received_at_us))
            .contains(&"app-enumeration-sequential".to_string())
    );
}

#[test]
fn no_actor_id_is_a_no_op() {
    let mut d = StatefulDetectors::new(cfg());
    let mut e = ev("e0", 0, &[(keys::SUBJECT, "person-1")]);
    e.fields.remove(keys::ACTOR);
    let r = rec_of(&e);
    assert!(d.observe(&e, &r, false, false).is_empty());
    assert_eq!(d.tracked_actors(), 0);
}

#[test]
fn stateful_ids_are_standalone_not_policy() {
    for id in STATEFUL_DETECTORS {
        assert!(crate::is_standalone(id), "{id} must be standalone");
        assert!(
            !crate::is_deterministic_policy(id),
            "{id} must not be a policy finding"
        );
    }
}