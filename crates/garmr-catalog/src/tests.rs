// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use chrono::TimeZone;
use garmr_core::{AuditAction, AuditRecord};

/// `object_pattern_matches` must be exactly case-insensitive across all three
/// pattern kinds (exact, `schema.*` wildcard, unqualified last-segment) — the
/// behaviour the old two-`to_ascii_lowercase` body gave, now allocation-free.
#[test]
fn object_pattern_matches_is_case_insensitive_all_kinds() {
    // Exact (case-insensitive both ways).
    assert!(object_pattern_matches("Public.Persons", "public.persons"));
    assert!(object_pattern_matches("public.persons", "PUBLIC.PERSONS"));
    assert!(!object_pattern_matches("public.persons", "public.personx"));

    // Schema wildcard: bare schema + any object under it, mixed case.
    assert!(object_pattern_matches("RAW.*", "raw"));
    assert!(object_pattern_matches("raw.*", "RAW.raw_persons"));
    assert!(object_pattern_matches("raw.*", "raw.addresses"));
    assert!(!object_pattern_matches("raw.*", "curated.persons"));
    // A prefix that is a substring but not a segment boundary must NOT match.
    assert!(!object_pattern_matches("raw.*", "rawer.x"));

    // Unqualified: matches the last dotted segment, case-insensitively.
    assert!(object_pattern_matches("Persons", "public.persons"));
    assert!(object_pattern_matches("persons", "PERSONS"));
    assert!(!object_pattern_matches("persons", "public.personseditor"));
}

/// A catalog entry wrapping `resource` at the given approval state.
fn entry(id: &str, resource: Resource, approval: ApprovalState) -> CatalogEntry {
    CatalogEntry {
        id: id.into(),
        resource,
        approval,
        version: 1,
        valid_from: None,
        valid_until: None,
        created_by: "alice".into(),
        approved_by: if approval == ApprovalState::Trusted {
            Some("alice".into())
        } else {
            None
        },
        audit_refs: vec![],
        source: CatalogSource::Manual,
    }
}

/// The prebuilt `ObjectIndex` must resolve every name byte-identically to the
/// linear `Catalog::resolve_object_at` — across all three pattern kinds (exact,
/// `schema.*`, unqualified), overlapping matches (first-Some order preserved),
/// validity windows, and misses. Red the instant the index misroutes, drops a
/// candidate, or breaks the entries-order fold.
#[test]
fn object_index_matches_linear_resolve() {
    use chrono::TimeZone;
    let t0 = Utc.timestamp_opt(1_000_000, 0).unwrap();
    let expired = entry(
        "expired",
        sensitive_persons("curated.persons", DataClassification::Secret),
        ApprovalState::Trusted,
    );
    let mut expired = expired;
    expired.valid_until = Some(t0); // effective only before t0
    let cat = Catalog::new(vec![
        entry(
            "s1",
            sensitive_persons("curated.persons", DataClassification::Restricted),
            ApprovalState::Trusted,
        ),
        // unqualified pattern (no dot) — matches any `*.persons`
        entry(
            "t_unqual",
            Resource::Table(Table {
                name: "persons".into(),
                application: Some("app-u".into()),
                owner: None,
                classification: Some(DataClassification::Confidential),
                sensitive: false,
                expected_users: vec!["carol".into()],
                ..Default::default()
            }),
            ApprovalState::Trusted,
        ),
        // schema wildcard
        entry(
            "w1",
            sensitive_persons("raw.*", DataClassification::Confidential),
            ApprovalState::Trusted,
        ),
        // a Candidate (never effective) + a windowed entry
        entry(
            "cand",
            sensitive_persons("curated.persons", DataClassification::Secret),
            ApprovalState::Candidate,
        ),
        expired,
    ]);
    let index = cat.object_index();

    let now = Utc.timestamp_opt(2_000_000, 0).unwrap(); // after t0 → expired inactive
    let before = Utc.timestamp_opt(500_000, 0).unwrap(); // before t0 → expired active
    let names = [
        "curated.persons",      // exact + unqualified(persons) overlap
        "CURATED.PERSONS",      // case-insensitive
        "raw.addresses",        // wildcard
        "raw",                  // bare schema
        "public.persons",       // unqualified only
        "public.personseditor", // near-miss, no match
        "unrelated.table",      // miss
    ];
    for at in [None, Some(now), Some(before)] {
        for name in names {
            assert_eq!(
                index.resolve_object_at(&cat.entries, name, at),
                cat.resolve_object_at(name, at),
                "index vs linear mismatch for {name:?} at {at:?}",
            );
        }
    }
}

fn sensitive_persons(object: &str, class: DataClassification) -> Resource {
    Resource::SensitiveResource(SensitiveResource {
        object: object.into(),
        application: Some("registry".into()),
        owner: Some("team-registry".into()),
        classification: class,
        expected_users: vec!["anna".into(), "bruno".into()],
        data_subject_type: Some("person".into()),
    })
}

// -------------------------------------------------------------------------

#[test]
fn candidate_sensitive_resource_is_not_treated_as_sensitive() {
    // A Candidate marks curated.persons as Restricted+sensitive, but a Candidate
    // must NEVER be treated as Trusted for a security decision.
    let mut cat = Catalog::new(vec![entry(
        "sr:curated.persons",
        sensitive_persons("curated.persons", DataClassification::Restricted),
        ApprovalState::Candidate,
    )]);

    assert!(
        !cat.is_sensitive("curated.persons"),
        "a Candidate sensitive resource must not make is_sensitive true"
    );
    assert!(cat.resolve_object("curated.persons").is_none());
    assert_eq!(cat.classification_of("curated.persons"), None);
    // It is still VISIBLE for review.
    assert_eq!(cat.candidates().count(), 1);

    // Human promotion is the only path to Trusted → now it resolves.
    cat.entries[0].promote("alice");
    assert!(cat.is_sensitive("curated.persons"));
    assert_eq!(
        cat.classification_of("curated.persons").as_deref(),
        Some("restricted")
    );
}

#[test]
fn trusted_resolution_returns_full_facts() {
    let cat = Catalog::new(vec![entry(
        "sr:curated.persons",
        sensitive_persons("curated.persons", DataClassification::Confidential),
        ApprovalState::Trusted,
    )]);
    let r = cat.resolve_object("curated.persons").expect("resolves");
    assert_eq!(r.application.as_deref(), Some("registry"));
    assert_eq!(r.owner.as_deref(), Some("team-registry"));
    assert_eq!(r.classification, Some(DataClassification::Confidential));
    assert!(r.sensitive);
    assert_eq!(
        r.expected_users,
        vec!["anna".to_string(), "bruno".to_string()]
    );
}

#[test]
fn schema_wildcard_matching_resolves() {
    // A trusted `raw.*` sensitive resource covers every object in the schema.
    let cat = Catalog::new(vec![entry(
        "sr:raw.*",
        sensitive_persons("raw.*", DataClassification::Restricted),
        ApprovalState::Trusted,
    )]);
    assert!(cat.is_sensitive("raw.raw_persons"));
    assert!(cat.is_sensitive("raw.addresses"));
    assert!(cat.is_sensitive("raw")); // the bare schema too
    assert!(!cat.is_sensitive("curated.persons")); // other schema untouched
}

#[test]
fn unqualified_object_name_matches_qualified_pattern_segment() {
    // Consistent with garmr-policy: an unqualified stored name matches the last
    // dotted segment of the accessed object.
    let cat = Catalog::new(vec![entry(
        "tbl:persons",
        Resource::Table(Table {
            name: "persons".into(),
            sensitive: true,
            classification: Some(DataClassification::Confidential),
            ..Default::default()
        }),
        ApprovalState::Trusted,
    )]);
    assert!(cat.is_sensitive("public.persons"));
    assert!(!cat.is_sensitive("public.personseditor"));
}

#[test]
fn enrich_stamps_classification_and_sensitivity_onto_record() {
    let cat = Catalog::new(vec![entry(
        "tbl:raw.raw_persons",
        Resource::Table(Table {
            name: "raw.raw_persons".into(),
            application: Some("registry".into()),
            sensitive: true,
            classification: Some(DataClassification::Restricted),
            expected_users: vec!["anna".into()],
            ..Default::default()
        }),
        ApprovalState::Trusted,
    )]);

    let mut rec = AuditRecord {
        action: AuditAction {
            object_name: Some("raw.raw_persons".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    // Before: nothing stamped.
    assert!(rec.classification.data_classification.is_none());
    assert!(!rec.classification.sensitive_resource);

    let enr = cat.enrich(&rec);
    assert_eq!(enr.data_classification.as_deref(), Some("restricted"));
    assert!(enr.sensitive_resource);
    assert_eq!(enr.application.as_deref(), Some("registry"));

    cat.stamp(&mut rec);
    assert_eq!(
        rec.classification.data_classification.as_deref(),
        Some("restricted")
    );
    assert!(rec.classification.sensitive_resource);
}

#[test]
fn stamp_never_downgrades_an_already_sensitive_record() {
    // A catalog that resolves nothing must not clear an existing sensitive flag.
    let cat = Catalog::default();
    let mut rec = AuditRecord {
        action: AuditAction {
            object_name: Some("unknown.thing".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    rec.classification.sensitive_resource = true;
    cat.stamp(&mut rec);
    assert!(
        rec.classification.sensitive_resource,
        "stamp must never clear an existing sensitive flag"
    );
}

#[test]
fn digest_is_stable_and_order_independent() {
    let a = entry(
        "sr:a",
        sensitive_persons("raw.a", DataClassification::Restricted),
        ApprovalState::Trusted,
    );
    let b = entry(
        "sr:z",
        sensitive_persons("raw.z", DataClassification::Confidential),
        ApprovalState::Trusted,
    );
    let d1 = Catalog::new(vec![a.clone(), b.clone()]).digest();
    let d2 = Catalog::new(vec![b, a]).digest();
    assert_eq!(d1, d2, "digest must not depend on entry ordering");
    assert!(d1.starts_with("cat1:"));
}

#[test]
fn toml_import_yields_candidates_not_trusted() {
    let text = r#"
created_by = "alice"

[[application]]
name = "registry"
owner = "team-registry"
business_purpose = "Population register"

[[table]]
name = "raw.raw_persons"
application = "registry"
classification = "restricted"
sensitive = true
expected_users = ["anna", "bruno"]

[[sensitive_resource]]
object = "curated.persons"
application = "registry"
classification = "confidential"
expected_users = ["anna"]

[[user_role]]
name = "registry-readers"
application = "registry"
members = ["anna", "bruno", "carol"]
"#;
    let cat = Catalog::from_toml(text).expect("valid TOML");
    assert_eq!(cat.entries.len(), 4);
    // Everything imported is a Candidate from FileImport — confers nothing yet.
    assert!(cat
        .entries
        .iter()
        .all(|e| e.approval == ApprovalState::Candidate));
    assert!(cat
        .entries
        .iter()
        .all(|e| e.source == CatalogSource::FileImport));
    assert!(cat.entries.iter().all(|e| e.created_by == "alice"));
    assert!(
        !cat.is_sensitive("raw.raw_persons"),
        "imported facts must not resolve until promoted"
    );

    // Promote everything → now it resolves.
    let mut cat = cat;
    for e in &mut cat.entries {
        e.promote("alice");
    }
    assert!(cat.is_sensitive("raw.raw_persons"));
    assert_eq!(
        cat.classification_of("curated.persons").as_deref(),
        Some("confidential")
    );
    assert_eq!(
        cat.expected_users_of("registry"),
        vec!["anna".to_string(), "bruno".to_string(), "carol".to_string()]
    );
}

#[test]
fn retired_entry_is_inactive() {
    let mut cat = Catalog::new(vec![entry(
        "sr:curated.persons",
        sensitive_persons("curated.persons", DataClassification::Restricted),
        ApprovalState::Trusted,
    )]);
    assert!(cat.is_sensitive("curated.persons"));

    cat.entries[0].retire();
    assert_eq!(cat.entries[0].approval, ApprovalState::Retired);
    assert!(
        !cat.is_sensitive("curated.persons"),
        "a retired entry must stop resolving"
    );
    assert!(cat.resolve_object("curated.persons").is_none());
}

#[test]
fn validity_window_is_enforced_by_resolve_object_at() {
    let mut e = entry(
        "sr:curated.persons",
        sensitive_persons("curated.persons", DataClassification::Restricted),
        ApprovalState::Trusted,
    );
    e.valid_from = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    e.valid_until = Some(Utc.with_ymd_and_hms(2026, 12, 31, 0, 0, 0).unwrap());
    let cat = Catalog::new(vec![e]);

    let inside = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let before = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
    assert!(cat
        .resolve_object_at("curated.persons", Some(inside))
        .is_some());
    assert!(cat
        .resolve_object_at("curated.persons", Some(before))
        .is_none());
    // Time-agnostic resolution ignores the window (approval gate still applies).
    assert!(cat.resolve_object("curated.persons").is_some());
}

#[test]
fn highest_classification_wins_when_entries_overlap() {
    // Two trusted entries match the same object with different classifications;
    // the higher rank must win and sensitivity is monotonic.
    let cat = Catalog::new(vec![
        entry(
            "sr:raw.*",
            sensitive_persons("raw.*", DataClassification::Confidential),
            ApprovalState::Trusted,
        ),
        entry(
            "tbl:raw.raw_persons",
            Resource::Table(Table {
                name: "raw.raw_persons".into(),
                sensitive: true,
                classification: Some(DataClassification::Secret),
                ..Default::default()
            }),
            ApprovalState::Trusted,
        ),
    ]);
    let r = cat.resolve_object("raw.raw_persons").expect("resolves");
    assert_eq!(r.classification, Some(DataClassification::Secret));
    assert!(r.sensitive);
}

#[test]
fn object_pattern_matching_rules() {
    assert!(object_pattern_matches("raw.*", "raw.persons"));
    assert!(object_pattern_matches("raw.*", "raw"));
    assert!(!object_pattern_matches("raw.*", "curated.persons"));
    assert!(object_pattern_matches("persons", "public.persons"));
    assert!(object_pattern_matches("public.persons", "PUBLIC.PERSONS"));
    assert!(!object_pattern_matches("persons", "personseditor"));
}
