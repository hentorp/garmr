// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Guards `garmr_store::state::ALL_TABLES` against drift.
//!
//! A whole-store operation (logical backup, migration, integrity sweep) needs to
//! enumerate the schema. If the registry can fall behind the actual table
//! definitions, a table added later is silently omitted from every backup taken
//! afterwards — and that omission surfaces only when someone restores, which is
//! the worst possible moment to learn about it.
//!
//! So the source is the authority: this reads the declarations directly and
//! fails if the registry does not match them exactly.

#[test]
fn table_registry_is_complete() {
    const MARKER: &str = "TableDefinition::new(\"";
    let src = include_str!("../src/state/mod.rs");
    let mut declared: Vec<&str> = src
        .match_indices(MARKER)
        .filter_map(|(i, _)| {
            let rest = &src[i + MARKER.len()..];
            rest.find('"').map(|end| &rest[..end])
        })
        .collect();
    declared.sort_unstable();
    declared.dedup();
    assert!(!declared.is_empty(), "found no table declarations to check");

    let registered: Vec<&str> = garmr_store::state::ALL_TABLES.to_vec();

    let missing: Vec<_> = declared
        .iter()
        .filter(|d| !registered.contains(d))
        .collect();
    let extra: Vec<_> = registered
        .iter()
        .filter(|r| !declared.contains(r))
        .collect();

    assert!(
        missing.is_empty(),
        "table(s) declared but NOT in ALL_TABLES: {missing:?} — a whole-store backup \
         would silently omit them, and the loss would surface only on restore"
    );
    assert!(
        extra.is_empty(),
        "ALL_TABLES names table(s) that no longer exist: {extra:?} — a restore would \
         look for data that was never written"
    );
}
