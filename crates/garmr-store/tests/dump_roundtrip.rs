// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The properties an online backup lives or dies by.

use garmr_store::state::{dump::SHAPES, StateStore, ALL_TABLES};

fn tmp(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("garmr-dump-{tag}-{n}.redb"))
}

#[test]
fn the_shape_table_covers_exactly_the_registered_schema() {
    // The chain that keeps a backup honest: source -> ALL_TABLES (guarded in
    // its own test) -> SHAPES (guarded here). A table missing from SHAPES is a
    // table missing from every dump.
    let mut shaped: Vec<&str> = SHAPES.iter().map(|(n, _)| *n).collect();
    shaped.sort_unstable();
    let mut registered: Vec<&str> = ALL_TABLES.to_vec();
    registered.sort_unstable();
    assert_eq!(
        shaped, registered,
        "SHAPES and ALL_TABLES disagree — a dump would skip or invent a table"
    );
}

#[test]
fn a_dump_round_trips_every_value_shape() {
    // Bytes, u64 and i64 tables all have to survive: a scalar restored as bytes
    // (or truncated) is silent corruption that only shows when something reads it.
    let (src, dst) = (tmp("src"), tmp("dst"));
    let a = StateStore::open(&src).unwrap();
    a.set_cold_watermark_us(1_755_000_000_000_000).unwrap(); // i64 table
    a.put_cold_archive(&garmr_core::ColdArchive {
        id: "w1".into(),
        kind: "znippy".into(),
        file: "w1.znippy".into(),
        start_us: 1,
        end_us: 2,
        rows: 5,
        bytes_in: 100,
        bytes_out: 20,
        checksum: "abc".into(),
        hot_pruned: false,
        sealed_at: chrono::Utc::now(),
        legal_hold: true,
    })
    .unwrap(); // bytes table

    let mut buf = Vec::new();
    let stats = a.dump_to(&mut buf).unwrap();
    assert_eq!(stats.tables, SHAPES.len());
    assert!(stats.rows >= 2, "seeded rows must be captured: {stats:?}");

    let b = StateStore::open(&dst).unwrap();
    b.restore_dump(&mut std::io::Cursor::new(&buf)).unwrap();

    assert_eq!(
        b.cold_watermark_us().unwrap(),
        Some(1_755_000_000_000_000),
        "the i64 scalar must survive exactly"
    );
    let arcs = b.list_cold_archives().unwrap();
    assert_eq!(arcs.len(), 1);
    assert_eq!(arcs[0].id, "w1");
    assert!(arcs[0].legal_hold, "a legal hold must survive a restore");

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn a_dump_is_a_snapshot_writes_during_it_do_not_leak_in() {
    // THE property. The dump reads inside one transaction, so a row committed
    // after it starts must not appear. If it could, the image would be a mix of
    // two instants — internally inconsistent in exactly the way that makes a
    // restore produce a store that never existed.
    let (src, dst) = (tmp("snap-src"), tmp("snap-dst"));
    let a = StateStore::open(&src).unwrap();
    let arc = |id: &str| garmr_core::ColdArchive {
        id: id.into(),
        kind: "znippy".into(),
        file: format!("{id}.znippy"),
        start_us: 1,
        end_us: 2,
        rows: 1,
        bytes_in: 1,
        bytes_out: 1,
        checksum: "x".into(),
        hot_pruned: false,
        sealed_at: chrono::Utc::now(),
        legal_hold: false,
    };
    a.put_cold_archive(&arc("before")).unwrap();

    // Take the dump, then write MORE while the bytes are still in hand. The
    // read transaction opened inside dump_to has already fixed the view.
    let mut buf = Vec::new();
    a.dump_to(&mut buf).unwrap();
    a.put_cold_archive(&arc("after")).unwrap();

    let b = StateStore::open(&dst).unwrap();
    b.restore_dump(&mut std::io::Cursor::new(&buf)).unwrap();
    let ids: Vec<String> = b
        .list_cold_archives()
        .unwrap()
        .into_iter()
        .map(|x| x.id)
        .collect();
    assert_eq!(ids, vec!["before".to_string()], "the dump is one instant");
    // And the live store still has both — the dump changed nothing.
    assert_eq!(a.list_cold_archives().unwrap().len(), 2);

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

#[test]
fn a_truncated_or_foreign_dump_is_refused() {
    let dst = tmp("bad");
    let b = StateStore::open(&dst).unwrap();
    // Not a dump at all.
    assert!(b
        .restore_dump(&mut std::io::Cursor::new(b"hello world!!!!!"))
        .is_err());
    // Right magic, wrong version: refuse rather than read with the wrong rules,
    // which would restore plausible-looking garbage.
    let mut wrong = b"GARMRDMP".to_vec();
    wrong.extend_from_slice(&99u32.to_le_bytes());
    wrong.extend_from_slice(&0u32.to_le_bytes());
    let err = b
        .restore_dump(&mut std::io::Cursor::new(&wrong))
        .unwrap_err()
        .to_string();
    assert!(err.contains("version"), "{err}");
    std::fs::remove_file(&dst).ok();
}
