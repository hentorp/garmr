//! Crash-recovery: a torn commit (unclean shutdown) leaves the durable catalog
//! pointer aimed at a zero-byte metadata file; `Warehouse::heal_table` must roll
//! it back to the last intact snapshot so the table opens again.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use skade::HealOutcome;
use skade::arrow_array::{Int64Array, RecordBatch};
use skade::arrow_schema::{DataType, Field, Schema};

fn schema() -> Schema {
    Schema::new(vec![Field::new("id", DataType::Int64, false)])
}

fn batch(ids: Vec<i64>) -> Result<RecordBatch> {
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![Arc::new(Int64Array::from(ids))],
    )?)
}

/// Every `*.metadata.json` under `root`, newest last (lexicographic == version
/// order for iceberg's zero-padded `NNNNN-…` names).
fn metadata_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.to_string_lossy().ends_with(".metadata.json") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Every `*.avro` MANIFEST (the `<uuid>-m0.avro` files, NOT the `snap-*.avro`
/// manifest LISTS) under `root`, oldest-first by modification time — so the last
/// is the manifest written by the most recent append (the current snapshot's).
#[cfg(feature = "sql")]
fn manifest_files(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name.ends_with(".avro") && !name.starts_with("snap-") {
                let mtime = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                out.push((mtime, p));
            }
        }
    }
    out.sort();
    out.into_iter().map(|(_, p)| p).collect()
}

#[cfg(feature = "sql")]
#[tokio::test]
async fn heals_torn_commit_by_rolling_pointer_back() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let lake = tmp.path().join("lake");

    // Two appends → two snapshots; pointer at the second (20 rows total).
    {
        let wh = skade::open(&lake).await?;
        let mut events = wh.create_table("events", &schema()).await?;
        events.append(&[batch((1..=10).collect())?]).await?;
        events.append(&[batch((11..=20).collect())?]).await?;
        assert_eq!(events.count().await?, 20);
    } // drop → release the redb file lock so we can reopen a fresh process view

    // Simulate the torn commit: truncate the current (highest-numbered) metadata
    // file to zero bytes — exactly what an unclean shutdown leaves behind.
    let files = metadata_files(&lake);
    let current = files.last().expect("at least one metadata file").clone();
    std::fs::write(&current, b"")?;
    assert_eq!(std::fs::metadata(&current)?.len(), 0);

    // Fresh open: the pointer mirror is rebuilt from the durable TABLES entry,
    // which names the now-zero-byte file. Without healing, opening the table
    // would fail with an EOF parse error.
    let wh = skade::open(&lake).await?;
    let outcome = wh.heal_table("events").await?;
    match &outcome {
        HealOutcome::Healed { from, to } => {
            assert!(from.ends_with(&*current.file_name().unwrap().to_string_lossy()));
            assert_ne!(from, to);
        }
        other => panic!("expected Healed, got {other:?}"),
    }

    // The table opens again and reflects the last intact snapshot (the torn
    // second commit is gone → 10 rows, not 20).
    let events = wh.table("events").await?;
    assert_eq!(events.count().await?, 10);

    // Idempotent: a second heal on the now-healthy table is a no-op.
    assert_eq!(wh.heal_table("events").await?, HealOutcome::Healthy);
    // Unknown table → nothing to heal.
    assert_eq!(wh.heal_table("does_not_exist").await?, HealOutcome::Unknown);
    Ok(())
}

#[cfg(feature = "sql")]
#[tokio::test]
async fn heals_torn_manifest_by_rolling_pointer_back() -> Result<()> {
    // Regression for the 2026-07 storage incident: a SIGTERM mid-compaction left a
    // zero-byte `<uuid>-m0.avro` MANIFEST that the current snapshot's (intact,
    // parseable) manifest LIST still referenced. Validating only the list treats
    // that snapshot as healthy, yet every scan then dies loading the 0-byte
    // manifest — so heal must stat the manifests too and roll the pointer back
    // past the torn commit. (Before the fix, this returned Healthy and the table
    // stayed broken.)
    let tmp = tempfile::tempdir()?;
    let lake = tmp.path().join("lake");

    {
        let wh = skade::open(&lake).await?;
        let mut events = wh.create_table("events", &schema()).await?;
        events.append(&[batch((1..=10).collect())?]).await?; // snapshot 1 -> manifest A
        events.append(&[batch((11..=20).collect())?]).await?; // snapshot 2 -> manifest B
        assert_eq!(events.count().await?, 20);
    }

    // Truncate the CURRENT snapshot's manifest (newest `*-m0.avro`) to zero bytes,
    // leaving its manifest LIST fully intact — exactly the torn-compaction shape.
    let manifests = manifest_files(&lake);
    let torn = manifests.last().expect("at least one manifest").clone();
    std::fs::write(&torn, b"")?;
    assert_eq!(std::fs::metadata(&torn)?.len(), 0);

    // Fresh open: the durable pointer names metadata whose snapshot references the
    // 0-byte manifest. heal must detect it (not just the list) and roll back.
    let wh = skade::open(&lake).await?;
    match wh.heal_table("events").await? {
        HealOutcome::Healed { from, to } => assert_ne!(from, to),
        other => panic!("expected Healed (torn manifest), got {other:?}"),
    }

    // The table opens again at the last intact snapshot (torn second commit gone
    // → 10 rows), and a second heal is a no-op.
    let events = wh.table("events").await?;
    assert_eq!(events.count().await?, 10);
    assert_eq!(wh.heal_table("events").await?, HealOutcome::Healthy);
    Ok(())
}

#[cfg(feature = "sql")]
#[tokio::test]
async fn heal_refuses_to_empty_a_table_that_had_data() -> Result<()> {
    // Regression for the HIGH review finding: if the ONLY fallback below a torn
    // commit is the empty create-metadata (00000, no snapshot), heal must NOT
    // silently roll the table back to empty — that is data loss, not recovery.
    // It reports Unrecoverable (loud) so an operator can recover the real data.
    let tmp = tempfile::tempdir()?;
    let lake = tmp.path().join("lake");
    {
        let wh = skade::open(&lake).await?;
        let mut events = wh.create_table("events", &schema()).await?; // -> 00000 (empty)
        events.append(&[batch((1..=10).collect())?]).await?; // -> 00001 (data)
        assert_eq!(events.count().await?, 10);
    }
    // Tear the current (data) commit; the only remaining candidate is 00000.
    let current = metadata_files(&lake).last().expect("metadata").clone();
    std::fs::write(&current, b"")?;

    let wh = skade::open(&lake).await?;
    match wh.heal_table("events").await? {
        HealOutcome::Unrecoverable { .. } => {}
        other => panic!("expected Unrecoverable (must not empty the table), got {other:?}"),
    }
    Ok(())
}

#[cfg(feature = "sql")]
#[tokio::test]
async fn heal_is_healthy_noop_on_a_sound_store() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let lake = tmp.path().join("lake");
    let wh = skade::open(&lake).await?;
    let mut events = wh.create_table("events", &schema()).await?;
    events.append(&[batch((1..=5).collect())?]).await?;
    assert_eq!(wh.heal_table("events").await?, HealOutcome::Healthy);
    assert_eq!(events.count().await?, 5);
    Ok(())
}
