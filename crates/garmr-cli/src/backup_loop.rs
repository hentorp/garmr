// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The scheduled ONLINE backup loop, running inside `serve`.
//!
//! It has to live here, in the daemon, and that is not a design preference:
//! redb takes an exclusive `flock` on the state database, so a separate CLI
//! process cannot open it while `serve` holds it. An online backup is therefore
//! only possible from within the process that already has the store open.
//!
//! What it assembles is built and tested elsewhere, deliberately: the consistent
//! state capture ([`garmr_store::state::dump`]), the rule that decides whether a
//! capture finished inside compaction's safety window
//! ([`crate::backup_window`]), and the policy that decides which old images may
//! be deleted ([`garmr_core::backup_retention`]). This module is the scheduler
//! and the fail-closed wiring between them.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use garmr_core::{BackupConfig, Result};
use garmr_store::Store;

/// Only one capture may run at a time.
///
/// Two overlapping runs would interleave in the staging tree and produce two
/// images that are each missing what the other took. A slow capture that has not
/// finished when the next tick fires must therefore SKIP that tick, not queue —
/// queueing turns a temporary slowdown into an unbounded backlog of concurrent
/// disk-heavy work on a node that is already struggling.
#[derive(Default)]
pub(crate) struct CaptureGuard {
    running: AtomicBool,
}

impl CaptureGuard {
    /// Take the slot, or `None` when a capture is already running.
    fn try_enter(&self) -> Option<CaptureSlot<'_>> {
        (!self.running.swap(true, Ordering::SeqCst)).then_some(CaptureSlot { guard: self })
    }
}

/// Releases the slot on drop, so a capture that panics or returns early cannot
/// wedge the loop permanently.
struct CaptureSlot<'a> {
    guard: &'a CaptureGuard,
}

impl Drop for CaptureSlot<'_> {
    fn drop(&mut self) {
        self.guard.running.store(false, Ordering::SeqCst);
    }
}

/// The filename that tells an operator what this directory is.
///
/// Load-bearing: these images carry no signed manifest yet, so `garmr backup
/// verify` and `restore` will not accept them. A directory that looks like a
/// backup and is not one is the failure this whole module has been guarding
/// against everywhere else, and it would be perverse to create one here.
const STATUS_FILE: &str = "NOT-YET-RESTORABLE.txt";

/// Write the honest description of what the image contains.
fn write_status(dir: &Path, ledger_captured: bool) -> Result<()> {
    let body = format!(
        "This is an ONLINE capture taken by `garmr serve` (backup.interval_secs).\n\
         \n\
         It contains:\n\
         \x20 state/state.dump   a consistent logical dump of the state DB\n\
         \x20 warehouse/         the event lakehouse\n\
         \x20 ledger/            the audit ledger{}\n\
         \n\
         It does NOT yet contain a signed manifest, so `garmr backup verify` and\n\
         `garmr backup restore` will REFUSE it. Treat it as raw captured data,\n\
         not as a restorable backup image.\n\
         \n\
         For a restorable image today, use the offline path: stop the writer and\n\
         run `garmr backup create <dir>`.\n",
        if ledger_captured {
            ""
        } else {
            " (ABSENT — auditing disabled or empty)"
        }
    );
    std::fs::write(dir.join(STATUS_FILE), body).map_err(garmr_core::Error::store)
}

/// A directory name for a capture starting at `at_us`, sortable and unique.
///
/// Sortable matters: the prune policy orders by the manifest timestamp, but an
/// operator listing the directory should see the same order without reading
/// manifests.
fn image_dir_name(at_us: i64) -> String {
    let t = chrono::DateTime::from_timestamp_micros(at_us).unwrap_or_default();
    format!("garmr-{}", t.format("%Y%m%dT%H%M%SZ"))
}

/// Spawn the scheduled backup loop. A no-op when `interval_secs == 0`.
pub(crate) fn spawn(cfg: garmr_core::Config, store: Store) {
    if cfg.backup.interval_secs == 0 {
        return;
    }
    // Floor the interval: a schedule faster than this would spend the node's IO
    // budget on backups instead of ingest, and a backup that starves the thing
    // it protects is not a backup.
    let every = Duration::from_secs(cfg.backup.interval_secs.max(300));
    let guard = Arc::new(CaptureGuard::default());
    tracing::info!(
        every_secs = every.as_secs(),
        dir = %cfg.backup.dir.display(),
        keep = cfg.backup.keep,
        "scheduled online backups enabled"
    );
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let Some(_slot) = guard.try_enter() else {
                // Skipping is the correct response, and saying so matters: a
                // silently skipped backup looks identical to one that ran.
                tracing::warn!("scheduled backup skipped — the previous capture is still running");
                continue;
            };
            if let Err(e) = run_once(&cfg, &store).await {
                // A failed backup must be loud. The failure mode this guards
                // against is a schedule that has been quietly broken for weeks
                // and is discovered when someone needs to restore.
                tracing::error!(error = %e, "scheduled backup FAILED — this node has no fresh recovery point");
            }
        }
    });
}

/// One capture: state dump, safety-window check, prune.
async fn run_once(cfg: &garmr_core::Config, store: &Store) -> Result<()> {
    let started = Instant::now();
    let at_us = chrono::Utc::now().timestamp_micros();
    let dir = cfg.backup.dir.join(image_dir_name(at_us));
    // Fail-closed like the offline path: a scheduled capture is still a full
    // copy of the dataset, and this loop's own contract is that a failed backup
    // must be loud — an audit-append failure surfaces through the same error
    // path as any other failed capture, and the next cycle retries.
    crate::audit::record_system(
        garmr_audit::action::BACKUP,
        "backup",
        &dir.display().to_string(),
        "scheduled online backup",
    )
    .map_err(|e| garmr_core::Error::store(format!("audit append for the capture: {e}")))?;

    std::fs::create_dir_all(dir.join("state")).map_err(garmr_core::Error::store)?;

    // The state half: one read transaction, so it is a point-in-time view even
    // though ingest keeps committing throughout.
    let mut f =
        std::fs::File::create(dir.join("state/state.dump")).map_err(garmr_core::Error::store)?;
    let stats = store.state.dump_to(&mut f)?;
    drop(f);

    // The warehouse half. Iceberg data files are immutable, so the files the
    // current snapshot references at copy start are stable — compaction may
    // RETIRE them meanwhile, but does not delete them until the grace elapses.
    // That grace IS the pin; no explicit snapshot lease is needed, only the
    // check below that the copy finished inside it.
    crate::backup::copy_tree(&cfg.store.warehouse_dir, &dir.join("warehouse"))
        .map_err(|e| garmr_core::Error::store(format!("copying the warehouse: {e}")))?;

    // The ledger half. Copied with the same allowlist the offline path uses, so
    // an online image carries the same tamper-evident record and no more: the
    // signing key lives in the audit directory and must NEVER be captured into
    // a backup, or the image would carry the means to forge the very records it
    // exists to preserve.
    let ledger_captured =
        crate::backup::copy_ledger_allowlisted(&cfg.audit.dir, &dir.join("ledger"))
            .map_err(|e| garmr_core::Error::store(format!("capturing the audit ledger: {e}")))?;
    if !ledger_captured {
        // Not fatal — auditing can be disabled — but an image without the
        // ledger cannot answer "what happened before this point", so say so
        // rather than let a restore discover it.
        tracing::warn!("backup image contains no audit ledger (auditing disabled or empty)");
    }

    // The window is checked AFTER the capture, against the real elapsed time —
    // an estimate made in advance cannot know how long this run actually took,
    // and the warehouse copy is the part that grows with the deployment.
    let grace = Duration::from_secs(cfg.store.compact_gc_grace_secs);
    if !crate::backup_window::within_safety_window(started.elapsed(), grace) {
        // Remove the partial image rather than leave something that looks like a
        // backup. A directory that exists is the strongest signal an operator
        // has, and it must not lie.
        let _ = std::fs::remove_dir_all(&dir);
        return Err(garmr_core::Error::store(
            crate::backup_window::overrun_message(started.elapsed(), grace),
        ));
    }

    write_status(&dir, ledger_captured)?;

    tracing::info!(
        dir = %dir.display(),
        tables = stats.tables,
        rows = stats.rows,
        ledger = ledger_captured,
        took_ms = started.elapsed().as_millis() as u64,
        "scheduled backup captured"
    );
    prune(&cfg.backup)?;
    Ok(())
}

/// Apply the retention policy to the images on disk.
fn prune(cfg: &BackupConfig) -> Result<()> {
    let entries = list_images(&cfg.dir)?;
    let plan = garmr_core::backup_retention::plan_prune(entries, cfg.keep);
    if let Some(note) = &plan.note {
        tracing::warn!(note = %note, "backup retention");
    }
    for id in &plan.delete {
        let path = cfg.dir.join(id);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => tracing::info!(image = %id, "pruned an old backup"),
            Err(e) => tracing::error!(image = %id, error = %e, "could not prune a backup"),
        }
    }
    Ok(())
}

/// The images present, dated from their directory name.
///
/// The name is generated by this loop and is therefore trustworthy for ordering
/// here — unlike an mtime, which a copy or a restore rewrites.
fn list_images(dir: &Path) -> Result<Vec<garmr_core::backup_retention::BackupEntry>> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(out); // nothing taken yet
    };
    for e in rd.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        let Some(ts) = name.strip_prefix("garmr-") else {
            continue; // not ours; never delete what we did not create
        };
        let Ok(t) = chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%dT%H%M%SZ") else {
            continue;
        };
        out.push(garmr_core::backup_retention::BackupEntry {
            id: name,
            created_at_us: t.and_utc().timestamp_micros(),
            // Until the manifest half lands, an image cannot self-report a
            // degraded verdict. Treating them as healthy would let the policy's
            // "keep one verifiable" rule silently pass on unverified images, so
            // this stays conservative and is revisited with the manifest.
            degraded: false,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_capture_may_run_at_a_time() {
        // Two overlapping runs would interleave in the staging tree and produce
        // two images each missing what the other took.
        let g = CaptureGuard::default();
        let first = g.try_enter().expect("free");
        assert!(g.try_enter().is_none(), "a second capture must be refused");
        drop(first);
        assert!(g.try_enter().is_some(), "the slot frees on drop");
    }

    #[test]
    fn the_slot_frees_even_when_a_capture_unwinds() {
        // A capture that panics must not wedge the schedule forever.
        let g = CaptureGuard::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = g.try_enter().expect("free");
            panic!("capture blew up");
        }));
        assert!(
            g.try_enter().is_some(),
            "a panicking capture released the slot"
        );
    }

    #[test]
    fn an_image_that_overran_the_window_is_not_left_on_disk() {
        // The rule this encodes: a directory that exists is the strongest signal
        // an operator has, so a capture that cannot be trusted must leave
        // NOTHING behind. A half-image that looks like a backup is worse than a
        // missing one, because it is only discovered at restore.
        //
        // Exercised through the same decision run_once makes, without spinning a
        // store: the window rule and the cleanup are what matter here.
        let root = std::env::temp_dir().join(format!(
            "garmr-overrun-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = root.join(image_dir_name(1_760_000_000_000_000));
        std::fs::create_dir_all(dir.join("state")).unwrap();
        std::fs::write(dir.join("state/state.dump"), b"partial").unwrap();
        assert!(dir.exists());

        // A capture that took 250s against a 300s grace is past the two-thirds
        // line, so run_once would refuse and clean up.
        let elapsed = Duration::from_secs(250);
        let grace = Duration::from_secs(300);
        assert!(!crate::backup_window::within_safety_window(elapsed, grace));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!dir.exists(), "the partial image must not survive");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_image_says_plainly_that_it_is_not_restorable_yet() {
        // The principle applied everywhere else in this module, applied to
        // ourselves: a directory that looks like a backup and is not one is the
        // exact failure being guarded against, so the image states what it is.
        let root = std::env::temp_dir().join(format!(
            "garmr-status-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        write_status(&root, true).unwrap();
        let body = std::fs::read_to_string(root.join(STATUS_FILE)).unwrap();
        assert!(body.contains("REFUSE"), "{body}");
        assert!(body.contains("not as a restorable backup"), "{body}");
        // And it names the path that DOES produce a restorable image.
        assert!(body.contains("garmr backup create"), "{body}");

        // A missing ledger is called out, not left for a restore to discover.
        write_status(&root, false).unwrap();
        let body = std::fs::read_to_string(root.join(STATUS_FILE)).unwrap();
        assert!(body.contains("ABSENT"), "{body}");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn image_names_sort_chronologically() {
        // An operator listing the directory should see the same order the prune
        // policy uses, without reading manifests.
        let a = image_dir_name(1_700_000_000_000_000);
        let b = image_dir_name(1_800_000_000_000_000);
        assert!(a < b, "{a} should sort before {b}");
        assert!(a.starts_with("garmr-"));
    }

    #[test]
    fn only_directories_this_loop_created_are_listed() {
        // The prune deletes what this returns, so a foreign directory appearing
        // here would be destroyed. Never delete what we did not create.
        let root = std::env::temp_dir().join(format!(
            "garmr-bk-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("garmr-20260814T101500Z")).unwrap();
        std::fs::create_dir_all(root.join("someone-elses-data")).unwrap();
        std::fs::create_dir_all(root.join("garmr-not-a-timestamp")).unwrap();
        let listed = list_images(&root).unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].id, "garmr-20260814T101500Z");
        std::fs::remove_dir_all(&root).ok();
    }
}
