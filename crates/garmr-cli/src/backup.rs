// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13 — `garmr backup`: create / verify / restore / promote / show. The
//! garmr-cli edge of the pure [`garmr_core::backup`] vocabulary, mirroring the
//! Phase-11 `bundle` twin.
//!
//! `create` is OFFLINE / writer-stopped: it acquires the redb exclusion over the
//! state DB and the warehouse catalog (a non-destructive [`try_acquire_exclusion`]
//! probe, NOT `open_writable`), copies the durable trees, ed25519-signs the
//! content-addressed manifest, and FAILS CLOSED if any secret path is staged —
//! the ledger is copied by the SAME allow-list as `garmr audit export` (segments
//! plus checkpoints and public key, never `signing.key`). `verify` is offline and
//! fail-closed against an OUT-OF-BAND trusted key (the embedded key is never a
//! trust root). `restore` verifies first, refuses a live writer and a
//! warehouse-path-binding mismatch, stages + swaps atomically with rollback, and
//! writes the restored-follower marker BEFORE the swap commits — a restored node
//! is a read-only FOLLOWER until the audited `promote` clears the marker
//! (invariant #2: a restored node never silently becomes a writer).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use garmr_audit::{Signer, SoftwareSigner, TrustRoot};
use garmr_core::backup::{
    canonical_backup_body, manifest_digest, BackupEntry, BackupEntryKind, BackupFinding,
    BackupManifest, LedgerCoord, SignedBackup, StateCoord, WarehouseCoord, BACKUP_FORMAT,
};
use garmr_store::try_acquire_exclusion;

use crate::bundle::{default_key_path, stream_digest};
use crate::cli::{BackupCmd, Cli};
use crate::load_config;

/// Envelope files written LAST and excluded from the content-addressed walk.
const ENVELOPE: [&str; 2] = ["backup.json", "public_key.hex"];

pub(crate) async fn backup_cmd(cli: &Cli, what: &BackupCmd) -> Result<()> {
    match what {
        BackupCmd::Create {
            dir,
            include_cold,
            signing_key,
        } => create(cli, dir, *include_cold, signing_key.as_deref()).await,
        BackupCmd::Verify { dir, key } => {
            let findings = verify(cli, dir, key.as_deref())?;
            if !findings.is_empty() {
                bail!("backup verification FAILED: {} finding(s)", findings.len());
            }
            println!("backup OK");
            Ok(())
        }
        BackupCmd::Restore {
            dir,
            key,
            force,
            accept_degraded,
            include_cold,
            dry_run,
        } => {
            restore(
                cli,
                dir,
                key.as_deref(),
                *force,
                *accept_degraded,
                *include_cold,
                *dry_run,
            )
            .await
        }
        BackupCmd::Promote { reason } => promote(cli, reason).await,
        BackupCmd::Show { dir } => show(dir),
    }
}

/// The path of the restored-follower marker. Its presence means a node was
/// restored from a backup and has NOT been promoted to writer; `serve` refuses to
/// open writable while it exists, and `garmr backup promote` clears it after an
/// audited transition (invariant #2: a restored node never silently becomes a
/// writer).
pub(crate) fn restored_marker_path(cfg: &garmr_core::Config) -> PathBuf {
    // Single source of truth in garmr-store, so Store::open_writable (the choke
    // point) and this CLI path can never disagree on the marker location.
    garmr_store::restored_marker_path(&cfg.store.state_db)
}

/// Promote a restored follower to writer: prove no writer is live (the redb-lock
/// fence — the concrete, network-free anti-split-brain gate), record a fail-closed
/// audited follower→writer transition, then clear the restored marker. Run with
/// serve stopped. Single-host authoritative only; true multi-node failover stays
/// operationally fenced and UNVERIFIED (see docs/ha-design.md).
async fn promote(cli: &Cli, reason: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let marker = restored_marker_path(&cfg);
    if !marker.exists() {
        bail!(
            "no restored-follower marker at {} — `promote` applies to a node restored via \
             `garmr backup restore`",
            marker.display()
        );
    }

    // FENCE (review must-fix #3): a bare redb probe proving the lock is FREE. If a
    // writer is already up, refuse — this is what prevents two writers.
    let catalog = cfg.store.warehouse_dir.join("catalog.redb");
    let _fence = match try_acquire_exclusion(&[cfg.store.state_db.as_path(), catalog.as_path()])
        .context("probing for a live writer before promotion")?
    {
        Some(g) => g,
        None => bail!(
            "a writer is already running on this node (its state DB or catalog is locked) — not \
             promoting; this prevents two writers"
        ),
    };

    // Read the restore provenance from the marker BEFORE auditing, so the promote
    // record binds the backup this node was restored from — never promote blind
    // (a corrupt/foreign marker with no backup id is refused).
    let marker_body = std::fs::read_to_string(&marker)
        .with_context(|| format!("reading the restored marker {}", marker.display()))?;
    let field = |k: &str| {
        marker_body
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let Some(restored_from) = field("restored_from") else {
        bail!(
            "the restored marker {} has no restored_from backup id — refusing to promote blind \
             (the marker may be corrupt)",
            marker.display()
        );
    };
    let restored_at = field("restored_at").unwrap_or_else(|| "unknown".into());

    // AUDITED transition, fail-closed (the bundle-import discipline): an unaudited
    // writer transition is refused. The restore provenance is bound into the reason.
    crate::audit::ensure_init(&cfg.audit)?;
    let audit_id = crate::audit::record_admin_local(
        garmr_audit::action::HA_PROMOTE,
        "ha",
        Some(&cfg.audit.node_id),
        Some(&format!(
            "restored_from={restored_from} restored_at={restored_at}; {reason}"
        )),
    )?;
    let Some(audit_id) = audit_id else {
        bail!(
            "the audit ledger is DISABLED — refusing to promote unaudited (a writer transition \
             must be tamper-evidently recorded). Enable [audit] and retry."
        );
    };

    std::fs::remove_file(&marker).with_context(|| format!("clearing {}", marker.display()))?;
    println!("promoted this node to WRITER (audit {audit_id})");
    println!(
        "  start `garmr serve` — it acquires the writer lock; a second writer on the same store \
         will hard-fail (exactly-one-writer)."
    );
    Ok(())
}

async fn create(
    cli: &Cli,
    dir: &Path,
    include_cold: bool,
    signing_key: Option<&Path>,
) -> Result<()> {
    let cfg = load_config(cli)?;
    let warehouse_dir = &cfg.store.warehouse_dir;
    let state_db = &cfg.store.state_db;
    let catalog = warehouse_dir.join("catalog.redb");

    if !state_db.is_file() {
        bail!(
            "no state DB at {} — nothing to back up (is this the right --config?)",
            state_db.display()
        );
    }
    // The destination must be empty (never clobber an existing artifact/dir).
    if dir.exists()
        && std::fs::read_dir(dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    {
        bail!(
            "backup destination {} exists and is not empty",
            dir.display()
        );
    }

    // FENCE (must-fix #3): acquire the redb exclusion over the state DB + the
    // warehouse catalog WITHOUT the destructive side effects of open_writable.
    // A live `serve` holds these locks, so we refuse fail-closed and, while the
    // guard lives, no writer can start mid-copy.
    let _exclusion = match try_acquire_exclusion(&[state_db.as_path(), catalog.as_path()])
        .context("probing for a live writer")?
    {
        Some(g) => g,
        None => bail!(
            "a writer is live (the state DB or warehouse catalog is locked) — stop `garmr serve` \
             before taking an offline backup"
        ),
    };

    // AUDITED, fail-closed (the promote discipline): a backup is a complete copy
    // of the dataset leaving the node's enforcement boundary, and an unrecorded
    // one is indistinguishable from exfiltration. Opening the ledger here is
    // safe — the exclusion fence above proves no live writer has it open.
    // Auditing disabled is tolerated (a backup is a safety mechanism and must
    // not depend on an optional subsystem); an append FAILURE refuses the
    // backup, because nothing has been written yet.
    crate::audit::ensure_init(&cfg.audit)?;
    if crate::audit::record_admin_local(
        garmr_audit::action::BACKUP,
        "backup",
        Some(&dir.display().to_string()),
        Some(&format!("offline backup (include_cold={include_cold})")),
    )?
    .is_none()
    {
        eprintln!("note: auditing is disabled — this backup is not tamper-evidently recorded");
    }

    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    // 1. Copy the durable trees into staging (no digests yet).
    copy_tree(warehouse_dir, &dir.join("warehouse"))
        .with_context(|| format!("copying warehouse {}", warehouse_dir.display()))?;
    std::fs::create_dir_all(dir.join("state"))?;
    std::fs::copy(state_db, dir.join("state/state.redb"))
        .with_context(|| format!("copying state DB {}", state_db.display()))?;
    let ledger_captured = copy_ledger_allowlisted(&cfg.audit.dir, &dir.join("ledger"))?;
    if include_cold && cfg.retention.cold_dir.is_dir() {
        copy_tree(&cfg.retention.cold_dir, &dir.join("cold")).context("copying cold tier")?;
    }

    // 2. SECRET DENYLIST over the whole staged tree — fail closed, not a silent
    //    filter (a signing key or live config that slipped in aborts the build).
    for abs in walk_files(dir)? {
        let rel = rel_path(dir, &abs);
        if is_denied_secret(&rel) {
            let _ = std::fs::remove_dir_all(dir);
            bail!(
                "refusing to write a backup: a secret path was staged ({rel}). This is a \
                 fail-closed guard; the ledger signing key and live config must never be \
                 captured."
            );
        }
    }

    // 3. Warehouse coordinate: open the STAGED copy read-only to read the pinned
    //    snapshot + metadata location. This may touch the staged catalog.redb, so
    //    every file is digested AFTER (step 5), keeping the manifest internally
    //    consistent with the captured bytes.
    let (snapshot_id, metadata_rel, wh_opened) = read_warehouse_pin(&dir.join("warehouse")).await?;
    let abs_warehouse_path = warehouse_dir
        .canonicalize()
        .unwrap_or_else(|_| warehouse_dir.clone())
        .to_string_lossy()
        .to_string();
    let metadata_digest = if metadata_rel.is_empty() {
        String::new()
    } else {
        stream_digest(&dir.join("warehouse").join(&metadata_rel))
            .map(|(d, _)| d)
            .unwrap_or_default()
    };

    // 4. Ledger coordinate: read the head read-only via verify_dir (public key
    //    only, non-mutating — secondary note b), over the CAPTURED ledger.
    let ledger = ledger_coord(&cfg, signing_key, ledger_captured, &dir.join("ledger"))?;

    // 5. Content-address every staged file (post-open bytes) into entries.
    let mut entries: Vec<BackupEntry> = Vec::new();
    let mut state = StateCoord::default();
    for abs in walk_files(dir)? {
        let rel = rel_path(dir, &abs);
        if ENVELOPE.contains(&rel.as_str()) {
            continue;
        }
        let (digest, size_bytes) = stream_digest(&abs)?;
        let kind = classify(&rel);
        if kind == BackupEntryKind::StateDb {
            state = StateCoord {
                kind: "redb_file".into(),
                digest: digest.clone(),
                len: size_bytes,
            };
        }
        entries.push(BackupEntry {
            path: rel,
            kind,
            digest,
            size_bytes,
        });
    }
    entries.sort_by(|a, b| (a.kind.tag(), &a.path).cmp(&(b.kind.tag(), &b.path)));

    // 6. Assemble + sign.
    let signer = {
        let key = signing_key
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_key_path(&cfg));
        SoftwareSigner::load_or_create(&key)
            .with_context(|| format!("loading the signing key {}", key.display()))?
    };
    let mut manifest = BackupManifest {
        format_version: BACKUP_FORMAT,
        backup_id: String::new(),
        created_at_us: Utc::now().timestamp_micros(),
        node_id: cfg.audit.node_id.clone(),
        garmr_version: env!("CARGO_PKG_VERSION").into(),
        git_commit: std::env::var("GARMR_GIT_COMMIT").unwrap_or_default(),
        mode: "offline_quiesced".into(),
        // Honest create-time verdict: "verified" only when the warehouse actually
        // opened; a warehouse that failed to open is "degraded" so restore refuses
        // it without --accept-degraded (review MEDIUM).
        integrity: if wh_opened { "verified" } else { "degraded" }.into(),
        warehouse: WarehouseCoord {
            current_snapshot_id: snapshot_id,
            metadata_location: metadata_rel,
            metadata_digest,
            abs_warehouse_path,
        },
        ledger,
        state,
        entries,
        audit_public_key_id: signer.key_id().to_string(),
        notes: String::new(),
    };
    manifest.backup_id = manifest_digest(&manifest);

    let body = canonical_backup_body(&manifest);
    let sig = signer.sign(&body);
    let pk = signer.public_key();
    let signed = SignedBackup {
        manifest_digest: manifest.backup_id.clone(),
        manifest,
        signature_format: "ed25519".into(),
        signing_key_id: signer.key_id().to_string(),
        public_key: hex::encode(pk),
        signature: sig.to_hex(),
    };
    std::fs::write(dir.join("backup.json"), serde_json::to_vec_pretty(&signed)?)?;
    std::fs::write(dir.join("public_key.hex"), hex::encode(pk))?;

    println!(
        "created backup {} ({} entries)",
        dir.display(),
        signed.manifest.entries.len()
    );
    println!("  backup_id:      {}", signed.manifest_digest);
    println!(
        "  warehouse:      snapshot {} @ {}",
        signed.manifest.warehouse.current_snapshot_id, signed.manifest.warehouse.abs_warehouse_path
    );
    println!("  ledger head:    seq {}", signed.manifest.ledger.head_seq);
    println!("  signing key:    {}", signed.signing_key_id);
    println!(
        "  NOTE: this artifact contains node state (incl. the session-cookie key in the state \
         DB) — treat it as confidential and keep it on trusted, encrypted-at-rest media."
    );
    Ok(())
}

/// Read the pinned snapshot id + the warehouse-relative current-metadata path by
/// opening the staged warehouse read-only. Returns `(snapshot_id, metadata_rel,
/// opened_ok)`. `opened_ok == false` means the warehouse FAILED to open (a
/// corrupt/torn catalog) — distinct from a legitimately-empty warehouse (opens
/// fine, no `events` table) — so create can stamp `integrity = "degraded"` and
/// restore refuses it without `--accept-degraded` (review MEDIUM).
async fn read_warehouse_pin(staged_warehouse: &Path) -> Result<(i64, String, bool)> {
    let wh = match skade::Warehouse::open(staged_warehouse).await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "staged warehouse did NOT open — marking the backup degraded");
            return Ok((-1, String::new(), false));
        }
    };
    let table = match wh.table("events").await {
        Ok(t) => t,
        // Opened fine but no events table yet (a fresh node) — a legitimately
        // empty pin, NOT degraded.
        Err(_) => return Ok((-1, String::new(), true)),
    };
    let snapshot_id = table.current_snapshot_id().unwrap_or(-1);
    // metadata_location is an absolute file:// URI baked by skade; relativize it
    // to the warehouse directory for a portable, presence-checkable coordinate.
    let abs_wh = staged_warehouse
        .canonicalize()
        .unwrap_or_else(|_| staged_warehouse.to_path_buf());
    let metadata_rel = table
        .inner()
        .metadata_location()
        .map(|loc| relativize_location(loc, &abs_wh))
        .unwrap_or_default();
    Ok((snapshot_id, metadata_rel, true))
}

/// Turn skade's absolute `file:///…/warehouse/metadata/x.json` into the
/// warehouse-relative `metadata/x.json` (best-effort; empty if it can't be made
/// relative — the presence check simply won't match, which is safe).
fn relativize_location(loc: &str, abs_warehouse: &Path) -> String {
    let path = loc.strip_prefix("file://").unwrap_or(loc);
    let wh = abs_warehouse.to_string_lossy();
    path.strip_prefix(wh.as_ref())
        .map(|r| r.trim_start_matches('/').to_string())
        .unwrap_or_default()
}

/// Copy ONLY the audit-ledger allow-list (segments/, checkpoints/,
/// public_key.hex) — NEVER `signing.key`, exactly as `garmr audit export`.
/// Returns whether any ledger content was captured.
pub(crate) fn copy_ledger_allowlisted(audit_dir: &Path, dst: &Path) -> Result<bool> {
    if !audit_dir.is_dir() {
        return Ok(false);
    }
    let mut any = false;
    for sub in ["segments", "checkpoints"] {
        let from = audit_dir.join(sub);
        if from.is_dir() {
            copy_tree(&from, &dst.join(sub))?;
            any = true;
        }
    }
    let pk = audit_dir.join("public_key.hex");
    if pk.is_file() {
        std::fs::create_dir_all(dst)?;
        std::fs::copy(&pk, dst.join("public_key.hex"))?;
        any = true;
    }
    Ok(any)
}

/// The ledger coordinate from the CAPTURED ledger, read-only via `verify_dir`
/// against the audit public key. Zeroed when auditing is off / nothing captured.
fn ledger_coord(
    cfg: &garmr_core::Config,
    signing_key: Option<&Path>,
    captured: bool,
    staged_ledger: &Path,
) -> Result<LedgerCoord> {
    if !captured || !staged_ledger.join("segments").is_dir() {
        return Ok(LedgerCoord::default());
    }
    // The ledger is signed by the AUDIT key (not necessarily the backup signing
    // key), so verify it against the audit signer's public key.
    let audit_key = signing_key
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_key_path(cfg));
    let pk = SoftwareSigner::load_or_create(&audit_key)
        .context("loading the audit key to read the ledger head")?
        .public_key();
    let report = garmr_audit::verify_dir(staged_ledger, &TrustRoot::from_public_key(pk))
        .context("reading the captured ledger head")?;
    Ok(LedgerCoord {
        head_seq: report.last_sequence,
        last_record_hash: report
            .last_hash
            .map(|h| h.to_hex().to_string())
            .unwrap_or_default(),
        last_checkpoint_seq: 0,
    })
}

/// Infer a staged file's subsystem kind from its backup-relative path.
fn classify(rel: &str) -> BackupEntryKind {
    if let Some(w) = rel.strip_prefix("warehouse/") {
        if w == "catalog.redb" {
            BackupEntryKind::Catalog
        } else if w.ends_with(".parquet") {
            BackupEntryKind::WarehouseData
        } else {
            BackupEntryKind::WarehouseMeta
        }
    } else if rel == "state/state.redb" {
        BackupEntryKind::StateDb
    } else if rel.starts_with("ledger/segments/") {
        BackupEntryKind::LedgerSegment
    } else if rel.starts_with("ledger/checkpoints/") {
        BackupEntryKind::LedgerCheckpoint
    } else if rel == "ledger/public_key.hex" {
        BackupEntryKind::LedgerPubkey
    } else if rel.starts_with("cold/") {
        BackupEntryKind::ColdArchive
    } else {
        BackupEntryKind::Other
    }
}

/// A staged path that must NEVER appear in a backup (belt-and-suspenders over the
/// ledger allow-list): a signing key, any private key material, or live config.
fn is_denied_secret(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base == "signing.key"
        || base == "garmr.toml"
        || base.ends_with(".key")
        || base.ends_with(".pem")
}

/// Recursively copy a directory tree, rejecting symlinks and non-regular files.
pub(crate) fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let s = entry.path();
        let meta = std::fs::symlink_metadata(&s)?;
        let d = dst.join(entry.file_name());
        if meta.file_type().is_symlink() {
            bail!("symlink in source tree: {}", s.display());
        } else if meta.is_dir() {
            copy_tree(&s, &d)?;
        } else if meta.is_file() {
            std::fs::copy(&s, &d).with_context(|| format!("copying {}", s.display()))?;
        }
        // silently skip fifos/sockets/devices
    }
    Ok(())
}

/// Every regular file under `root`, absolute paths, sorted. Rejects symlinks.
fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_into(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.file_type().is_symlink() {
            bail!("symlink in staged tree: {}", p.display());
        } else if meta.is_dir() {
            walk_into(&p, out)?;
        } else if meta.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

fn rel_path(root: &Path, abs: &Path) -> String {
    abs.strip_prefix(root)
        .unwrap_or(abs)
        .to_string_lossy()
        .replace('\\', "/")
}

fn show(dir: &Path) -> Result<()> {
    let raw = std::fs::read(dir.join("backup.json"))
        .with_context(|| format!("reading {}/backup.json", dir.display()))?;
    let signed: SignedBackup = serde_json::from_slice(&raw).context("parsing backup.json")?;
    let m = &signed.manifest;
    println!("backup {}", dir.display());
    println!("  backup_id:     {}", m.backup_id);
    println!("  format:        v{}", m.format_version);
    println!("  node:          {}", m.node_id);
    println!("  garmr version: {}", m.garmr_version);
    println!("  mode:          {}", m.mode);
    println!("  integrity:     {}", m.integrity);
    println!(
        "  warehouse:     snapshot {} @ {} (meta {})",
        m.warehouse.current_snapshot_id,
        m.warehouse.abs_warehouse_path,
        m.warehouse.metadata_location
    );
    println!(
        "  ledger:        head seq {} ({})",
        m.ledger.head_seq,
        short(&m.ledger.last_record_hash, 16)
    );
    println!(
        "  state:         {} ({} bytes)",
        short(&m.state.digest, 16),
        m.state.len
    );
    println!("  entries:       {}", m.entries.len());
    println!("  signing key:   {}", signed.signing_key_id);
    println!(
        "  verify with an OUT-OF-BAND trusted key: garmr backup verify {} --key <hex>",
        dir.display()
    );
    Ok(())
}

fn short(s: &str, n: usize) -> String {
    if s.is_empty() {
        return "-".into();
    }
    // Truncate on a CHAR boundary — `show` prints these fields straight from an
    // untrusted backup.json, so a multibyte value must not panic a byte slice
    // (review LOW).
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

// ---- restore ----------------------------------------------------------------

/// One subsystem's restore: copy `backup_src` into `staging` (a sibling of the
/// live `target`, so the swap is an atomic same-filesystem rename).
struct RestorePlan {
    label: &'static str,
    backup_src: PathBuf,
    staging: PathBuf,
    target: PathBuf,
}

/// What actually happened for one subsystem during apply, for rollback: the live
/// `target`, and where its prior contents were moved aside (if it existed).
struct Applied {
    target: PathBuf,
    staging: PathBuf,
    moved_aside: Option<PathBuf>,
}

#[allow(clippy::too_many_arguments)]
async fn restore(
    cli: &Cli,
    backup_dir: &Path,
    key_override: Option<&str>,
    force: bool,
    accept_degraded: bool,
    include_cold: bool,
    dry_run: bool,
) -> Result<()> {
    let cfg = load_config(cli)?;

    // 1. VERIFY the backup fail-closed BEFORE touching any target.
    let trust_key = crate::bundle::resolve_trust_key(&cfg, key_override)?;
    if trust_key.is_none() {
        bail!(
            "restore requires an out-of-band trusted key (--key <hex>, or a local audit \
             public_key.hex) — the backup's embedded key is never a trust root"
        );
    }
    let findings = verify_backup(backup_dir, trust_key)?;
    if !findings.is_empty() {
        bail!(
            "backup verification FAILED ({} finding(s)); refusing to restore",
            findings.len()
        );
    }
    let raw = std::fs::read(backup_dir.join("backup.json"))?;
    let signed: SignedBackup = serde_json::from_slice(&raw).context("decoding backup.json")?;
    let m = &signed.manifest;

    // 2. Degraded + version guards.
    if m.integrity == "degraded" && !accept_degraded {
        bail!("backup integrity is 'degraded'; pass --accept-degraded to restore it anyway");
    }
    let running = env!("CARGO_PKG_VERSION");
    if !m.garmr_version.is_empty() && m.garmr_version != running && !force {
        bail!(
            "backup garmr_version {} != running {} — a redb/skade schema change is unsafe to \
             restore blindly; pass --force if you know the formats are compatible",
            m.garmr_version,
            running
        );
    }

    // 3. PATH BINDING (review must-fix #1): Iceberg data locations are ABSOLUTE, so
    //    restoring the warehouse to a path other than the one baked at create time
    //    would resolve NO data despite every digest matching. Refuse fail-closed.
    let target_wh = cfg.store.warehouse_dir.clone();
    let target_canon = canonical_target(&target_wh).to_string_lossy().to_string();
    if !m.warehouse.abs_warehouse_path.is_empty() && target_canon != m.warehouse.abs_warehouse_path
    {
        if force {
            tracing::warn!(
                target = %target_canon, baked = %m.warehouse.abs_warehouse_path,
                "restoring across an absolute-path mismatch (--force): the warehouse may resolve \
                 NO data. Verify queries after restore."
            );
        } else {
            bail!(
                "restore target warehouse path '{}' differs from the path baked into the backup \
                 ('{}'). Iceberg data locations are absolute, so restoring here would resolve no \
                 data. Restore to the ORIGINAL path, or pass --force only if the paths are truly \
                 equivalent (e.g. a bind mount).",
                target_canon,
                m.warehouse.abs_warehouse_path
            );
        }
    }

    // 4. NEVER OVERWRITE A LIVE NODE (review must-fix #3): fence the target with a
    //    bare redb probe. A live serve holds the lock ⇒ refuse.
    let target_state = cfg.store.state_db.clone();
    let target_catalog = target_wh.join("catalog.redb");
    let fence = match try_acquire_exclusion(&[target_state.as_path(), target_catalog.as_path()])
        .context("probing the restore target for a live writer")?
    {
        Some(g) => g,
        None => bail!(
            "a writer is live at the restore target (its state DB or catalog is locked) — stop \
             `garmr serve` before restoring"
        ),
    };

    // 5. Build the per-subsystem plan (staging siblings on the same filesystem).
    let mut plan = vec![
        RestorePlan {
            label: "warehouse",
            backup_src: backup_dir.join("warehouse"),
            staging: with_suffix(&target_wh, ".restore-staging"),
            target: target_wh.clone(),
        },
        RestorePlan {
            label: "state",
            backup_src: backup_dir.join("state/state.redb"),
            staging: with_suffix(&target_state, ".restore-staging"),
            target: target_state.clone(),
        },
    ];
    if backup_dir.join("ledger").is_dir() {
        plan.push(RestorePlan {
            label: "audit ledger",
            backup_src: backup_dir.join("ledger"),
            staging: with_suffix(&cfg.audit.dir, ".restore-staging"),
            target: cfg.audit.dir.clone(),
        });
    }
    if include_cold && backup_dir.join("cold").is_dir() {
        plan.push(RestorePlan {
            label: "cold tier",
            backup_src: backup_dir.join("cold"),
            staging: with_suffix(&cfg.retention.cold_dir, ".restore-staging"),
            target: cfg.retention.cold_dir.clone(),
        });
    }

    if dry_run {
        println!("restore plan (dry run — nothing written):");
        for p in &plan {
            println!("  {:<13} -> {}", p.label, p.target.display());
        }
        println!("  warehouse snapshot: {}", m.warehouse.current_snapshot_id);
        println!("  ledger head:        seq {}", m.ledger.head_seq);
        println!("  (verification passed; run without --dry-run to apply)");
        return Ok(());
    }

    // AUDITED, fail-closed, into the CURRENT chain BEFORE any mutation: when the
    // backup carries a ledger, the restore replaces the audit directory itself,
    // so this record's home is the pre-restore chain — which the swap moves
    // aside to *.pre-restore-<ts> rather than deleting. The restored chain gets
    // its half from the audited `promote`, which binds the same backup id. An
    // append failure refuses the restore (nothing has been touched yet).
    crate::audit::ensure_init(&cfg.audit)?;
    if crate::audit::record_admin_local(
        garmr_audit::action::RESTORE,
        "backup",
        Some(&m.backup_id),
        Some(&format!(
            "restoring {} (warehouse snapshot {}, ledger head seq {}) over this node",
            backup_dir.display(),
            m.warehouse.current_snapshot_id,
            m.ledger.head_seq
        )),
    )?
    .is_none()
    {
        eprintln!("note: auditing is disabled — this restore is not tamper-evidently recorded");
    }

    // Materialize each staging tree (a pristine byte copy — no open before apply,
    // review must-fix #2). Clear any leftover staging first.
    for p in &plan {
        if p.staging.exists() {
            remove_path(&p.staging)?;
        }
        stage_copy(&p.backup_src, &p.staging).with_context(|| format!("staging {}", p.label))?;
    }

    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    // 6. MARKER FIRST (review HIGH fix): write + fsync the restored-follower marker
    //    BEFORE the swap commits, so NO observable state ever has a fully-restored
    //    store WITHOUT the marker. Otherwise a crash (or a marker-write error)
    //    between the swap and a last-step marker write would leave a restored node
    //    that `serve` opens writable — a silent, unaudited writer (invariant #2).
    //    The fail-safe default is therefore "follower". Any prior marker is saved
    //    so a rollback restores the exact prior state.
    let marker = restored_marker_path(&cfg);
    let prior_marker = std::fs::read(&marker).ok();
    write_restored_marker(&cfg, &m.backup_id, &ts)?;

    // 7. APPLY atomically: move each live target aside to *.pre-restore-<ts>, then
    //    rename staging into place; roll back everything on any failure.
    let applied = match apply_swaps(&plan, &ts) {
        Ok(a) => a,
        Err(e) => {
            restore_prior_marker(&marker, prior_marker.as_deref());
            return Err(e);
        }
    };

    // 8. RESOLVABILITY PROBE (review must-fix #1): the swap is committed, so open
    //    the RESTORED node read-only (Store::open ignores the marker) and confirm
    //    the warehouse opens + resolves data at the pinned snapshot. Roll back —
    //    including the marker — on failure.
    drop(fence);
    if let Err(e) = resolvability_probe(&cfg, m.warehouse.current_snapshot_id).await {
        tracing::error!(error = %e, "post-restore resolvability probe failed — rolling back");
        rollback_swaps(&applied)?;
        restore_prior_marker(&marker, prior_marker.as_deref());
        bail!("post-restore resolvability probe failed ({e}); rolled back — target left untouched");
    }

    // Success: the follower marker stays (invariant #2 — read-only until an
    // audited `garmr backup promote`).
    println!(
        "restored backup {} into the configured targets",
        backup_dir.display()
    );
    println!(
        "  warehouse snapshot {} | ledger head seq {}",
        m.warehouse.current_snapshot_id, m.ledger.head_seq
    );
    println!(
        "  the node is a read-only FOLLOWER — run `garmr backup promote` (audited) before serving \
         as a writer"
    );
    println!(
        "  full-text + semantic search are COLD until you re-index (garmr embed-index / reindex)"
    );
    println!(
        "  the previous data was moved aside to *.pre-restore-{ts} (garmr never hard-deletes)"
    );
    Ok(())
}

/// Canonicalize a target path, tolerating a not-yet-existing leaf (canonicalize
/// the parent + rejoin the basename) so the path-binding check works on a fresh
/// node.
fn canonical_target(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .map(|c| c.join(name))
            .unwrap_or_else(|_| p.to_path_buf()),
        _ => p.to_path_buf(),
    }
}

/// Append a suffix to a path (for the sibling staging / pre-restore names).
fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Copy `src` (a file or a dir) to `dst`, pristine (rejecting symlinks).
fn stage_copy(src: &Path, dst: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src)
        .with_context(|| format!("staging source {}", src.display()))?;
    if meta.is_dir() {
        copy_tree(src, dst)?;
    } else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

fn remove_path(p: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(p)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(p)?;
    } else {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

/// Move each live target aside to `*.pre-restore-<ts>` and rename its staging into
/// place. On any error, roll back the swaps already done so the targets are left
/// exactly as they were.
fn apply_swaps(plan: &[RestorePlan], ts: &str) -> Result<Vec<Applied>> {
    let mut applied: Vec<Applied> = Vec::new();
    for p in plan {
        let moved_aside = if p.target.exists() {
            let aside = with_suffix(&p.target, &format!(".pre-restore-{ts}"));
            if let Err(e) = std::fs::rename(&p.target, &aside) {
                rollback_swaps(&applied)?;
                return Err(e).with_context(|| format!("moving {} aside", p.label));
            }
            Some(aside)
        } else {
            None
        };
        if let Err(e) = std::fs::rename(&p.staging, &p.target) {
            // Undo this target's move-aside, then roll back the rest.
            if let Some(aside) = &moved_aside {
                let _ = std::fs::rename(aside, &p.target);
            }
            rollback_swaps(&applied)?;
            return Err(e).with_context(|| format!("swapping {} into place", p.label));
        }
        applied.push(Applied {
            target: p.target.clone(),
            staging: p.staging.clone(),
            moved_aside,
        });
    }
    Ok(applied)
}

/// Reverse applied swaps: move the just-restored target back to its staging, then
/// restore the moved-aside prior contents. Best-effort per entry (logs on error)
/// so a partial rollback still restores as much as possible.
fn rollback_swaps(applied: &[Applied]) -> Result<()> {
    for a in applied.iter().rev() {
        if a.target.exists() {
            if let Err(e) = std::fs::rename(&a.target, &a.staging) {
                tracing::warn!(error = %e, target = %a.target.display(), "rollback: could not move restored target back to staging");
            }
        }
        if let Some(aside) = &a.moved_aside {
            if let Err(e) = std::fs::rename(aside, &a.target) {
                tracing::warn!(error = %e, target = %a.target.display(), "rollback: could not restore the pre-restore copy");
            }
        }
    }
    Ok(())
}

/// Open the restored node read-only and confirm the warehouse resolves data at
/// the pinned snapshot (a bounded scan). Skipped when the backup captured no
/// snapshot (`current_snapshot_id < 0`).
async fn resolvability_probe(cfg: &garmr_core::Config, expected_snapshot: i64) -> Result<()> {
    // ALWAYS open the restored store — a warehouse that failed to open at create
    // time (a corrupt/torn catalog) reads as snapshot -1, so skipping on
    // `snapshot < 0` would bypass the probe for exactly the image class it exists
    // to catch (review MEDIUM). An open failure here fails the restore closed.
    let store = garmr_store::Store::open(cfg)
        .await
        .context("opening the restored store read-only")?;
    // A bounded read that must resolve the metadata + at least one data file when
    // the snapshot has rows; if the absolute Iceberg locations don't resolve, this
    // errors. Skipped only for an empty warehouse (no snapshot), where an
    // events-table scan may legitimately have nothing to resolve.
    if expected_snapshot >= 0 {
        store
            .events
            .sql("SELECT host FROM events LIMIT 1")
            .await
            .context("scanning the restored warehouse")?;
    }
    Ok(())
}

/// Write the restored-follower marker next to the state DB. Its presence means a
/// restored node has NOT been promoted to writer; `garmr backup promote` (c5)
/// clears it after an audited transition.
fn write_restored_marker(cfg: &garmr_core::Config, backup_id: &str, ts: &str) -> Result<()> {
    use std::io::Write;
    let marker = restored_marker_path(cfg);
    // Durable write (fsync): the marker is the fail-safe that keeps a restored node
    // a follower across a crash, so it must survive one — write + fsync BEFORE the
    // swap commits (the caller orders it so).
    let mut f = std::fs::File::create(&marker)
        .with_context(|| format!("writing the restored marker {}", marker.display()))?;
    f.write_all(
        format!("restored_from={backup_id}\nrestored_at={ts}\nrole=follower\n").as_bytes(),
    )?;
    f.sync_all()
        .with_context(|| format!("fsync of the restored marker {}", marker.display()))?;
    Ok(())
}

/// Undo a marker write on rollback: restore the exact prior marker bytes, or
/// remove the marker if there was none (so a fully rolled-back node returns to its
/// exact prior state — a writer with no marker, or its previous marker). Best
/// effort: a failure here only leaves the node MORE fenced, never less.
fn restore_prior_marker(marker: &Path, prior: Option<&[u8]>) {
    let res = match prior {
        Some(bytes) => std::fs::write(marker, bytes),
        None => std::fs::remove_file(marker).or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        }),
    };
    if let Err(e) = res {
        tracing::warn!(error = %e, marker = %marker.display(),
            "rollback: could not restore the prior follower-marker state (node left fenced as a follower — safe)");
    }
}

// ---- verify -----------------------------------------------------------------

/// Verify a backup offline, fail-closed. Resolves the out-of-band trust key
/// (`--key`, else the local audit public key; NEVER the artifact-embedded key)
/// then delegates to [`verify_backup`].
fn verify(cli: &Cli, dir: &Path, key_override: Option<&str>) -> Result<Vec<BackupFinding>> {
    let cfg = load_config(cli)?;
    let trust_key = crate::bundle::resolve_trust_key(&cfg, key_override)?;
    verify_backup(dir, trust_key)
}

/// The trust-key-parameterized verify core (testable without config). Checks, in
/// order and all fail-closed: an out-of-band trusted key is present; the signature
/// over the canonical body verifies against it; the stamped manifest digest
/// recomputes; every file digest matches with STRICT extra-file detection and
/// symlink/escape rejection; and the captured ledger verifies to exactly the
/// signed head. Does NOT open the warehouse (that would mutate the artifact — see
/// review must-fix #2); the per-file digests already prove the bytes are the ones
/// `create` verified openable, and the restore-time resolvability probe (c4) is
/// where the warehouse is actually opened. Empty vec == the backup verifies.
pub(crate) fn verify_backup(dir: &Path, trust_key: Option<[u8; 32]>) -> Result<Vec<BackupFinding>> {
    let raw = std::fs::read(dir.join("backup.json"))
        .with_context(|| format!("reading {}/backup.json", dir.display()))?;
    let sb: SignedBackup = serde_json::from_slice(&raw).context("decoding backup.json")?;

    let Some(trust_key) = trust_key else {
        println!("UNVERIFIED: no trusted key (pass --key <hex> or publish audit public_key.hex)");
        return Ok(vec![BackupFinding {
            category: "no_trusted_key".into(),
            coord: dir.display().to_string(),
            detail: "no out-of-band trusted key; the embedded key is never a trust root".into(),
        }]);
    };

    let mut findings: Vec<BackupFinding> = Vec::new();

    // Signature over the canonical body, against the TRUSTED key.
    let body = canonical_backup_body(&sb.manifest);
    let sig_bytes = hex::decode(sb.signature.trim()).unwrap_or_default();
    if !garmr_audit::verify_signature(&trust_key, &body, &garmr_audit::Sig(sig_bytes)) {
        findings.push(BackupFinding {
            category: "signature".into(),
            coord: sb.signing_key_id.clone(),
            detail: "signature does not verify against the trusted key".into(),
        });
    }
    if !garmr_core::backup::verify_manifest_digest(&sb) {
        findings.push(BackupFinding {
            category: "manifest_digest".into(),
            coord: sb.manifest_digest.clone(),
            detail: "stamped manifest digest != recomputed".into(),
        });
    }

    // Every file: recompute + STRICT extra-file detection + symlink/escape reject.
    let (computed, walk_findings) = walk_backup(dir)?;
    findings.extend(walk_findings);
    findings.extend(garmr_core::backup::verify_backup_digests(
        &sb.manifest,
        &computed,
        true,
    ));

    // Ledger cross-check: the captured segments must verify to EXACTLY the signed
    // head. verify_dir is read-only (public-key only), so re-verification is
    // idempotent. Uses the same out-of-band trusted key (the single-key default:
    // the backup is signed by the audit key that also signs the ledger).
    let ledger_dir = dir.join("ledger");
    if sb.manifest.ledger.head_seq > 0 || ledger_dir.join("segments").is_dir() {
        match garmr_audit::verify_dir(&ledger_dir, &TrustRoot::from_public_key(trust_key)) {
            Ok(report) => {
                if !report.ok {
                    findings.push(BackupFinding {
                        category: "ledger_binding".into(),
                        coord: "ledger".into(),
                        detail: format!(
                            "captured ledger fails verification ({} finding(s))",
                            report.findings.len()
                        ),
                    });
                }
                if report.last_sequence != sb.manifest.ledger.head_seq {
                    findings.push(BackupFinding {
                        category: "ledger_binding".into(),
                        coord: "ledger".into(),
                        detail: format!(
                            "ledger head_seq {} != manifest head_seq {}",
                            report.last_sequence, sb.manifest.ledger.head_seq
                        ),
                    });
                }
                let last_hash = report
                    .last_hash
                    .map(|h| h.to_hex().to_string())
                    .unwrap_or_default();
                if last_hash != sb.manifest.ledger.last_record_hash {
                    findings.push(BackupFinding {
                        category: "ledger_binding".into(),
                        coord: "ledger".into(),
                        detail: "ledger head hash != manifest last_record_hash".into(),
                    });
                }
            }
            Err(e) => findings.push(BackupFinding {
                category: "ledger_binding".into(),
                coord: "ledger".into(),
                detail: format!("could not verify the captured ledger: {e}"),
            }),
        }
    }

    if findings.is_empty() {
        println!(
            "verified {} entries against key {}",
            sb.manifest.entries.len(),
            sb.signing_key_id
        );
    } else {
        for f in &findings {
            println!("  [{}] {}: {}", f.category, f.coord, f.detail);
        }
    }
    Ok(findings)
}

/// Walk the backup tree (excluding the envelope files), rejecting symlinks and
/// any non-regular or escaping path, returning `rel_path -> blake3-hex`.
fn walk_backup(
    dir: &Path,
) -> Result<(
    std::collections::BTreeMap<String, String>,
    Vec<BackupFinding>,
)> {
    let mut computed = std::collections::BTreeMap::new();
    let mut findings = Vec::new();
    let root = dir
        .canonicalize()
        .with_context(|| format!("backup dir {}", dir.display()))?;
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)?.flatten() {
            let p = e.path();
            let meta = std::fs::symlink_metadata(&p)?;
            if meta.file_type().is_symlink() {
                findings.push(BackupFinding {
                    category: "unsafe_path".into(),
                    coord: p.display().to_string(),
                    detail: "symlink in the backup tree".into(),
                });
                continue;
            }
            if meta.is_dir() {
                stack.push(p);
                continue;
            }
            // Only REGULAR files are hashed — a hostile FIFO/socket would block
            // stream_digest's blocking open forever.
            if !meta.is_file() {
                findings.push(BackupFinding {
                    category: "unsafe_path".into(),
                    coord: p.display().to_string(),
                    detail: "non-regular file (fifo/socket/device) in the backup tree".into(),
                });
                continue;
            }
            let rel = p
                .strip_prefix(&root)
                .ok()
                .and_then(|r| r.to_str())
                .map(|s| s.replace('\\', "/"))
                .unwrap_or_default();
            if ENVELOPE.contains(&rel.as_str()) {
                continue;
            }
            if !garmr_core::is_safe_relative_path(&rel) {
                findings.push(BackupFinding {
                    category: "unsafe_path".into(),
                    coord: rel,
                    detail: "file path escapes the backup tree".into(),
                });
                continue;
            }
            let (digest, _) = stream_digest(&p)?;
            computed.insert(rel, digest);
        }
    }
    Ok((computed, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gap this closes: every existing test here exercises `verify` against
    /// a HAND-BUILT manifest. Nothing ran `create` itself, so the assembly —
    /// walk, digest, classify, sign — was the one part of the disaster-recovery
    /// path with no coverage at all. That is also exactly the code any future
    /// refactor (sharing it with the online capture) would touch, and
    /// refactoring untested code is how behaviour changes in silence.
    #[tokio::test]
    async fn a_created_backup_verifies_against_its_own_key() {
        let root = std::env::temp_dir().join(format!(
            "garmr-create-rt-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (wh, state_dir, out) = (
            root.join("warehouse"),
            root.join("state"),
            root.join("image"),
        );
        std::fs::create_dir_all(wh.join("data")).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        // A warehouse-shaped tree plus a state DB file. `create` copies and
        // digests whatever is there; it does not require a real lakehouse.
        std::fs::write(wh.join("data/part-1.parquet"), b"columnar bytes").unwrap();
        // A REAL redb file: the writer-liveness probe opens it, so a dummy byte
        // blob fails as "invalid data" long before the assembly runs. Opened and
        // dropped so the exclusive lock is released before `create` probes.
        let state_db = state_dir.join("state.redb");
        drop(garmr_store::state::StateStore::open(&state_db).unwrap());

        let cfg_path = root.join("garmr.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "[store]\nwarehouse_dir = {:?}\nstate_db = {:?}\nsearch_dir = {:?}\n\
                 [ingest]\n\
                 [detect]\nrules_dir = {:?}\ncorrelations_dir = {:?}\nhunts_dir = {:?}\n\
                 policies_dir = {:?}\n\
                 [agent]\nbackend = \"anthropic\"\nmodel = \"m\"\n\
                 [audit]\nenabled = true\ndir = {:?}\n",
                wh,
                state_db,
                root.join("search"),
                root.join("rules"),
                root.join("correlations"),
                root.join("hunts"),
                root.join("policies"),
                root.join("audit"),
            ),
        )
        .unwrap();

        let cli = crate::cli::Cli {
            config: Some(cfg_path),
            cmd: crate::cli::Cmd::Serve,
        };
        create(&cli, &out, false, None)
            .await
            .expect("create should produce an image");

        // The real assertion: the image verifies against the key create signed
        // it with. A manifest that is written but does not verify is the failure
        // an operator meets at the worst possible moment.
        let key = SoftwareSigner::load_or_create(&default_key_path(
            &garmr_core::Config::load(&root.join("garmr.toml")).unwrap(),
        ))
        .unwrap();
        let findings = verify_backup(&out, Some(key.public_key())).unwrap();
        assert!(
            findings.is_empty(),
            "a freshly created backup must verify: {findings:?}"
        );

        // And the mode is the offline one — the online loop must not be able to
        // claim this path's guarantees by accident.
        let signed: SignedBackup =
            serde_json::from_slice(&std::fs::read(out.join("backup.json")).unwrap()).unwrap();
        assert_eq!(signed.manifest.mode, "offline_quiesced");
        assert_eq!(signed.manifest.state.kind, "redb_file");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn classify_maps_each_subsystem_path() {
        assert_eq!(classify("warehouse/catalog.redb"), BackupEntryKind::Catalog);
        assert_eq!(
            classify("warehouse/data/x.parquet"),
            BackupEntryKind::WarehouseData
        );
        assert_eq!(
            classify("warehouse/metadata/v3.metadata.json"),
            BackupEntryKind::WarehouseMeta
        );
        assert_eq!(classify("state/state.redb"), BackupEntryKind::StateDb);
        assert_eq!(
            classify("ledger/segments/0001.jsonl"),
            BackupEntryKind::LedgerSegment
        );
        assert_eq!(
            classify("ledger/checkpoints/0001.ckpt.json"),
            BackupEntryKind::LedgerCheckpoint
        );
        assert_eq!(
            classify("ledger/public_key.hex"),
            BackupEntryKind::LedgerPubkey
        );
        assert_eq!(classify("cold/2026-07.zip"), BackupEntryKind::ColdArchive);
        assert_eq!(classify("stray"), BackupEntryKind::Other);
    }

    #[test]
    fn secret_denylist_catches_keys_and_live_config() {
        // The exact secret the allow-list already excludes, caught again here.
        assert!(is_denied_secret("ledger/signing.key"));
        assert!(is_denied_secret("warehouse/leaked.key"));
        assert!(is_denied_secret("x/y/server.pem"));
        assert!(is_denied_secret("garmr.toml"));
        // Legitimate captured files are NOT denied.
        assert!(!is_denied_secret("ledger/public_key.hex"));
        assert!(!is_denied_secret("warehouse/data/x.parquet"));
        assert!(!is_denied_secret("state/state.redb"));
    }

    #[test]
    fn relativize_strips_the_file_uri_and_warehouse_prefix() {
        let wh = Path::new("/data/garmr/warehouse");
        assert_eq!(
            relativize_location("file:///data/garmr/warehouse/metadata/v3.json", wh),
            "metadata/v3.json"
        );
        // An unrelated location cannot be relativized → empty (safe: no match).
        assert_eq!(relativize_location("file:///elsewhere/x", wh), "");
    }

    #[test]
    fn rel_path_is_forward_slashed_and_root_relative() {
        let root = Path::new("/tmp/bk");
        assert_eq!(
            rel_path(root, Path::new("/tmp/bk/warehouse/data/x.parquet")),
            "warehouse/data/x.parquet"
        );
    }

    // A minimal signed backup artifact WITHOUT a real store: verify never opens
    // the warehouse, so dummy files with matching digests exercise the whole
    // signature + digest + strict-extra path. Ledger head_seq 0 (no ledger dir)
    // skips the ledger cross-check.
    fn make_backup(dir: &Path) -> [u8; 32] {
        std::fs::create_dir_all(dir.join("warehouse/data")).unwrap();
        std::fs::create_dir_all(dir.join("state")).unwrap();
        let pq = b"parquet-bytes";
        let st = b"state-bytes";
        std::fs::write(dir.join("warehouse/data/x.parquet"), pq).unwrap();
        std::fs::write(dir.join("state/state.redb"), st).unwrap();
        let entries = vec![
            BackupEntry {
                path: "warehouse/data/x.parquet".into(),
                kind: BackupEntryKind::WarehouseData,
                digest: blake3::hash(pq).to_hex().to_string(),
                size_bytes: pq.len() as u64,
            },
            BackupEntry {
                path: "state/state.redb".into(),
                kind: BackupEntryKind::StateDb,
                digest: blake3::hash(st).to_hex().to_string(),
                size_bytes: st.len() as u64,
            },
        ];
        let mut manifest = BackupManifest {
            format_version: BACKUP_FORMAT,
            node_id: "garmr-1".into(),
            mode: "offline_quiesced".into(),
            integrity: "verified".into(),
            state: StateCoord {
                kind: "redb_file".into(),
                digest: blake3::hash(st).to_hex().to_string(),
                len: st.len() as u64,
            },
            entries,
            ..Default::default()
        };
        manifest.backup_id = manifest_digest(&manifest);
        let signer = SoftwareSigner::from_seed([3u8; 32]);
        let sig = signer.sign(&canonical_backup_body(&manifest));
        let pk = signer.public_key();
        let signed = SignedBackup {
            manifest_digest: manifest.backup_id.clone(),
            manifest,
            signature_format: "ed25519".into(),
            signing_key_id: signer.key_id().to_string(),
            public_key: hex::encode(pk),
            signature: sig.to_hex(),
        };
        std::fs::write(
            dir.join("backup.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("public_key.hex"), hex::encode(pk)).unwrap();
        pk
    }

    #[test]
    fn valid_backup_verifies_with_the_trusted_key() {
        let tmp = tempfile::tempdir().unwrap();
        let pk = make_backup(tmp.path());
        assert!(verify_backup(tmp.path(), Some(pk)).unwrap().is_empty());
    }

    #[test]
    fn no_key_is_unverified_never_ok() {
        let tmp = tempfile::tempdir().unwrap();
        make_backup(tmp.path());
        let f = verify_backup(tmp.path(), None).unwrap();
        assert!(f.iter().any(|x| x.category == "no_trusted_key"));
    }

    #[test]
    fn a_foreign_key_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        make_backup(tmp.path());
        let foreign = SoftwareSigner::from_seed([9u8; 32]).public_key();
        let f = verify_backup(tmp.path(), Some(foreign)).unwrap();
        assert!(f.iter().any(|x| x.category == "signature"));
    }

    #[test]
    fn a_tampered_file_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let pk = make_backup(tmp.path());
        std::fs::write(tmp.path().join("warehouse/data/x.parquet"), b"TAMPERED").unwrap();
        let f = verify_backup(tmp.path(), Some(pk)).unwrap();
        assert!(f.iter().any(|x| x.category == "digest_mismatch"));
    }

    #[test]
    fn an_unmanifested_file_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let pk = make_backup(tmp.path());
        std::fs::write(tmp.path().join("warehouse/data/evil.parquet"), b"x").unwrap();
        let f = verify_backup(tmp.path(), Some(pk)).unwrap();
        assert!(f
            .iter()
            .any(|x| x.category == "unexpected_file" && x.coord == "warehouse/data/evil.parquet"));
    }

    #[test]
    fn with_suffix_appends_to_the_whole_path() {
        assert_eq!(
            with_suffix(Path::new("/a/b/state.redb"), ".restore-staging"),
            PathBuf::from("/a/b/state.redb.restore-staging")
        );
    }

    #[test]
    fn apply_swaps_moves_aside_then_swaps_and_rolls_back_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // A dir target + a file target, each with prior contents and a staged copy.
        std::fs::create_dir_all(root.join("wh")).unwrap();
        std::fs::write(root.join("wh/old.txt"), b"old").unwrap();
        std::fs::write(root.join("state.redb"), b"oldstate").unwrap();
        std::fs::create_dir_all(root.join("wh.restore-staging")).unwrap();
        std::fs::write(root.join("wh.restore-staging/new.txt"), b"new").unwrap();
        std::fs::write(root.join("state.redb.restore-staging"), b"newstate").unwrap();

        let plan = vec![
            RestorePlan {
                label: "warehouse",
                backup_src: root.join("ignored"),
                staging: root.join("wh.restore-staging"),
                target: root.join("wh"),
            },
            RestorePlan {
                label: "state",
                backup_src: root.join("ignored"),
                staging: root.join("state.redb.restore-staging"),
                target: root.join("state.redb"),
            },
        ];

        let applied = apply_swaps(&plan, "TS").unwrap();
        // Targets now hold the staged content; prior contents moved aside.
        assert!(root.join("wh/new.txt").exists());
        assert!(!root.join("wh/old.txt").exists());
        assert!(root.join("wh.pre-restore-TS/old.txt").exists());
        assert_eq!(std::fs::read(root.join("state.redb")).unwrap(), b"newstate");
        assert_eq!(
            std::fs::read(root.join("state.redb.pre-restore-TS")).unwrap(),
            b"oldstate"
        );

        // Rollback restores the originals exactly.
        rollback_swaps(&applied).unwrap();
        assert!(root.join("wh/old.txt").exists());
        assert!(!root.join("wh/new.txt").exists());
        assert_eq!(std::fs::read(root.join("state.redb")).unwrap(), b"oldstate");
    }

    #[test]
    fn short_does_not_panic_on_a_multibyte_string() {
        // The exact review case: 6× '€' = 18 bytes, boundary NOT at byte 16.
        let s = "€€€€€€";
        let out = short(s, 4);
        assert_eq!(out, "€€€€…");
        assert_eq!(short("abc", 16), "abc");
        assert_eq!(short("", 8), "-");
    }

    #[test]
    fn restore_prior_marker_removes_when_none_and_rewrites_prior() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("state.redb.restored");

        // No prior: a rollback removes the freshly-written marker.
        std::fs::write(&marker, b"role=follower\n").unwrap();
        restore_prior_marker(&marker, None);
        assert!(!marker.exists());

        // Prior existed: a rollback restores its exact bytes.
        std::fs::write(&marker, b"NEW").unwrap();
        restore_prior_marker(&marker, Some(b"PRIOR"));
        assert_eq!(std::fs::read(&marker).unwrap(), b"PRIOR");

        // Removing an already-absent marker is not an error.
        std::fs::remove_file(&marker).unwrap();
        restore_prior_marker(&marker, None); // must not panic
    }

    #[test]
    fn apply_swaps_creates_a_fresh_target_with_no_move_aside() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("wh.restore-staging")).unwrap();
        std::fs::write(root.join("wh.restore-staging/x.txt"), b"x").unwrap();
        let plan = vec![RestorePlan {
            label: "warehouse",
            backup_src: root.join("ignored"),
            staging: root.join("wh.restore-staging"),
            target: root.join("wh"),
        }];
        let applied = apply_swaps(&plan, "TS").unwrap();
        assert!(root.join("wh/x.txt").exists());
        assert!(applied[0].moved_aside.is_none());
    }
}
