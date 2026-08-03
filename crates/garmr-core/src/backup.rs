// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 13 — the pure BACKUP vocabulary: a content-addressed manifest binding a
//! whole node's durable state (warehouse + state DB + audit ledger) to ONE
//! recoverable point, its deterministic signed-over encoding, and offline
//! verifiers. No I/O, no crypto, no new dep (blake3 + serde + `frame` only) — all
//! signing, file I/O, store-open and the redb-lock fence live at the garmr-cli
//! edge, the same boundary rule as [`crate::bundle`] and [`crate::egress`].
//!
//! A backup is "a signed image of runtime state" (vs a bundle's signed *release*):
//! the manifest lists every copied file by BLAKE3 digest AND the three subsystem
//! coordinates — warehouse snapshot id + absolute path, ledger head sequence +
//! hash, state-DB digest — that together name one instant. The manifest is framed
//! by hand (domain-separated, fixed field order, entries sorted so the id is
//! filesystem-walk-order independent) and ed25519-signed with the operator's audit
//! key. Verification recomputes every digest, the manifest digest, and checks the
//! signature against an OUT-OF-BAND trusted key — the backup's own embedded public
//! key is NEVER a trust root.

use serde::{Deserialize, Serialize};

use crate::bundle::is_safe_relative_path;

/// Backup manifest format version.
pub const BACKUP_FORMAT: u16 = 1;

/// What a backup entry is — which subsystem tree a copied file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupEntryKind {
    /// An immutable Iceberg data file (parquet).
    WarehouseData,
    /// An Iceberg metadata/manifest file.
    WarehouseMeta,
    /// The warehouse `catalog.redb` snapshot pointer.
    Catalog,
    /// The redb state database file.
    StateDb,
    /// An append-only audit ledger segment.
    LedgerSegment,
    /// A signed audit ledger checkpoint.
    LedgerCheckpoint,
    /// The audit ledger's published PUBLIC key (never the signing key).
    LedgerPubkey,
    /// An optional cold-tier archive file.
    ColdArchive,
    Other,
    #[default]
    #[serde(other)]
    Unknown,
}

impl BackupEntryKind {
    pub fn tag(self) -> &'static str {
        match self {
            BackupEntryKind::WarehouseData => "warehouse_data",
            BackupEntryKind::WarehouseMeta => "warehouse_meta",
            BackupEntryKind::Catalog => "catalog",
            BackupEntryKind::StateDb => "state_db",
            BackupEntryKind::LedgerSegment => "ledger_segment",
            BackupEntryKind::LedgerCheckpoint => "ledger_checkpoint",
            BackupEntryKind::LedgerPubkey => "ledger_pubkey",
            BackupEntryKind::ColdArchive => "cold_archive",
            BackupEntryKind::Other => "other",
            BackupEntryKind::Unknown => "unknown",
        }
    }
}

/// One content-addressed file in the backup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEntry {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub kind: BackupEntryKind,
    /// BLAKE3-hex of the file contents.
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub size_bytes: u64,
}

/// The warehouse coordinate: the pinned Iceberg snapshot + the ABSOLUTE warehouse
/// path. skade bakes absolute `file:///…/warehouse/…` locations into Iceberg
/// metadata, so a restore to a DIFFERENT path silently resolves no data even
/// though every digest matches — the absolute path is captured and enforced
/// fail-closed on restore (Phase-13 review must-fix #1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarehouseCoord {
    #[serde(default)]
    pub current_snapshot_id: i64,
    /// The pinned snapshot's metadata file, warehouse-relative.
    #[serde(default)]
    pub metadata_location: String,
    #[serde(default)]
    pub metadata_digest: String,
    /// The canonicalized absolute warehouse directory captured at create time.
    #[serde(default)]
    pub abs_warehouse_path: String,
}

/// The audit-ledger coordinate: the head the copied segments must verify to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCoord {
    #[serde(default)]
    pub head_seq: u64,
    #[serde(default)]
    pub last_record_hash: String,
    #[serde(default)]
    pub last_checkpoint_seq: u64,
}

/// The state-DB coordinate: a whole-file digest of the redb state database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCoord {
    /// `redb_file` (whole-file copy) — `logical_dump` is reserved for the deferred
    /// online capture mode.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub len: u64,
}

/// The backup manifest (the signed-over content).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    #[serde(default)]
    pub format_version: u16,
    /// The content id = the manifest digest (set after framing; NOT signed over).
    #[serde(default)]
    pub backup_id: String,
    #[serde(default)]
    pub created_at_us: i64,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub garmr_version: String,
    #[serde(default)]
    pub git_commit: String,
    /// `offline_quiesced` (the MLP) | `online_savepoint` | `fs_snapshot`.
    #[serde(default)]
    pub mode: String,
    /// `verified` | `degraded` — the create-time self-verify verdict. Restore
    /// refuses a `degraded` image unless the operator passes `--accept-degraded`.
    #[serde(default)]
    pub integrity: String,
    #[serde(default)]
    pub warehouse: WarehouseCoord,
    #[serde(default)]
    pub ledger: LedgerCoord,
    #[serde(default)]
    pub state: StateCoord,
    #[serde(default)]
    pub entries: Vec<BackupEntry>,
    /// The audit signer's PUBLIC key id — NEVER the ed25519 seed.
    #[serde(default)]
    pub audit_public_key_id: String,
    #[serde(default)]
    pub notes: String,
}

/// A manifest + its signature. `public_key` is a DISPLAY convenience copy only —
/// verification requires an out-of-band trusted key, never this field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBackup {
    #[serde(default)]
    pub manifest: BackupManifest,
    #[serde(default)]
    pub manifest_digest: String,
    #[serde(default)]
    pub signature_format: String,
    #[serde(default)]
    pub signing_key_id: String,
    /// A copy of the signer's public key (hex) for display/key-id — NOT a trust
    /// root. An out-of-band trusted key is required to verify.
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub signature: String,
}

/// A verification finding — an empty vec == the checked property holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFinding {
    /// `missing_file` | `digest_mismatch` | `unexpected_file` | `unsafe_path` |
    /// `manifest_digest` | `warehouse_binding` | `ledger_binding` | `state_binding`
    /// | `path_binding`.
    pub category: String,
    pub coord: String,
    pub detail: String,
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u64).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
}

fn put_u64(b: &mut Vec<u8>, n: u64) {
    b.extend_from_slice(&n.to_le_bytes());
}

/// The exact bytes signed over: domain-separated, fixed field order, entries
/// SORTED (so the signature is independent of the filesystem walk order). Binds
/// the three subsystem coordinates AND every entry digest, so a swapped subsystem
/// is caught even if per-file entries are also patched. Excludes `backup_id`
/// (which IS this body's digest) and the signature.
pub fn canonical_backup_body(m: &BackupManifest) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"garmr-backup-manifest\x01");
    put_u64(&mut b, m.format_version as u64);
    put_u64(&mut b, m.created_at_us as u64);
    put_str(&mut b, &m.node_id);
    put_str(&mut b, &m.garmr_version);
    put_str(&mut b, &m.git_commit);
    put_str(&mut b, &m.mode);
    put_str(&mut b, &m.integrity);

    // Warehouse coordinate.
    put_u64(&mut b, m.warehouse.current_snapshot_id as u64);
    put_str(&mut b, &m.warehouse.metadata_location);
    put_str(&mut b, &m.warehouse.metadata_digest);
    put_str(&mut b, &m.warehouse.abs_warehouse_path);
    // Ledger coordinate.
    put_u64(&mut b, m.ledger.head_seq);
    put_str(&mut b, &m.ledger.last_record_hash);
    put_u64(&mut b, m.ledger.last_checkpoint_seq);
    // State coordinate.
    put_str(&mut b, &m.state.kind);
    put_str(&mut b, &m.state.digest);
    put_u64(&mut b, m.state.len);

    let mut entries = m.entries.clone();
    entries.sort_by(|a, b| (a.kind.tag(), &a.path).cmp(&(b.kind.tag(), &b.path)));
    put_u64(&mut b, entries.len() as u64);
    for e in &entries {
        put_str(&mut b, e.kind.tag());
        put_str(&mut b, &e.path);
        put_str(&mut b, &e.digest);
        put_u64(&mut b, e.size_bytes);
    }

    put_str(&mut b, &m.audit_public_key_id);
    put_str(&mut b, &m.notes);
    b
}

/// The manifest content digest (BLAKE3-hex of the canonical body).
pub fn manifest_digest(m: &BackupManifest) -> String {
    blake3::hash(&canonical_backup_body(m)).to_hex().to_string()
}

/// Verify the stamped manifest digest matches the recomputed canonical body.
pub fn verify_manifest_digest(sb: &SignedBackup) -> bool {
    !sb.manifest_digest.is_empty() && sb.manifest_digest == manifest_digest(&sb.manifest)
}

/// Compare the manifest's declared entries against the digests actually computed
/// from the backup tree. `strict_extra` flags any computed file NOT in the
/// manifest as an `unexpected_file` (the caller pre-excludes the envelope files).
/// Also flags any entry whose path is unsafe. Empty vec == the tree matches.
pub fn verify_backup_digests(
    manifest: &BackupManifest,
    computed: &std::collections::BTreeMap<String, String>,
    strict_extra: bool,
) -> Vec<BackupFinding> {
    let mut out = Vec::new();
    let declared: std::collections::BTreeSet<&str> =
        manifest.entries.iter().map(|e| e.path.as_str()).collect();
    for e in &manifest.entries {
        if !is_safe_relative_path(&e.path) {
            out.push(BackupFinding {
                category: "unsafe_path".into(),
                coord: e.path.clone(),
                detail: "manifest entry path is absolute, escaping, or malformed".into(),
            });
            continue;
        }
        match computed.get(&e.path) {
            None => out.push(BackupFinding {
                category: "missing_file".into(),
                coord: e.path.clone(),
                detail: "declared in the manifest but absent from the backup".into(),
            }),
            Some(d) if *d != e.digest => out.push(BackupFinding {
                category: "digest_mismatch".into(),
                coord: e.path.clone(),
                detail: format!("expected {}, computed {d}", e.digest),
            }),
            Some(_) => {}
        }
    }
    if strict_extra {
        for path in computed.keys() {
            if !declared.contains(path.as_str()) {
                out.push(BackupFinding {
                    category: "unexpected_file".into(),
                    coord: path.clone(),
                    detail: "present in the backup but NOT covered by the signed manifest".into(),
                });
            }
        }
    }
    out
}

/// What was actually observed by opening the restored/staged stores — the CLI
/// derives these (I/O) and passes them here for a pure comparison against the
/// signed coordinates.
#[derive(Debug, Clone, Default)]
pub struct ObservedCoords {
    pub warehouse_snapshot_id: i64,
    pub warehouse_abs_path: String,
    pub metadata_location_present: bool,
    pub ledger_head_seq: u64,
    pub ledger_last_hash: String,
    pub state_digest: String,
}

/// Verify the manifest's subsystem binding: the coordinates observed by opening
/// the staged bytes must equal the SIGNED coordinates. Catches a warehouse rolled
/// back to a different snapshot, a truncated/forked ledger, a swapped state DB,
/// and (must-fix #1) a restore whose target absolute path differs from the one
/// baked into the Iceberg metadata — which would resolve no data despite every
/// per-file digest matching. Empty vec == the image binds to the recorded point.
pub fn verify_backup_binding(m: &BackupManifest, obs: &ObservedCoords) -> Vec<BackupFinding> {
    let mut out = Vec::new();
    if obs.warehouse_snapshot_id != m.warehouse.current_snapshot_id {
        out.push(BackupFinding {
            category: "warehouse_binding".into(),
            coord: "warehouse".into(),
            detail: format!(
                "opened snapshot {} != manifest snapshot {}",
                obs.warehouse_snapshot_id, m.warehouse.current_snapshot_id
            ),
        });
    }
    if !obs.metadata_location_present {
        out.push(BackupFinding {
            category: "warehouse_binding".into(),
            coord: m.warehouse.metadata_location.clone(),
            detail: "pinned snapshot metadata is absent from the captured entries".into(),
        });
    }
    if obs.warehouse_abs_path != m.warehouse.abs_warehouse_path {
        out.push(BackupFinding {
            category: "path_binding".into(),
            coord: "warehouse".into(),
            detail: format!(
                "restore target warehouse path '{}' differs from the path baked into the \
                 backup ('{}') — Iceberg data locations are absolute, so restore here would \
                 resolve no data. Restore to the original path (or use an explicit rewrite).",
                obs.warehouse_abs_path, m.warehouse.abs_warehouse_path
            ),
        });
    }
    if obs.ledger_head_seq != m.ledger.head_seq {
        out.push(BackupFinding {
            category: "ledger_binding".into(),
            coord: "ledger".into(),
            detail: format!(
                "verified head_seq {} != manifest head_seq {}",
                obs.ledger_head_seq, m.ledger.head_seq
            ),
        });
    }
    if obs.ledger_last_hash != m.ledger.last_record_hash {
        out.push(BackupFinding {
            category: "ledger_binding".into(),
            coord: "ledger".into(),
            detail: "verified ledger head hash != manifest last_record_hash".into(),
        });
    }
    if obs.state_digest != m.state.digest {
        out.push(BackupFinding {
            category: "state_binding".into(),
            coord: "state".into(),
            detail: "staged state-DB digest != manifest state digest".into(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn entry(path: &str, kind: BackupEntryKind, digest: &str) -> BackupEntry {
        BackupEntry {
            path: path.into(),
            kind,
            digest: digest.into(),
            size_bytes: 1,
        }
    }

    fn manifest() -> BackupManifest {
        BackupManifest {
            format_version: BACKUP_FORMAT,
            node_id: "garmr-1".into(),
            mode: "offline_quiesced".into(),
            integrity: "verified".into(),
            warehouse: WarehouseCoord {
                current_snapshot_id: 7,
                metadata_location: "warehouse/metadata/v3.metadata.json".into(),
                metadata_digest: "md".into(),
                abs_warehouse_path: "/data/garmr/warehouse".into(),
            },
            ledger: LedgerCoord {
                head_seq: 42,
                last_record_hash: "hh".into(),
                last_checkpoint_seq: 40,
            },
            state: StateCoord {
                kind: "redb_file".into(),
                digest: "sd".into(),
                len: 4096,
            },
            entries: vec![
                entry(
                    "warehouse/data/a.parquet",
                    BackupEntryKind::WarehouseData,
                    "d1",
                ),
                entry("state/state.redb", BackupEntryKind::StateDb, "sd"),
            ],
            ..Default::default()
        }
    }

    fn observed(m: &BackupManifest) -> ObservedCoords {
        ObservedCoords {
            warehouse_snapshot_id: m.warehouse.current_snapshot_id,
            warehouse_abs_path: m.warehouse.abs_warehouse_path.clone(),
            metadata_location_present: true,
            ledger_head_seq: m.ledger.head_seq,
            ledger_last_hash: m.ledger.last_record_hash.clone(),
            state_digest: m.state.digest.clone(),
        }
    }

    #[test]
    fn empty_object_decodes() {
        let _: SignedBackup = serde_json::from_str("{}").unwrap();
        let _: BackupManifest = serde_json::from_str("{}").unwrap();
    }

    #[test]
    fn manifest_digest_is_walk_order_independent_but_content_sensitive() {
        let a = manifest();
        let mut b = manifest();
        b.entries.reverse();
        assert_eq!(manifest_digest(&a), manifest_digest(&b));
        let mut c = manifest();
        c.entries[0].digest = "TAMPERED".into();
        assert_ne!(manifest_digest(&a), manifest_digest(&c));
    }

    #[test]
    fn manifest_digest_binds_every_coordinate() {
        let base = manifest();
        for mutate in [
            |m: &mut BackupManifest| m.warehouse.current_snapshot_id = 9,
            |m: &mut BackupManifest| m.warehouse.abs_warehouse_path = "/other".into(),
            |m: &mut BackupManifest| m.warehouse.metadata_digest = "x".into(),
            |m: &mut BackupManifest| m.ledger.head_seq = 99,
            |m: &mut BackupManifest| m.ledger.last_record_hash = "x".into(),
            |m: &mut BackupManifest| m.state.digest = "x".into(),
            |m: &mut BackupManifest| m.mode = "fs_snapshot".into(),
            |m: &mut BackupManifest| m.integrity = "degraded".into(),
        ] {
            let mut c = base.clone();
            mutate(&mut c);
            assert_ne!(
                manifest_digest(&base),
                manifest_digest(&c),
                "a coordinate change must change the manifest digest"
            );
        }
    }

    #[test]
    fn framing_is_injective() {
        let m1 = BackupManifest {
            node_id: "a".into(),
            garmr_version: "bc".into(),
            ..Default::default()
        };
        let m2 = BackupManifest {
            node_id: "ab".into(),
            garmr_version: "c".into(),
            ..Default::default()
        };
        assert_ne!(manifest_digest(&m1), manifest_digest(&m2));
    }

    #[test]
    fn digests_flag_missing_mismatch_and_strict_extra() {
        let m = manifest();
        let mut computed = BTreeMap::new();
        computed.insert("warehouse/data/a.parquet".to_string(), "d1".to_string());
        computed.insert("state/state.redb".to_string(), "WRONG".to_string());
        computed.insert("warehouse/data/evil.parquet".to_string(), "x".to_string());
        let f = verify_backup_digests(&m, &computed, true);
        assert!(f.iter().any(|x| x.category == "digest_mismatch"));
        assert!(f
            .iter()
            .any(|x| x.category == "unexpected_file" && x.coord == "warehouse/data/evil.parquet"));
        computed.remove("warehouse/data/a.parquet");
        assert!(verify_backup_digests(&m, &computed, false)
            .iter()
            .any(|x| x.category == "missing_file"));
    }

    #[test]
    fn unsafe_entry_paths_are_rejected() {
        let m = BackupManifest {
            entries: vec![entry("../evil", BackupEntryKind::Other, "d")],
            ..Default::default()
        };
        let f = verify_backup_digests(&m, &BTreeMap::new(), false);
        assert!(f.iter().any(|x| x.category == "unsafe_path"));
    }

    #[test]
    fn binding_holds_when_observed_matches_and_flags_each_drift() {
        let m = manifest();
        assert!(verify_backup_binding(&m, &observed(&m)).is_empty());

        // must-fix #1: a different absolute path is caught even though every
        // per-file digest and the snapshot id would match.
        let mut o = observed(&m);
        o.warehouse_abs_path = "/mnt/usb/warehouse".into();
        assert!(verify_backup_binding(&m, &o)
            .iter()
            .any(|x| x.category == "path_binding"));

        let mut o = observed(&m);
        o.warehouse_snapshot_id = 999;
        assert!(verify_backup_binding(&m, &o)
            .iter()
            .any(|x| x.category == "warehouse_binding"));

        let mut o = observed(&m);
        o.ledger_head_seq = 1;
        assert!(verify_backup_binding(&m, &o)
            .iter()
            .any(|x| x.category == "ledger_binding"));

        let mut o = observed(&m);
        o.state_digest = "different".into();
        assert!(verify_backup_binding(&m, &o)
            .iter()
            .any(|x| x.category == "state_binding"));

        let mut o = observed(&m);
        o.metadata_location_present = false;
        assert!(verify_backup_binding(&m, &o)
            .iter()
            .any(|x| x.category == "warehouse_binding"));
    }
}
