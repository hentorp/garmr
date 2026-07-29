// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Config-write persistence: the generated override layer plus a versioned
//! revision history. This is what lets an operator change settings from the
//! console — preview the diff and restart impact, apply atomically, and roll
//! back — without ever editing the operator-owned base `garmr.toml`.
//!
//! Precedence (see [`garmr_core::Config::load`]): `defaults < base TOML <
//! override < env`. The override file lives in the service-writable state dir
//! (`garmr.override.toml`, a sibling of `store.state_db`); revisions live beside
//! it under `config-revisions/`. `GARMR_AIRGAP` is env-only and never in this
//! chain, so a persisted override can never disable airgap.
//!
//! A revision is the FULL override document (not a delta) plus provenance, so
//! rollback is just re-applying an older body and every applied state is
//! reproducible from a single file. Writes are atomic (temp + rename).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// The base config file path this process was started with. Set once at startup
/// (single-threaded, before the runtime) so the config-write API can re-run the
/// figment merge (`base < proposed override < env`) for validate/apply without
/// threading the path through every layer. A genuine process singleton — one
/// config file per process — matching the existing egress-policy global.
static BASE_CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Record the base config path (idempotent; the first set wins).
pub fn set_base_config_path(path: PathBuf) {
    let _ = BASE_CONFIG_PATH.set(path);
}

/// The base config path, or `garmr.toml` if it was never set (e.g. a subcommand
/// that never loads config — the config-write API is only reachable from serve,
/// which always sets it).
pub fn base_config_path() -> PathBuf {
    BASE_CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("garmr.toml"))
}

/// The override path the LOADER reads (resolved from base+env at startup, before
/// any override could relocate it). The write API reads this so the file it
/// writes is provably the file `Config::load` reads — never the merged-config
/// derivation, which could diverge if an out-of-band override moved `state_db`.
static OVERRIDE_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Record the loader's override path (idempotent; first set wins).
pub fn set_override_path(path: PathBuf) {
    let _ = OVERRIDE_PATH.set(path);
}

/// The loader's override path, if it was resolved at startup.
pub fn override_path() -> Option<PathBuf> {
    OVERRIDE_PATH.get().cloned()
}

/// blake3 hash of the override that was loaded at process startup. Compared
/// against the current on-disk override to detect a persisted-but-not-yet-loaded
/// config change (a restart is pending). Set once at startup.
static STARTUP_OVERRIDE_HASH: OnceLock<String> = OnceLock::new();

/// Hex blake3 of an override body (empty body hashes to a stable value).
pub fn override_hash(body: &str) -> String {
    blake3::hash(body.as_bytes()).to_hex().to_string()
}

/// Record the hash of the override the process started with (idempotent).
pub fn set_startup_override_hash(hash: String) {
    let _ = STARTUP_OVERRIDE_HASH.set(hash);
}

/// True when the persisted override differs from what this process loaded at
/// startup — i.e. a config apply/rollback is persisted but a restart is needed to
/// load it. `false` when the startup hash was never recorded (non-serve command).
pub fn restart_pending() -> bool {
    let Some(startup) = STARTUP_OVERRIDE_HASH.get() else {
        return false;
    };
    let current = override_path()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .unwrap_or_default();
    &override_hash(&current) != startup
}

/// One persisted config revision: the exact override document it installs plus
/// who/when/why and a hash chain to its parent (tamper-evident ordering).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    /// Monotonic sequence (1-based); the active override is always the latest.
    pub seq: u64,
    /// Unix seconds when applied.
    pub ts: i64,
    /// Principal that applied it (from the authenticated request).
    pub author: String,
    /// Human summary: "apply", "rollback to revision N", …
    pub note: String,
    /// blake3 of the parent revision's `body` ("" for the first revision).
    pub parent_hash: String,
    /// blake3 of this revision's `body` (hex).
    pub hash: String,
    /// The override TOML this revision installs verbatim.
    pub body: String,
}

impl Revision {
    /// Short display hash (first 8 hex chars), matching the secret-fingerprint style.
    pub fn short_hash(&self) -> String {
        self.hash.chars().take(8).collect()
    }
}

/// Reads and writes the override file + its revision history. Cheap to construct;
/// holds no open handles.
pub struct RevisionStore {
    /// The active override file `Config::load` reads.
    override_path: PathBuf,
    /// `config-revisions/` beside the override file.
    dir: PathBuf,
}

impl RevisionStore {
    /// Build a store for the given active override path (from
    /// [`garmr_core::Config::config_override_path`]).
    pub fn new(override_path: PathBuf) -> Self {
        let dir = override_path
            .parent()
            .map(|p| p.join("config-revisions"))
            .unwrap_or_else(|| PathBuf::from("config-revisions"));
        Self { override_path, dir }
    }

    /// The currently active override body (`""` if none has ever been written).
    pub fn active_override(&self) -> String {
        std::fs::read_to_string(&self.override_path).unwrap_or_default()
    }

    /// All revisions, ascending by `seq`. Unreadable/malformed files are skipped
    /// for DISPLAY only — seq allocation uses [`next_seq`](Self::next_seq) (derived
    /// from filenames), so a skipped/corrupt tail file can never rewind the counter
    /// and clobber history.
    pub fn list(&self) -> Vec<Revision> {
        let mut out: Vec<Revision> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(rev) = serde_json::from_slice::<Revision>(&bytes) {
                        out.push(rev);
                    }
                }
            }
        }
        out.sort_by_key(|r| r.seq);
        out
    }

    /// The most recent revision, if any.
    pub fn latest(&self) -> Option<Revision> {
        self.list().into_iter().max_by_key(|r| r.seq)
    }

    /// Fetch a specific revision by sequence.
    pub fn get(&self, seq: u64) -> Option<Revision> {
        self.list().into_iter().find(|r| r.seq == seq)
    }

    /// The next sequence number, derived from revision FILENAMES (not parsed
    /// content) so a corrupt/torn tail file cannot rewind the counter.
    fn next_seq(&self) -> u64 {
        let mut max = 0u64;
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Some(n) = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    max = max.max(n);
                }
            }
        }
        max + 1
    }

    /// Persist `body` as the new active override and append a revision record.
    /// Process-wide serialized: seq allocation + both file writes are atomic w.r.t.
    /// a concurrent apply. The caller must have VALIDATED `body` first.
    pub fn apply(&self, body: String, author: &str, note: &str, now: i64) -> io::Result<Revision> {
        // One config write at a time process-wide. Without this two applies can
        // read the same seq, write the same revision file, and (with the old shared
        // temp name) tear the override file into an unparseable state.
        let _guard = apply_lock();
        std::fs::create_dir_all(&self.dir)?;
        let seq = self.next_seq();
        let parent_hash = self.latest().map(|r| r.hash).unwrap_or_default();
        let hash = blake3::hash(body.as_bytes()).to_hex().to_string();
        let rev = Revision {
            seq,
            ts: now,
            author: author.to_string(),
            note: note.to_string(),
            parent_hash,
            hash,
            body: body.clone(),
        };
        let rev_json = serde_json::to_vec_pretty(&rev)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // Create the revision record EXCLUSIVELY (belt-and-suspenders beyond the
        // lock): a seq collision fails loudly rather than clobbering an existing
        // record. Written before the override swap, so a failure leaves the live
        // precedence unchanged.
        write_new_private(&self.dir.join(format!("{seq:08}.json")), &rev_json)?;
        // Then swap the active override the loader reads.
        write_atomic(&self.override_path, body.as_bytes())?;
        Ok(rev)
    }

    /// Re-apply the body of an earlier revision as a NEW revision (linear history,
    /// never rewrites the past). Errors if `target_seq` doesn't exist.
    pub fn rollback(&self, target_seq: u64, author: &str, now: i64) -> io::Result<Revision> {
        let target = self.get(target_seq).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no config revision {target_seq}"),
            )
        })?;
        let note = format!("rollback to revision {target_seq}");
        self.apply(target.body, author, &note, now)
    }
}

/// Process-wide config-write lock: serializes apply/rollback so seq allocation and
/// the file writes never interleave with a concurrent writer.
fn apply_lock() -> std::sync::MutexGuard<'static, ()> {
    static APPLY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    APPLY_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A per-process-unique temp suffix (pid + monotonic counter) so two atomic writes
/// never share a temp path (which would tear each other's content).
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!("{}.{}", std::process::id(), CTR.fetch_add(1, Ordering::Relaxed))
}

/// fsync the file's parent directory so a create/rename is durable — POSIX does
/// not guarantee the directory entry survives a crash otherwise (the same class of
/// gap as the prior 0-byte-manifest incident).
fn fsync_parent(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Create a NEW private (0600) file exclusively, write, fsync it and its parent.
/// Fails if the path already exists (the seq-collision guard).
fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fsync_parent(path)
}

/// Replace `path` atomically with private (0600) content: a uniquely-named sibling
/// temp, fsync, rename, then fsync the parent dir. 0600 because a config body CAN
/// carry a secret-bearing leaf (e.g. an MCP-server env token or a credentialed
/// URL); the file lives in the service-private state dir and `Config::load` reads
/// it as the same user.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("override");
    let tmp = dir.join(format!(".{name}.{}.tmp", unique_suffix()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    fsync_parent(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tmp: &Path) -> RevisionStore {
        RevisionStore::new(tmp.join("garmr.override.toml"))
    }

    #[test]
    fn apply_appends_linear_hash_chained_revisions() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        assert!(s.list().is_empty());
        assert_eq!(s.active_override(), "");

        let r1 = s.apply("a = 1\n".into(), "operator", "apply", 100).unwrap();
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.parent_hash, "");
        assert_eq!(s.active_override(), "a = 1\n");

        let r2 = s.apply("a = 2\n".into(), "operator", "apply", 200).unwrap();
        assert_eq!(r2.seq, 2);
        // The chain links r2 back to r1.
        assert_eq!(r2.parent_hash, r1.hash);
        assert_eq!(s.active_override(), "a = 2\n");
        assert_eq!(s.list().len(), 2);
    }

    #[test]
    fn rollback_reapplies_old_body_as_new_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.apply("a = 1\n".into(), "op", "apply", 1).unwrap();
        s.apply("a = 2\n".into(), "op", "apply", 2).unwrap();

        let r3 = s.rollback(1, "op", 3).unwrap();
        assert_eq!(r3.seq, 3);
        assert_eq!(r3.note, "rollback to revision 1");
        // History is linear (nothing rewritten) and the live override is r1's body.
        assert_eq!(r3.body, "a = 1\n");
        assert_eq!(s.active_override(), "a = 1\n");
        assert_eq!(s.list().len(), 3);
    }

    #[test]
    fn rollback_to_missing_revision_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        assert!(s.rollback(9, "op", 1).is_err());
    }
}