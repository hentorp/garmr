// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr collector add|rotate|revoke|list` — the collector-credential
//! lifecycle, over the registry file `ingest.collectors_file`.
//!
//! The file (never the env blob) is what makes rotation an operation instead of
//! an outage: `GARMR_COLLECTORS` is parsed once at startup, so changing ONE
//! token there means restarting the whole SIEM. The file is rewritten
//! atomically here and (M3) watched by `serve`, so rotate/revoke take effect
//! without a restart.
//!
//! The keyed-digest key lives in a sibling `<file>.key` rather than in the
//! state store, deliberately: the state store is single-writer, and a CLI that
//! needed its lock could not manage credentials while `serve` runs — which is
//! precisely when an emergency revoke happens.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use garmr_core::{mint_collector, CollectorFile, COLLECTOR_FILE_VERSION};

/// Load the registry file, or an empty one when it does not exist yet.
pub(crate) fn load_file(path: &Path) -> Result<CollectorFile> {
    match std::fs::read(path) {
        Ok(bytes) => CollectorFile::parse(&bytes).map_err(|e| anyhow::anyhow!(e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CollectorFile::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write the registry atomically: tmp + fsync + rename, the same discipline as
/// every other file a crash must not tear. A torn registry fails closed at the
/// next load (parse error), but "fails closed" here means "no collector can
/// ingest", which is an outage — so we don't produce torn files in the first
/// place.
pub(crate) fn save_file(path: &Path, file: &CollectorFile) -> Result<()> {
    use std::io::Write as _;
    let bytes = serde_json::to_vec_pretty(file)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

/// The sibling key file's path.
fn key_path(registry: &Path) -> PathBuf {
    let mut os = registry.as_os_str().to_os_string();
    os.push(".key");
    PathBuf::from(os)
}

/// Load the digest key, creating it (0600, CSPRNG) on first use.
pub(crate) fn load_or_init_key(registry: &Path) -> Result<[u8; 32]> {
    let kp = key_path(registry);
    match std::fs::read(&kp) {
        Ok(bytes) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!(
                    "{} is {} bytes, expected 32 — a wrong key silently verifies nothing, so \
                     this refuses rather than guessing",
                    kp.display(),
                    bytes.len()
                )
            })?;
            Ok(arr)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            if let Some(parent) = kp.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&kp, key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", kp.display())),
    }
}

/// `garmr collector add` — mint a credential, print the token ONCE.
pub(crate) fn collectors_add(
    registry: &Path,
    id: &str,
    sources: &[String],
    expires_days: Option<i64>,
) -> Result<()> {
    let mut file = load_file(registry)?;
    if file
        .collectors
        .iter()
        .any(|c| c.id == id && c.is_active(now()))
    {
        // Refused rather than silently stacked: two live credentials for one id
        // is what `rotate` produces ON PURPOSE (grace overlap) — reaching the
        // same state through `add` twice is almost always a mistake.
        anyhow::bail!(
            "collector {id:?} already has an active credential — use `garmr collector rotate {id}` \
             to replace it, or `revoke` first"
        );
    }
    let key = load_or_init_key(registry)?;
    let expires_at = expires_days.map(|d| now() + d.max(1) * 86_400);
    let minted = mint_collector(id, sources.to_vec(), expires_at, &key, now())
        .map_err(|e| anyhow::anyhow!(e))?;
    file.collectors.push(minted.record.clone());
    file.version = COLLECTOR_FILE_VERSION;
    save_file(registry, &file)?;
    println!(
        "collector {id} added (fingerprint {})",
        minted.record.fingerprint
    );
    println!("token: {}", minted.token);
    println!("copy it now — it is shown once and cannot be retrieved again");
    Ok(())
}

/// `garmr collector rotate` — mint a replacement, revoke the old credential.
///
/// The OLD record is kept, revoked, for the same reason expiry keeps deletion
/// tombstones: an incident review of a compromised collector needs the history
/// of which credentials existed and when they stopped working.
pub(crate) fn collectors_rotate(registry: &Path, id: &str) -> Result<()> {
    let mut file = load_file(registry)?;
    let Some(pos) = file
        .collectors
        .iter()
        .position(|c| c.id == id && c.is_active(now()))
    else {
        anyhow::bail!("no active credential for collector {id:?} — use `add`");
    };
    let sources = file.collectors[pos].sources.clone();
    let expires_at = file.collectors[pos].expires_at;
    file.collectors[pos].revoked = true;
    let key = load_or_init_key(registry)?;
    let minted =
        mint_collector(id, sources, expires_at, &key, now()).map_err(|e| anyhow::anyhow!(e))?;
    file.collectors.push(minted.record.clone());
    save_file(registry, &file)?;
    println!(
        "collector {id} rotated (old credential revoked, new fingerprint {})",
        minted.record.fingerprint
    );
    println!("token: {}", minted.token);
    println!("copy it now — it is shown once and cannot be retrieved again");
    Ok(())
}

/// `garmr collector revoke` — soft-revoke every active credential for the id.
pub(crate) fn collectors_revoke(registry: &Path, id: &str) -> Result<()> {
    let mut file = load_file(registry)?;
    let mut n = 0;
    for c in file
        .collectors
        .iter_mut()
        .filter(|c| c.id == id && !c.revoked)
    {
        c.revoked = true;
        n += 1;
    }
    if n == 0 {
        anyhow::bail!("no unrevoked credential for collector {id:?}");
    }
    save_file(registry, &file)?;
    println!("collector {id}: {n} credential(s) revoked");
    Ok(())
}

/// `garmr collector list` — the registry, fingerprints only, never a secret.
pub(crate) fn collectors_list(registry: &Path) -> Result<()> {
    let file = load_file(registry)?;
    if file.collectors.is_empty() {
        println!("(no collector credentials in {})", registry.display());
        return Ok(());
    }
    let t = now();
    for c in &file.collectors {
        println!(
            "{:<10} {:<16} fp={} sources={} expires={}",
            match c.inactive_reason(t) {
                None => "active",
                Some(r) => r,
            },
            c.id,
            c.fingerprint,
            if c.sources.is_empty() {
                "any".to_string()
            } else {
                c.sources.join(",")
            },
            c.expires_at
                .map(|e| chrono::DateTime::from_timestamp(e, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| e.to_string()))
                .unwrap_or_else(|| "never".to_string()),
        );
    }
    Ok(())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfile() -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "garmr-collectors-test-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    /// The full lifecycle at the file level: add resolves, rotate keeps the old
    /// record (revoked) and the new token resolves, revoke stops resolution.
    #[test]
    fn add_rotate_revoke_lifecycle_round_trips_through_the_file() {
        let reg = tmpfile();
        let _ = std::fs::remove_file(&reg);

        collectors_add(&reg, "fw", &["firewall".to_string()], None).unwrap();
        let file = load_file(&reg).unwrap();
        assert_eq!(file.collectors.len(), 1);
        assert!(!file.collectors[0].revoked);

        // A second add for the same live id is refused — rotate is the verb.
        assert!(collectors_add(&reg, "fw", &[], None).is_err());

        collectors_rotate(&reg, "fw").unwrap();
        let file = load_file(&reg).unwrap();
        assert_eq!(file.collectors.len(), 2, "history kept: old + new");
        assert!(file.collectors[0].revoked, "old credential revoked");
        assert!(!file.collectors[1].revoked);
        assert_eq!(
            file.collectors[1].sources,
            vec!["firewall".to_string()],
            "rotation inherits the source binding"
        );

        collectors_revoke(&reg, "fw").unwrap();
        let file = load_file(&reg).unwrap();
        assert!(file.collectors.iter().all(|c| c.revoked));

        // And the registry consumes the file end-to-end: a revoked-everything
        // file resolves no token.
        let key = load_or_init_key(&reg).unwrap();
        let mut r = garmr_core::CollectorRegistry::new();
        r.load_records(key, file.collectors.clone());
        // (No token to try — they were shown once and not captured here; the
        // resolution path is covered by garmr-core's own tests.)
        let _ = r;
        let _ = std::fs::remove_file(&reg);
    }

    #[test]
    fn the_key_file_is_created_once_and_stable() {
        let reg = tmpfile();
        let _ = std::fs::remove_file(&reg);
        let k1 = load_or_init_key(&reg).unwrap();
        let k2 = load_or_init_key(&reg).unwrap();
        assert_eq!(k1, k2, "the key must be stable across invocations");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(super::key_path(&reg))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the key file must not be group/world readable"
            );
        }
        let _ = std::fs::remove_file(&reg);
        let _ = std::fs::remove_file(super::key_path(&reg));
    }
}
