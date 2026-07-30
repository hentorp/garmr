// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Cold archivers: seal a window's parquet payload into an immutable archive,
//! and thaw it back out. Two backends behind one trait.
//!
//! - [`PlainArchiver`] (always available): the parquet file *is* the archive —
//!   zstd-compressed columnar bytes on disk, pure Rust, no C toolchain.
//! - [`ZnippyArchiver`] (feature `znippy`): seals the parquet into a
//!   content-addressed znippy archive (Arrow-IPC manifest + BLAKE3 blobs,
//!   readable by DuckDB / Polars / DataFusion via the znippy tooling).
//!
//! Both are content-addressed by a BLAKE3 hash of the archive file; the manifest
//! stores that hash so a thaw can verify the bytes it read.

use std::path::Path;

use garmr_core::{ColdArchiverKind, Error, Result};

/// The single member name every archive stores its parquet payload under.
pub const MEMBER: &str = "events.parquet";

/// Result of sealing a window.
pub struct SealOutcome {
    /// Archive size on disk.
    pub bytes_out: u64,
    /// BLAKE3 hex of the archive file.
    pub checksum: String,
}

/// Seal + thaw a single window's parquet payload.
pub trait ColdArchiver: Send + Sync {
    /// Which kind this is (recorded in the manifest so a thaw picks the matching
    /// reader even if the configured archiver later changes).
    fn kind(&self) -> ColdArchiverKind;
    /// File extension for archives this produces (no dot).
    fn extension(&self) -> &'static str;
    /// Seal `parquet` into `out`, returning its on-disk size and checksum.
    /// Takes the buffer by value so a whole window isn't duplicated in RAM.
    fn seal(&self, out: &Path, parquet: Vec<u8>) -> Result<SealOutcome>;
    /// Seal a parquet payload that already lives on disk — streamed there by the
    /// retention writer so the raw window never sits in RAM — into `out`. The
    /// default reads the file and delegates to [`seal`](Self::seal) (RAM bounded
    /// to the *compressed* parquet, not the raw Arrow window). Backends where
    /// the parquet file *is* the archive override this to avoid the read.
    fn seal_file(&self, out: &Path, parquet_path: &Path) -> Result<SealOutcome> {
        let bytes = std::fs::read(parquet_path).map_err(Error::store)?;
        self.seal(out, bytes)
    }
    /// Thaw the parquet payload back out of `archive`.
    fn thaw(&self, archive: &Path) -> Result<Vec<u8>>;
}

/// Build the archiver for a kind. Errors clearly if `znippy` is requested but
/// wasn't compiled in.
pub fn make_archiver(
    kind: ColdArchiverKind,
    compression_level: i32,
) -> Result<Box<dyn ColdArchiver>> {
    match kind {
        ColdArchiverKind::Plain => Ok(Box::new(PlainArchiver)),
        ColdArchiverKind::Znippy => make_znippy(compression_level),
    }
}

#[cfg(feature = "znippy")]
fn make_znippy(compression_level: i32) -> Result<Box<dyn ColdArchiver>> {
    Ok(Box::new(ZnippyArchiver {
        level: compression_level,
    }))
}

#[cfg(not(feature = "znippy"))]
fn make_znippy(_compression_level: i32) -> Result<Box<dyn ColdArchiver>> {
    Err(Error::store(
        "cold archiver \"znippy\" requested but this binary was built without the `znippy` \
         feature — set retention.archiver = \"plain\" or rebuild with the feature enabled",
    ))
}

/// The parquet file is itself the archive. Pure Rust, no C dependency.
pub struct PlainArchiver;

impl ColdArchiver for PlainArchiver {
    fn kind(&self) -> ColdArchiverKind {
        ColdArchiverKind::Plain
    }
    fn extension(&self) -> &'static str {
        "parquet"
    }
    fn seal(&self, out: &Path, parquet: Vec<u8>) -> Result<SealOutcome> {
        std::fs::write(out, &parquet).map_err(Error::store)?;
        Ok(SealOutcome {
            bytes_out: parquet.len() as u64,
            checksum: blake3_bytes(&parquet),
        })
    }
    fn seal_file(&self, out: &Path, parquet_path: &Path) -> Result<SealOutcome> {
        // The parquet file IS the archive — move it into place; no RAM copy.
        // rename is atomic within a filesystem (staging lives in cold_dir);
        // fall back to copy across a mount boundary.
        if parquet_path != out {
            std::fs::rename(parquet_path, out)
                .or_else(|_| std::fs::copy(parquet_path, out).map(|_| ()))
                .map_err(Error::store)?;
        }
        let bytes_out = std::fs::metadata(out).map_err(Error::store)?.len();
        Ok(SealOutcome {
            bytes_out,
            checksum: blake3_file(out)?,
        })
    }
    fn thaw(&self, archive: &Path) -> Result<Vec<u8>> {
        std::fs::read(archive).map_err(Error::store)
    }
}

/// Content-addressed znippy archive (Arrow-IPC manifest + BLAKE3 blobs).
#[cfg(feature = "znippy")]
pub struct ZnippyArchiver {
    level: i32,
}

#[cfg(feature = "znippy")]
impl ColdArchiver for ZnippyArchiver {
    fn kind(&self) -> ColdArchiverKind {
        ColdArchiverKind::Znippy
    }
    fn extension(&self) -> &'static str {
        "znippy"
    }
    fn seal(&self, out: &Path, parquet: Vec<u8>) -> Result<SealOutcome> {
        let files = [(MEMBER.to_string(), parquet)];
        znippy_common::meta_sink_append::create_archive(out, &files, self.level)
            .map_err(Error::store)?;
        let bytes_out = std::fs::metadata(out).map_err(Error::store)?.len();
        Ok(SealOutcome {
            bytes_out,
            checksum: blake3_file(out)?,
        })
    }
    fn thaw(&self, archive: &Path) -> Result<Vec<u8>> {
        znippy_common::get_file(archive, MEMBER).map_err(Error::store)
    }
}

/// Kind from the string stored in the manifest.
pub fn kind_from_str(s: &str) -> Result<ColdArchiverKind> {
    match s {
        "plain" => Ok(ColdArchiverKind::Plain),
        "znippy" => Ok(ColdArchiverKind::Znippy),
        other => Err(Error::store(format!(
            "unknown cold archiver kind {other:?}"
        ))),
    }
}

/// The manifest string for a kind.
pub fn kind_str(kind: ColdArchiverKind) -> &'static str {
    match kind {
        ColdArchiverKind::Plain => "plain",
        ColdArchiverKind::Znippy => "znippy",
    }
}

fn blake3_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// BLAKE3 hex of a file — what `SealOutcome.checksum` records, and what the
/// thaw path re-computes to verify an archive before trusting its contents.
pub fn blake3_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).map_err(Error::store)?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut f, &mut hasher).map_err(Error::store)?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_round_trips_and_addresses() {
        let dir = std::env::temp_dir().join(format!("garmr-plain-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("w.parquet");
        let payload = b"PAR1-ish parquet bytes".to_vec();
        let a = PlainArchiver;
        let o = a.seal(&out, payload.clone()).unwrap();
        assert_eq!(o.bytes_out, payload.len() as u64);
        assert_eq!(o.checksum, blake3::hash(&payload).to_hex().to_string());
        assert_eq!(a.thaw(&out).unwrap(), payload);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "znippy")]
    #[test]
    fn znippy_round_trips() {
        let dir = std::env::temp_dir().join(format!("garmr-znip-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("w.znippy");
        let payload = b"the quick brown fox failed a password 12 times".to_vec();
        let a = ZnippyArchiver { level: 6 };
        let o = a.seal(&out, payload.clone()).unwrap();
        assert!(o.bytes_out > 0);
        assert_eq!(o.checksum.len(), 64); // blake3 hex
        assert_eq!(a.thaw(&out).unwrap(), payload);
        std::fs::remove_dir_all(&dir).ok();
    }
}
