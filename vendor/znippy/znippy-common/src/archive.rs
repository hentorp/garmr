//! ZnippyArchive — trait and implementation for reading znippy archives.
//!
//! Provides selective file extraction by path (serve individual artifacts
//! on demand from a single .znippy archive).

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow};
use arrow::record_batch::RecordBatch;
use arrow_array::{BooleanArray, StringArray, UInt64Array};

use crate::codec;
use crate::index::read_znippy_index;
use crate::views::{
    CondaView, DebView, GemView, MavenView, NpmView, PythonView, RpmView, RustView,
    build_conda_view, build_deb_view, build_gem_view, build_maven_view, build_npm_view,
    build_python_view, build_rpm_view, build_rust_view,
};

/// Trait for reading from a znippy archive.
pub trait ZnippyReader: Send + Sync {
    fn list_files(&self) -> Result<Vec<String>>;
    fn extract_file(&self, relative_path: &str) -> Result<Vec<u8>>;
    fn contains(&self, relative_path: &str) -> bool;
    fn file_size(&self, relative_path: &str) -> Option<u64>;

    /// Batch extract multiple files. Default impl calls extract_file sequentially.
    fn extract_files(&self, paths: &[&str]) -> Vec<Result<Vec<u8>>> {
        paths.iter().map(|p| self.extract_file(p)).collect()
    }
}

struct ChunkInfo {
    blob_offset: u64,
    blob_size: u64,
    fdata_offset: u64,
    compressed: bool,
}

struct FileEntry {
    uncompressed_size: u64,
    chunks: Vec<ChunkInfo>,
}

/// A znippy archive opened for random-access reads.
/// Loads only the Arrow IPC index on open; blobs are pread on demand. The
/// archive fd is shared (`Arc<File>`) and read via positioned I/O, so
/// `extract_file` is safe to call concurrently from many threads.
pub struct ZnippyArchive {
    archive: Arc<File>,
    file_index: HashMap<String, FileEntry>,
    /// Archive path — kept so the typed views can do the one-time filtered
    /// sub-index read at view construction.
    path: PathBuf,
    /// Per-`pkg_type` typed view caches. Built once on first `as_*()` call and
    /// reused (the HARD perf contract: repeated `as_maven()` is free). `None`
    /// inside the `Option` means "no sub-index of that type in this archive".
    rust_view: OnceLock<Option<RustView>>,
    maven_view: OnceLock<Option<MavenView>>,
    python_view: OnceLock<Option<PythonView>>,
    npm_view: OnceLock<Option<NpmView>>,
    gem_view: OnceLock<Option<GemView>>,
    conda_view: OnceLock<Option<CondaView>>,
    rpm_view: OnceLock<Option<RpmView>>,
    deb_view: OnceLock<Option<DebView>>,
}

impl ZnippyArchive {
    pub fn open(path: &Path) -> Result<Self> {
        let (_, batches) = read_znippy_index(path)?;
        let file_index = Self::build_file_index(&batches)?;
        let archive = Arc::new(File::open(path)?);
        Ok(Self {
            archive,
            file_index,
            path: path.to_path_buf(),
            rust_view: OnceLock::new(),
            maven_view: OnceLock::new(),
            python_view: OnceLock::new(),
            npm_view: OnceLock::new(),
            gem_view: OnceLock::new(),
            conda_view: OnceLock::new(),
            rpm_view: OnceLock::new(),
            deb_view: OnceLock::new(),
        })
    }

    pub fn file_count(&self) -> usize {
        self.file_index.len()
    }

    /// Typed **rust/cargo** view of this archive (coords → crate). Built ONCE on
    /// first call from the rust sub-index and cached; subsequent calls are free.
    /// Returns `None` if the archive has no rust sub-index.
    pub fn as_rust(&self) -> Option<&RustView> {
        self.rust_view
            .get_or_init(|| build_rust_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    /// Typed **maven** view (GAV[+classifier] → artifact). Built ONCE and cached.
    /// Returns `None` if the archive has no maven sub-index.
    pub fn as_maven(&self) -> Option<&MavenView> {
        self.maven_view
            .get_or_init(|| build_maven_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    /// Typed **python** view (name, version → wheel/sdist). Built ONCE and cached.
    /// Returns `None` if the archive has no python sub-index.
    pub fn as_python(&self) -> Option<&PythonView> {
        self.python_view
            .get_or_init(|| {
                build_python_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None)
            })
            .as_ref()
    }

    /// Typed **npm** view (name[, incl. @scope], version → tarball). Built ONCE
    /// and cached. Returns `None` if the archive has no npm sub-index.
    pub fn as_npm(&self) -> Option<&NpmView> {
        self.npm_view
            .get_or_init(|| build_npm_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    /// Typed **gem** view (name, version[, platform] → gem). Built ONCE and
    /// cached. Returns `None` if the archive has no gem sub-index.
    pub fn as_gem(&self) -> Option<&GemView> {
        self.gem_view
            .get_or_init(|| build_gem_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    /// Typed **conda** view (name, version[, build, subdir] → package). Built ONCE
    /// and cached. Returns `None` if the archive has no conda sub-index.
    pub fn as_conda(&self) -> Option<&CondaView> {
        self.conda_view
            .get_or_init(|| build_conda_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    /// Typed **rpm** view (name, version, release, arch → rpm; authoritative
    /// NEVRA incl. `epoch` from the header). Built ONCE and cached. Returns `None`
    /// if the archive has no rpm sub-index.
    pub fn as_rpm(&self) -> Option<&RpmView> {
        self.rpm_view
            .get_or_init(|| build_rpm_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    /// Typed **deb** view (name, version, arch → deb; authoritative coords + the
    /// raw `control` stanza). Built ONCE and cached. Returns `None` if the archive
    /// has no deb sub-index.
    pub fn as_deb(&self) -> Option<&DebView> {
        self.deb_view
            .get_or_init(|| build_deb_view(&self.path, Arc::clone(&self.archive)).unwrap_or(None))
            .as_ref()
    }

    fn build_file_index(batches: &[RecordBatch]) -> Result<HashMap<String, FileEntry>> {
        let mut index: HashMap<String, FileEntry> = HashMap::new();

        for batch in batches {
            let paths = batch
                .column_by_name("relative_path")
                .ok_or_else(|| anyhow!("missing relative_path column"))?
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| anyhow!("relative_path not StringArray"))?;
            let compressed_col = batch
                .column_by_name("compressed")
                .ok_or_else(|| anyhow!("missing compressed column"))?
                .as_any()
                .downcast_ref::<BooleanArray>()
                .ok_or_else(|| anyhow!("compressed not BooleanArray"))?;
            let sizes = batch
                .column_by_name("uncompressed_size")
                .ok_or_else(|| anyhow!("missing uncompressed_size column"))?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| anyhow!("uncompressed_size not UInt64Array"))?;
            let blob_offset_col = batch
                .column_by_name("blob_offset")
                .ok_or_else(|| anyhow!("missing blob_offset column"))?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| anyhow!("blob_offset not UInt64Array"))?;
            let blob_size_col = batch
                .column_by_name("blob_size")
                .ok_or_else(|| anyhow!("missing blob_size column"))?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| anyhow!("blob_size not UInt64Array"))?;
            let fdata_offset_col = batch
                .column_by_name("fdata_offset")
                .ok_or_else(|| anyhow!("missing fdata_offset column"))?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| anyhow!("fdata_offset not UInt64Array"))?;

            for row in 0..batch.num_rows() {
                let path = paths.value(row).to_string();
                let compressed = compressed_col.value(row);
                let uncompressed_size = sizes.value(row);
                let blob_offset = blob_offset_col.value(row);
                let blob_size = blob_size_col.value(row);
                let fdata_offset = fdata_offset_col.value(row);

                let entry = index.entry(path).or_insert_with(|| FileEntry {
                    uncompressed_size: 0,
                    chunks: Vec::new(),
                });
                entry.uncompressed_size += uncompressed_size;
                entry.chunks.push(ChunkInfo {
                    blob_offset,
                    blob_size,
                    fdata_offset,
                    compressed,
                });
            }
        }

        for entry in index.values_mut() {
            entry.chunks.sort_by_key(|c| c.fdata_offset);
        }

        Ok(index)
    }
}

impl ZnippyReader for ZnippyArchive {
    fn list_files(&self) -> Result<Vec<String>> {
        Ok(self.file_index.keys().cloned().collect())
    }

    fn extract_file(&self, relative_path: &str) -> Result<Vec<u8>> {
        let entry = self
            .file_index
            .get(relative_path)
            .ok_or_else(|| anyhow!("file not found in archive: {}", relative_path))?;

        let mut result = Vec::with_capacity(entry.uncompressed_size as usize);
        let mut blob = Vec::new(); // reused across chunks
        let mut decomp = Vec::new(); // reused across compressed chunks

        for chunk in &entry.chunks {
            blob.resize(chunk.blob_size as usize, 0);
            // Positioned read — no shared seek, safe under concurrent calls.
            self.archive.read_exact_at(&mut blob, chunk.blob_offset)?;

            if chunk.compressed {
                codec::decompress_into(&blob, &mut decomp)?;
                result.extend_from_slice(&decomp);
            } else {
                result.extend_from_slice(&blob);
            }
        }

        Ok(result)
    }

    fn contains(&self, relative_path: &str) -> bool {
        self.file_index.contains_key(relative_path)
    }

    fn file_size(&self, relative_path: &str) -> Option<u64> {
        self.file_index
            .get(relative_path)
            .map(|e| e.uncompressed_size)
    }
}
