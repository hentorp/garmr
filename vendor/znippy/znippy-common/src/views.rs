//! Typed specialized package views — the READ side of the plugin contract.
//!
//! A znippy plugin writes per-ecosystem metadata into Arrow columns at compress
//! time (maven: `group_id`/`artifact_id`/`version`; python: `name`/`version`;
//! rust: `crate_name`/`version`), discriminated by `pkg_type`. This module is the
//! symmetric READ side: it turns those columns back into a typed, coord-addressed
//! view so consumers never re-derive coordinates by parsing file paths.
//!
//! ## Performance contract (HARD)
//!
//! 1. **The coord index is built ONCE**, at view construction, via
//!    [`read_znippy_index_filtered`](crate::read_znippy_index_filtered) with an
//!    [`IndexFilter`](crate::IndexFilter) pinned to the plugin's `pkg_type` — so
//!    only that one sub-index stream is read and parsed. The result is a
//!    `HashMap<Key, FileLoc>` interned into the view; the holder ([`ZnippyArchive`])
//!    caches it behind a `OnceLock` per `pkg_type`, so repeated `as_maven()` is free.
//! 2. **`get(coords)` is an O(1) map lookup** returning a lightweight handle
//!    ([`Package`]): coords + a borrowed `FileLoc` + the shared fd. No scan, no
//!    Arrow re-parse, no decompression, no bytes copied.
//! 3. **Bytes are LAZY** — [`Package::bytes`] is the only thing that preads the
//!    blob(s) and decompresses (the same loop as [`crate::ZnippyArchive::extract_file`]),
//!    and only when called. A `fetch` that only needs existence/size never decompresses.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use arrow::array::{Array, StringArray};
use arrow::record_batch::RecordBatch;

use crate::codec;
use crate::index::{IndexFilter, read_znippy_index_filtered};

// ─── pkg_type discriminants (single source of truth: each plugin's `type_id()`) ──
//
// These mirror the discriminant each plugin returns from `ArchiveTypePlugin::type_id()`:
//   CargoPlugin::type_id()        == 1   (znippy-common/src/plugins/cargo_native.rs)
//   NativePythonPlugin::type_id() == 2   (znippy-plugin-python)
//   NativeMavenPlugin::type_id()  == 3   (znippy-plugin-maven)
// They live here because `ZnippyArchive` (in this crate) builds the filtered index
// keyed on them, and the maven/python plugin crates depend on this crate (not the
// other way round), so the constant cannot live in those crates without a cycle.

/// `pkg_type` discriminant written by the rust/cargo plugin.
pub const RUST_PKG_TYPE: i8 = 1;
/// `pkg_type` discriminant written by the python plugin.
pub const PYTHON_PKG_TYPE: i8 = 2;
/// `pkg_type` discriminant written by the maven plugin.
pub const MAVEN_PKG_TYPE: i8 = 3;
/// `pkg_type` discriminant written by the npm plugin (`plugins::npm_native`).
pub const NPM_PKG_TYPE: i8 = 6;
/// `pkg_type` discriminant written by the gem plugin (`plugins::gem_native`).
pub const GEM_PKG_TYPE: i8 = 11;
/// `pkg_type` discriminant written by the rpm plugin (`plugins::rpm_native`).
pub const RPM_PKG_TYPE: i8 = 8;
/// `pkg_type` discriminant written by the deb plugin (`plugins::deb_native`).
pub const DEB_PKG_TYPE: i8 = 9;
/// `pkg_type` discriminant written by the conda plugin (`plugins::conda_native`).
pub const CONDA_PKG_TYPE: i8 = 14;

/// One file's chunk locations within the archive blob region — everything needed
/// to pread + decompress its bytes, with **no** path involved. Built from the base
/// index columns on the same rows that carried the coord match.
#[derive(Debug, Clone)]
pub struct FileLoc {
    /// The file's chunks, ordered by `fdata_offset` (concatenation order).
    pub chunks: Vec<ChunkRef>,
    /// Total uncompressed size across all chunks.
    pub uncompressed_size: u64,
}

/// One chunk's blob location.
#[derive(Debug, Clone, Copy)]
pub struct ChunkRef {
    pub blob_offset: u64,
    pub blob_size: u64,
    pub fdata_offset: u64,
    pub compressed: bool,
}

impl FileLoc {
    /// Read + decompress this file's bytes — the lone I/O of the read API.
    /// Reuses the exact pread/decompress loop of [`ZnippyArchive::extract_file`].
    fn read_bytes(&self, archive: &File) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(self.uncompressed_size as usize);
        let mut blob = Vec::new();
        let mut decomp = Vec::new();
        for chunk in &self.chunks {
            blob.resize(chunk.blob_size as usize, 0);
            archive.read_exact_at(&mut blob, chunk.blob_offset)?;
            if chunk.compressed {
                codec::decompress_into(&blob, &mut decomp)?;
                result.extend_from_slice(&decomp);
            } else {
                result.extend_from_slice(&blob);
            }
        }
        Ok(result)
    }
}

/// Project the base location columns of a row into a [`ChunkRef`], appending to a
/// per-file [`FileLoc`] keyed by `relative_path` (so chunked files group correctly).
fn group_rows_by_file(batch: &RecordBatch) -> Result<HashMap<String, FileLoc>> {
    use arrow::array::{BooleanArray, UInt64Array};

    let col = |n: &str| {
        batch
            .column_by_name(n)
            .ok_or_else(|| anyhow!("index missing column {n}"))
    };
    let paths = col("relative_path")?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| anyhow!("relative_path not StringArray"))?;
    let compressed = col("compressed")?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or_else(|| anyhow!("compressed not BooleanArray"))?;
    let sizes = col("uncompressed_size")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| anyhow!("uncompressed_size not UInt64Array"))?;
    let blob_offset = col("blob_offset")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| anyhow!("blob_offset not UInt64Array"))?;
    let blob_size = col("blob_size")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| anyhow!("blob_size not UInt64Array"))?;
    let fdata = col("fdata_offset")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| anyhow!("fdata_offset not UInt64Array"))?;

    let mut by_path: HashMap<String, FileLoc> = HashMap::new();
    for i in 0..batch.num_rows() {
        let path = paths.value(i);
        let entry = by_path.entry(path.to_string()).or_insert_with(|| FileLoc {
            chunks: Vec::new(),
            uncompressed_size: 0,
        });
        entry.uncompressed_size += sizes.value(i);
        entry.chunks.push(ChunkRef {
            blob_offset: blob_offset.value(i),
            blob_size: blob_size.value(i),
            fdata_offset: fdata.value(i),
            compressed: compressed.value(i),
        });
    }
    for f in by_path.values_mut() {
        f.chunks.sort_by_key(|c| c.fdata_offset);
    }
    Ok(by_path)
}

/// A trailing-path-segment helper: the artifact filename of a matched row, used
/// internally to disambiguate multi-artifact coords (maven jar vs pom, classifier).
/// **Never** exposed to callers.
fn file_name(rel_path: &str) -> &str {
    rel_path.rsplit('/').next().unwrap_or(rel_path)
}

// ════════════════════════════════════════════════════════════════════════════
// RUST view
// ════════════════════════════════════════════════════════════════════════════

/// `(name, version)` key for the rust coord index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RustKey {
    name: String,
    version: String,
}

/// Typed view over the rust (cargo) sub-index. Built once; `get` is O(1).
pub struct RustView {
    archive: Arc<File>,
    coords: HashMap<RustKey, FileLoc>,
}

/// A handle to one crate. Coords are authoritative (read from the columns).
/// Bytes are lazy — call [`RustPackage::bytes`].
pub struct RustPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
}

impl RustView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(RUST_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let name = batch
                .column_by_name("crate_name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let version = batch
                .column_by_name("version")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let (Some(name), Some(version)) = (name, version) else {
                continue;
            };
            let locs = group_rows_by_file(batch)?;
            // The grouped FileLocs are keyed by path; re-key by (name, version)
            // using the first row of each path.
            let paths = batch
                .column_by_name("relative_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow!("missing relative_path"))?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) || version.is_null(i) {
                    continue;
                }
                if let Some(loc) = locs.get(p) {
                    coords.insert(
                        RustKey {
                            name: name.value(i).to_string(),
                            version: version.value(i).to_string(),
                        },
                        loc.clone(),
                    );
                }
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup → handle. `None` if the crate is not in the archive.
    pub fn get(&self, name: &str, version: &str) -> Option<RustPackage> {
        let loc = self.coords.get(&RustKey {
            name: name.to_string(),
            version: version.to_string(),
        })?;
        Some(RustPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    /// Authoritative `(name, version)` coords of every crate in the view.
    pub fn list(&self) -> Vec<(String, String)> {
        self.coords
            .keys()
            .map(|k| (k.name.clone(), k.version.clone()))
            .collect()
    }

    /// Number of crates indexed.
    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl RustPackage {
    /// Authoritative crate name (from the `crate_name` column, not a path parse).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Authoritative version (from the `version` column).
    pub fn version(&self) -> &str {
        &self.version
    }
    /// The crate's uncompressed size in bytes (no decompression).
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the crate bytes. The only I/O of the read API.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    /// Consume into the crate bytes.
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MAVEN view
// ════════════════════════════════════════════════════════════════════════════

/// `(group, artifact, version, classifier?)` key for the maven coord index. The
/// classifier is part of the key so `-sources`/`-javadoc` resolve distinctly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MavenKey {
    group: String,
    artifact: String,
    version: String,
    classifier: Option<String>,
}

/// Typed view over the maven sub-index. Built once; `get` is O(1).
pub struct MavenView {
    archive: Arc<File>,
    coords: HashMap<MavenKey, FileLoc>,
}

/// A handle to one maven artifact. Coords authoritative (from `group_id`/
/// `artifact_id`/`version` columns). Bytes lazy via [`MavenPackage::bytes`].
pub struct MavenPackage {
    archive: Arc<File>,
    loc: FileLoc,
    group: String,
    artifact: String,
    version: String,
    classifier: Option<String>,
}

impl MavenView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(MAVEN_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let group = batch
                .column_by_name("group_id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let artifact = batch
                .column_by_name("artifact_id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let version = batch
                .column_by_name("version")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let (Some(group), Some(artifact), Some(version)) = (group, artifact, version) else {
                continue;
            };
            // `classifier` column is optional (only present when the plugin emits it).
            let classifier_col = batch
                .column_by_name("classifier")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let locs = group_rows_by_file(batch)?;
            let paths = batch
                .column_by_name("relative_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow!("missing relative_path"))?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if group.is_null(i) || artifact.is_null(i) || version.is_null(i) {
                    continue;
                }
                // Classifier: prefer the column; fall back to deriving from the
                // filename when the column is absent/null (older archives).
                let classifier = match classifier_col {
                    Some(c) if !c.is_null(i) && !c.value(i).is_empty() => {
                        Some(c.value(i).to_string())
                    }
                    _ => derive_classifier(file_name(p), artifact.value(i), version.value(i)),
                };
                if let Some(loc) = locs.get(p) {
                    coords.insert(
                        MavenKey {
                            group: group.value(i).to_string(),
                            artifact: artifact.value(i).to_string(),
                            version: version.value(i).to_string(),
                            classifier,
                        },
                        loc.clone(),
                    );
                }
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup of the primary artifact (no classifier) for a GAV.
    pub fn get(&self, group: &str, artifact: &str, version: &str) -> Option<MavenPackage> {
        self.get_classified(group, artifact, version, None)
    }

    /// O(1) lookup of a specific classifier (`Some("sources")`) or the primary
    /// artifact (`None`).
    pub fn get_classified(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
        classifier: Option<&str>,
    ) -> Option<MavenPackage> {
        let key = MavenKey {
            group: group.to_string(),
            artifact: artifact.to_string(),
            version: version.to_string(),
            classifier: classifier.map(|s| s.to_string()),
        };
        let loc = self.coords.get(&key)?;
        Some(MavenPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            group: group.to_string(),
            artifact: artifact.to_string(),
            version: version.to_string(),
            classifier: classifier.map(|s| s.to_string()),
        })
    }

    /// Authoritative coords of every artifact: `(group, artifact, version, classifier?)`.
    pub fn list(&self) -> Vec<(String, String, String, Option<String>)> {
        self.coords
            .keys()
            .map(|k| {
                (
                    k.group.clone(),
                    k.artifact.clone(),
                    k.version.clone(),
                    k.classifier.clone(),
                )
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

/// Best-effort classifier recovery from a filename when the column is absent.
/// Maven filename: `{artifact}-{version}[-{classifier}].{ext}`. Returns the
/// classifier if one is present (i.e. there is a suffix after `-{version}`).
fn derive_classifier(filename: &str, artifact: &str, version: &str) -> Option<String> {
    // strip extension(s) — handle compound like .tar.gz defensively
    let stem = filename
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(filename);
    let prefix = format!("{artifact}-{version}");
    let rest = stem.strip_prefix(&prefix)?;
    let rest = rest.strip_prefix('-')?;
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

impl MavenPackage {
    /// Authoritative groupId (from the `group_id` column).
    pub fn group(&self) -> &str {
        &self.group
    }
    /// Authoritative artifactId (from the `artifact_id` column).
    pub fn artifact(&self) -> &str {
        &self.artifact
    }
    /// Authoritative version (from the `version` column).
    pub fn version(&self) -> &str {
        &self.version
    }
    /// The classifier (`sources`, `javadoc`, …) or `None` for the primary artifact.
    pub fn classifier(&self) -> Option<&str> {
        self.classifier.as_deref()
    }
    /// `(group, artifact, version, classifier?)` — authoritative coords.
    pub fn coords(&self) -> (&str, &str, &str, Option<&str>) {
        (
            &self.group,
            &self.artifact,
            &self.version,
            self.classifier.as_deref(),
        )
    }
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the artifact bytes.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PYTHON view
// ════════════════════════════════════════════════════════════════════════════

/// Wheel vs sdist discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonKind {
    Wheel,
    Sdist,
}

/// `(name, version)` key for the python coord index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PythonKey {
    name: String,
    version: String,
}

/// Typed view over the python sub-index. Built once; `get` is O(1).
pub struct PythonView {
    archive: Arc<File>,
    coords: HashMap<PythonKey, FileLoc>,
    kinds: HashMap<PythonKey, PythonKind>,
}

/// A handle to one python distribution. Bytes lazy via [`PythonPackage::bytes`].
pub struct PythonPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
    kind: PythonKind,
}

impl PythonView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(PYTHON_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        let mut kinds = HashMap::new();
        for batch in &batches {
            let name = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let version = batch
                .column_by_name("version")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let (Some(name), Some(version)) = (name, version) else {
                continue;
            };
            let locs = group_rows_by_file(batch)?;
            let paths = batch
                .column_by_name("relative_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow!("missing relative_path"))?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) || version.is_null(i) {
                    continue;
                }
                let key = PythonKey {
                    name: name.value(i).to_string(),
                    version: version.value(i).to_string(),
                };
                let kind = if file_name(p).ends_with(".whl") {
                    PythonKind::Wheel
                } else {
                    PythonKind::Sdist
                };
                if let Some(loc) = locs.get(p) {
                    // Prefer a wheel over an sdist when both share a (name, version).
                    let replace = matches!(kind, PythonKind::Wheel) || !coords.contains_key(&key);
                    if replace {
                        coords.insert(key.clone(), loc.clone());
                        kinds.insert(key, kind);
                    }
                }
            }
        }
        Ok(Self {
            archive,
            coords,
            kinds,
        })
    }

    /// O(1) lookup → handle. `None` if the distribution is not in the archive.
    pub fn get(&self, name: &str, version: &str) -> Option<PythonPackage> {
        let key = PythonKey {
            name: name.to_string(),
            version: version.to_string(),
        };
        let loc = self.coords.get(&key)?;
        let kind = self.kinds.get(&key).copied().unwrap_or(PythonKind::Sdist);
        Some(PythonPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
            kind,
        })
    }

    /// Authoritative `(name, version)` coords of every distribution.
    pub fn list(&self) -> Vec<(String, String)> {
        self.coords
            .keys()
            .map(|k| (k.name.clone(), k.version.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl PythonPackage {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Wheel or sdist (derived from the matched row's filename).
    pub fn kind(&self) -> PythonKind {
        self.kind
    }
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the distribution bytes.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NPM view
// ════════════════════════════════════════════════════════════════════════════

/// `(name, version)` key for the npm coord index. `name` is the **authoritative**
/// package name from `package.json` — including the `@scope/` prefix that the
/// tarball filename drops.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NpmKey {
    name: String,
    version: String,
}

/// Typed view over the npm sub-index. Built once; `get` is O(1).
pub struct NpmView {
    archive: Arc<File>,
    coords: HashMap<NpmKey, FileLoc>,
}

/// A handle to one npm package tarball. Coords authoritative (from the `name`/
/// `version` columns the plugin parsed out of `package.json`). Bytes lazy via
/// [`NpmPackage::bytes`].
pub struct NpmPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
}

impl NpmView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(NPM_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let name = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let version = batch
                .column_by_name("version")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let (Some(name), Some(version)) = (name, version) else {
                continue;
            };
            let locs = group_rows_by_file(batch)?;
            let paths = batch
                .column_by_name("relative_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow!("missing relative_path"))?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) || version.is_null(i) {
                    continue;
                }
                if let Some(loc) = locs.get(p) {
                    coords.insert(
                        NpmKey {
                            name: name.value(i).to_string(),
                            version: version.value(i).to_string(),
                        },
                        loc.clone(),
                    );
                }
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup → handle. `None` if the package is not in the archive. `name`
    /// is the authoritative name (pass `@scope/pkg` for scoped packages).
    pub fn get(&self, name: &str, version: &str) -> Option<NpmPackage> {
        let loc = self.coords.get(&NpmKey {
            name: name.to_string(),
            version: version.to_string(),
        })?;
        Some(NpmPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    /// Authoritative `(name, version)` coords of every package in the view.
    pub fn list(&self) -> Vec<(String, String)> {
        self.coords
            .keys()
            .map(|k| (k.name.clone(), k.version.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl NpmPackage {
    /// Authoritative package name (from the `name` column — includes `@scope/`).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Authoritative version (from the `version` column).
    pub fn version(&self) -> &str {
        &self.version
    }
    /// The tarball's uncompressed size in bytes (no decompression).
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the tarball bytes. The only I/O of the read API.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// GEM view
// ════════════════════════════════════════════════════════════════════════════

/// `(name, version, platform)` key for the gem coord index. `platform` is part of
/// the key so a platform-suffixed native gem (`foo-1.2.3-java.gem`, platform
/// `java`) resolves distinctly from the pure-ruby gem of the same version. All
/// three come from `metadata.gz` (authoritative), not the filename.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GemKey {
    name: String,
    version: String,
    platform: String,
}

/// Typed view over the gem sub-index. Built once; `get` is O(1).
pub struct GemView {
    archive: Arc<File>,
    coords: HashMap<GemKey, FileLoc>,
}

/// A handle to one gem. Coords authoritative (from the `name`/`version`/`platform`
/// columns the plugin parsed out of `metadata.gz`). Bytes lazy via
/// [`GemPackage::bytes`].
pub struct GemPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
    platform: String,
}

impl GemView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(GEM_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let name = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let version = batch
                .column_by_name("version")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let (Some(name), Some(version)) = (name, version) else {
                continue;
            };
            // `platform` column is optional (older archives may omit it).
            let platform_col = batch
                .column_by_name("platform")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let locs = group_rows_by_file(batch)?;
            let paths = batch
                .column_by_name("relative_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow!("missing relative_path"))?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) || version.is_null(i) {
                    continue;
                }
                let platform = match platform_col {
                    Some(c) if !c.is_null(i) && !c.value(i).is_empty() => c.value(i).to_string(),
                    _ => "ruby".to_string(),
                };
                if let Some(loc) = locs.get(p) {
                    coords.insert(
                        GemKey {
                            name: name.value(i).to_string(),
                            version: version.value(i).to_string(),
                            platform,
                        },
                        loc.clone(),
                    );
                }
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup of the `ruby`-platform gem for a `(name, version)`.
    pub fn get(&self, name: &str, version: &str) -> Option<GemPackage> {
        self.get_platform(name, version, "ruby")
    }

    /// O(1) lookup of a specific platform (`java`, `x86_64-linux`, …).
    pub fn get_platform(&self, name: &str, version: &str, platform: &str) -> Option<GemPackage> {
        let key = GemKey {
            name: name.to_string(),
            version: version.to_string(),
            platform: platform.to_string(),
        };
        let loc = self.coords.get(&key)?;
        Some(GemPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
            platform: platform.to_string(),
        })
    }

    /// Authoritative `(name, version, platform)` coords of every gem in the view.
    pub fn list(&self) -> Vec<(String, String, String)> {
        self.coords
            .keys()
            .map(|k| (k.name.clone(), k.version.clone(), k.platform.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl GemPackage {
    /// Authoritative gem name (from the `name` column).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Authoritative version (from the `version` column).
    pub fn version(&self) -> &str {
        &self.version
    }
    /// The gem platform (`ruby` default, e.g. `java` for a native gem).
    pub fn platform(&self) -> &str {
        &self.platform
    }
    /// The gem's uncompressed size in bytes (no decompression).
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the gem bytes. The only I/O of the read API.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CONDA view
// ════════════════════════════════════════════════════════════════════════════

/// `(name, version, build, subdir)` key for the conda coord index. `build` +
/// `subdir` are part of the key so the same `(name, version)` resolves distinctly
/// across builds and platforms. All four come from `info/index.json`
/// (authoritative), not the filename.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CondaKey {
    name: String,
    version: String,
    build: String,
    subdir: String,
}

/// Typed view over the conda sub-index. Built once; `get` is O(1).
pub struct CondaView {
    archive: Arc<File>,
    coords: HashMap<CondaKey, FileLoc>,
}

/// A handle to one conda package. Coords authoritative (from the `name`/`version`/
/// `build`/`subdir` columns the plugin parsed out of `info/index.json`). Bytes
/// lazy via [`CondaPackage::bytes`].
pub struct CondaPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
    build: String,
    subdir: String,
}

impl CondaView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(CONDA_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let name = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let version = batch
                .column_by_name("version")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let (Some(name), Some(version)) = (name, version) else {
                continue;
            };
            let build_col = batch
                .column_by_name("build")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let subdir_col = batch
                .column_by_name("subdir")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let locs = group_rows_by_file(batch)?;
            let paths = batch
                .column_by_name("relative_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| anyhow!("missing relative_path"))?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) || version.is_null(i) {
                    continue;
                }
                let build = match build_col {
                    Some(c) if !c.is_null(i) => c.value(i).to_string(),
                    _ => String::new(),
                };
                let subdir = match subdir_col {
                    Some(c) if !c.is_null(i) && !c.value(i).is_empty() => c.value(i).to_string(),
                    _ => String::new(),
                };
                if let Some(loc) = locs.get(p) {
                    coords.insert(
                        CondaKey {
                            name: name.value(i).to_string(),
                            version: version.value(i).to_string(),
                            build,
                            subdir,
                        },
                        loc.clone(),
                    );
                }
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup of the first `(name, version)` match across any build/subdir.
    /// Use [`get_exact`](CondaView::get_exact) to pin the build + subdir.
    pub fn get(&self, name: &str, version: &str) -> Option<CondaPackage> {
        let (key, loc) = self
            .coords
            .iter()
            .find(|(k, _)| k.name == name && k.version == version)?;
        Some(CondaPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            name: key.name.clone(),
            version: key.version.clone(),
            build: key.build.clone(),
            subdir: key.subdir.clone(),
        })
    }

    /// O(1) lookup of an exact `(name, version, build, subdir)` coord.
    pub fn get_exact(
        &self,
        name: &str,
        version: &str,
        build: &str,
        subdir: &str,
    ) -> Option<CondaPackage> {
        let key = CondaKey {
            name: name.to_string(),
            version: version.to_string(),
            build: build.to_string(),
            subdir: subdir.to_string(),
        };
        let loc = self.coords.get(&key)?;
        Some(CondaPackage {
            archive: Arc::clone(&self.archive),
            loc: loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
            build: build.to_string(),
            subdir: subdir.to_string(),
        })
    }

    /// Authoritative `(name, version, build, subdir)` coords of every package.
    pub fn list(&self) -> Vec<(String, String, String, String)> {
        self.coords
            .keys()
            .map(|k| {
                (
                    k.name.clone(),
                    k.version.clone(),
                    k.build.clone(),
                    k.subdir.clone(),
                )
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl CondaPackage {
    /// Authoritative package name (from the `name` column).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Authoritative version (from the `version` column).
    pub fn version(&self) -> &str {
        &self.version
    }
    /// The build string (e.g. `py311h1234567_0`), from `info/index.json`.
    pub fn build(&self) -> &str {
        &self.build
    }
    /// The subdir/platform (e.g. `linux-64`), from `info/index.json`.
    pub fn subdir(&self) -> &str {
        &self.subdir
    }
    /// The package's uncompressed size in bytes (no decompression).
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the package bytes. The only I/O of the read API.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RPM view
// ════════════════════════════════════════════════════════════════════════════

/// `(name, version, release, arch)` key for the rpm coord index. Epoch is NOT a
/// lookup key (an rpm filename / dnf request carries no epoch) — it rides in the
/// value so the read side can surface it (e.g. in rpm-md `primary.xml`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RpmKey {
    name: String,
    version: String,
    release: String,
    arch: String,
}

/// The per-rpm value: where its bytes live + the authoritative header metadata
/// (`epoch` and the rpm-md `primary.xml` fields), parsed by
/// [`crate::plugins::rpm_native`].
#[derive(Clone)]
struct RpmEntry {
    loc: FileLoc,
    epoch: Option<String>,
    summary: Option<String>,
    license: Option<String>,
    url: Option<String>,
    vendor: Option<String>,
    sourcerpm: Option<String>,
    /// Provide/require dependency names (the plugin joined them with `\n`).
    provides: Vec<String>,
    requires: Vec<String>,
}

/// One rpm's authoritative header metadata — NEVRA plus the rpm-md `primary.xml`
/// fields — the shape holger's `primary.xml` synthesis feeds off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmMetaRow {
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub epoch: Option<String>,
    pub summary: Option<String>,
    pub license: Option<String>,
    pub url: Option<String>,
    pub vendor: Option<String>,
    pub sourcerpm: Option<String>,
    pub provides: Vec<String>,
    pub requires: Vec<String>,
}

/// Typed view over the rpm sub-index. Coords (incl. real `epoch`) come from the
/// `name`/`version`/`release`/`arch`/`epoch` columns the plugin parsed out of the
/// RPM header — NOT the filename. Built once; `get` is O(1).
pub struct RpmView {
    archive: Arc<File>,
    coords: HashMap<RpmKey, RpmEntry>,
}

/// A handle to one rpm. Coords authoritative; bytes lazy via [`RpmPackage::bytes`].
pub struct RpmPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
    release: String,
    arch: String,
    epoch: Option<String>,
}

impl RpmView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(RPM_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let col = |n: &str| {
                batch
                    .column_by_name(n)
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            };
            let (Some(name), Some(version)) = (col("name"), col("version")) else {
                continue;
            };
            let (release_c, arch_c, epoch_c) = (col("release"), col("arch"), col("epoch"));
            // Rich primary.xml columns — optional, so older archives (NEVRA-only)
            // simply carry `None`/empty here.
            let (summary_c, license_c, url_c) = (col("summary"), col("license"), col("url"));
            let (vendor_c, sourcerpm_c) = (col("vendor"), col("sourcerpm"));
            let (provides_c, requires_c) = (col("provides"), col("requires"));
            let paths = col("relative_path").ok_or_else(|| anyhow!("missing relative_path"))?;
            let locs = group_rows_by_file(batch)?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) || version.is_null(i) {
                    continue;
                }
                let Some(loc) = locs.get(p) else { continue };
                coords.insert(
                    RpmKey {
                        name: name.value(i).to_string(),
                        version: version.value(i).to_string(),
                        release: opt_col(release_c, i).unwrap_or_default(),
                        arch: opt_col(arch_c, i).unwrap_or_default(),
                    },
                    RpmEntry {
                        loc: loc.clone(),
                        epoch: opt_col(epoch_c, i),
                        summary: opt_col(summary_c, i),
                        license: opt_col(license_c, i),
                        url: opt_col(url_c, i),
                        vendor: opt_col(vendor_c, i),
                        sourcerpm: opt_col(sourcerpm_c, i),
                        provides: split_lines(opt_col(provides_c, i)),
                        requires: split_lines(opt_col(requires_c, i)),
                    },
                );
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup of the rpm for `(name, version, release, arch)`.
    pub fn get(&self, name: &str, version: &str, release: &str, arch: &str) -> Option<RpmPackage> {
        let key = RpmKey {
            name: name.to_string(),
            version: version.to_string(),
            release: release.to_string(),
            arch: arch.to_string(),
        };
        let entry = self.coords.get(&key)?;
        Some(RpmPackage {
            archive: Arc::clone(&self.archive),
            loc: entry.loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
            release: release.to_string(),
            arch: arch.to_string(),
            epoch: entry.epoch.clone(),
        })
    }

    /// Authoritative `(name, version, release, arch, epoch)` of every rpm in the
    /// view — the NEVRA-only projection.
    pub fn list(&self) -> Vec<(String, String, String, String, Option<String>)> {
        self.coords
            .iter()
            .map(|(k, e)| {
                (
                    k.name.clone(),
                    k.version.clone(),
                    k.release.clone(),
                    k.arch.clone(),
                    e.epoch.clone(),
                )
            })
            .collect()
    }

    /// Every rpm's full authoritative header metadata (NEVRA + the rpm-md
    /// `primary.xml` fields) — what holger's `primary.xml` synthesis emits.
    pub fn list_meta(&self) -> Vec<RpmMetaRow> {
        self.coords
            .iter()
            .map(|(k, e)| RpmMetaRow {
                name: k.name.clone(),
                version: k.version.clone(),
                release: k.release.clone(),
                arch: k.arch.clone(),
                epoch: e.epoch.clone(),
                summary: e.summary.clone(),
                license: e.license.clone(),
                url: e.url.clone(),
                vendor: e.vendor.clone(),
                sourcerpm: e.sourcerpm.clone(),
                provides: e.provides.clone(),
                requires: e.requires.clone(),
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl RpmPackage {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn release(&self) -> &str {
        &self.release
    }
    pub fn arch(&self) -> &str {
        &self.arch
    }
    /// The authoritative `Epoch` (from the header), or `None` when unset.
    pub fn epoch(&self) -> Option<&str> {
        self.epoch.as_deref()
    }
    /// The rpm's uncompressed size in bytes (no decompression).
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    /// LAZY: pread + decompress the rpm bytes. The only I/O of the read API.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

/// A nullable UTF-8 column value at row `i` as an owned `Option<String>`.
fn opt_col(c: Option<&StringArray>, i: usize) -> Option<String> {
    c.filter(|a| !a.is_null(i)).map(|a| a.value(i).to_string())
}

/// Split a newline-joined column value (the shape the rpm plugin stores dependency
/// lists in) back into its parts, dropping empties. `None`/`""` ⇒ `[]`.
fn split_lines(v: Option<String>) -> Vec<String> {
    v.map(|s| {
        s.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

// ════════════════════════════════════════════════════════════════════════════
// DEB view
// ════════════════════════════════════════════════════════════════════════════

/// `(name, version, arch)` key for the deb coord index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DebKey {
    name: String,
    version: String,
    arch: String,
}

/// The per-deb value: where its bytes live + the raw `control` stanza (the real
/// Depends/Maintainer/Description the filename can't carry), parsed by
/// [`crate::plugins::deb_native`]. `control` is `None` when the `.deb` wasn't
/// parseable at ingest (unsupported codec / off-feature) — coords then came from
/// the filename.
#[derive(Clone)]
struct DebEntry {
    loc: FileLoc,
    control: Option<String>,
}

/// Typed view over the deb sub-index. Coords + the authoritative `control` stanza
/// come from the columns the plugin parsed out of the control tarball — NOT the
/// filename. Built once; `get` is O(1).
pub struct DebView {
    archive: Arc<File>,
    coords: HashMap<DebKey, DebEntry>,
}

/// A handle to one deb. Coords + `control` authoritative; bytes lazy.
pub struct DebPackage {
    archive: Arc<File>,
    loc: FileLoc,
    name: String,
    version: String,
    arch: String,
    control: Option<String>,
}

impl DebView {
    fn build(path: &Path, archive: Arc<File>) -> Result<Self> {
        let (_schema, batches) = read_znippy_index_filtered(
            path,
            &IndexFilter {
                pkg_type: Some(DEB_PKG_TYPE),
                repo: None,
            },
        )?;
        let mut coords = HashMap::new();
        for batch in &batches {
            let col = |n: &str| {
                batch
                    .column_by_name(n)
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            };
            let Some(name) = col("name") else { continue };
            let (version_c, arch_c, control_c) = (col("version"), col("arch"), col("control"));
            let paths = col("relative_path").ok_or_else(|| anyhow!("missing relative_path"))?;
            let locs = group_rows_by_file(batch)?;
            let mut seen = std::collections::HashSet::new();
            for i in 0..batch.num_rows() {
                let p = paths.value(i);
                if !seen.insert(p) {
                    continue;
                }
                if name.is_null(i) {
                    continue;
                }
                let Some(loc) = locs.get(p) else { continue };
                coords.insert(
                    DebKey {
                        name: name.value(i).to_string(),
                        version: opt_col(version_c, i).unwrap_or_default(),
                        arch: opt_col(arch_c, i).unwrap_or_default(),
                    },
                    DebEntry {
                        loc: loc.clone(),
                        control: opt_col(control_c, i),
                    },
                );
            }
        }
        Ok(Self { archive, coords })
    }

    /// O(1) lookup of the deb for `(name, version, arch)`.
    pub fn get(&self, name: &str, version: &str, arch: &str) -> Option<DebPackage> {
        let key = DebKey {
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
        };
        let entry = self.coords.get(&key)?;
        Some(DebPackage {
            archive: Arc::clone(&self.archive),
            loc: entry.loc.clone(),
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
            control: entry.control.clone(),
        })
    }

    /// Authoritative `(name, version, arch, control)` of every deb in the view —
    /// the APT `Packages` synthesis feeds off this.
    pub fn list(&self) -> Vec<(String, String, String, Option<String>)> {
        self.coords
            .iter()
            .map(|(k, e)| {
                (
                    k.name.clone(),
                    k.version.clone(),
                    k.arch.clone(),
                    e.control.clone(),
                )
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.coords.len()
    }
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }
}

impl DebPackage {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn arch(&self) -> &str {
        &self.arch
    }
    /// The raw `control` stanza from the control tarball, or `None` when the `.deb`
    /// wasn't parseable at ingest.
    pub fn control(&self) -> Option<&str> {
        self.control.as_deref()
    }
    pub fn size(&self) -> u64 {
        self.loc.uncompressed_size
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.loc.read_bytes(&self.archive)
    }
}

// ─── construction entrypoints, shared by ZnippyArchive's cached `as_*` methods ──

pub(crate) fn build_rust_view(path: &Path, archive: Arc<File>) -> Result<Option<RustView>> {
    let view = RustView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_maven_view(path: &Path, archive: Arc<File>) -> Result<Option<MavenView>> {
    let view = MavenView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_python_view(path: &Path, archive: Arc<File>) -> Result<Option<PythonView>> {
    let view = PythonView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_npm_view(path: &Path, archive: Arc<File>) -> Result<Option<NpmView>> {
    let view = NpmView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_gem_view(path: &Path, archive: Arc<File>) -> Result<Option<GemView>> {
    let view = GemView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_conda_view(path: &Path, archive: Arc<File>) -> Result<Option<CondaView>> {
    let view = CondaView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_rpm_view(path: &Path, archive: Arc<File>) -> Result<Option<RpmView>> {
    let view = RpmView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}

pub(crate) fn build_deb_view(path: &Path, archive: Arc<File>) -> Result<Option<DebView>> {
    let view = DebView::build(path, archive)?;
    Ok(if view.is_empty() { None } else { Some(view) })
}
