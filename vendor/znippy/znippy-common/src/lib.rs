extern crate core;

/// Re-export arrow so plugins implement `schema_fields()` against the exact same arrow
/// version as the core trait, avoiding type-mismatch across crate boundaries.
pub use arrow;

pub mod archive;
pub mod codec;
pub mod common_config;
pub mod index;
pub mod meta_sink;
pub mod meta_sink_append;

pub mod slotpool;

pub mod meta;
pub use meta::{BlobMeta, ChunkMeta, FileMeta};

/// Detached, streaming CMS provenance signatures (per-artifact + per-archive).
/// Off by default; default builds and the on-disk format are byte-unchanged.
#[cfg(feature = "sign")]
pub mod sign;

pub mod plugin;
pub mod plugins;
pub mod views;

pub mod decompress;

pub use archive::{ZnippyArchive, ZnippyReader};
pub use decompress::{decompress_archive, decompress_archive_filtered, get_file};
pub use meta_sink::{ArchiveMetaSink, ArrowIpcSink, GroupKey, MetaSinkFactory};
pub use meta_sink_append::{AppendReport, ArrowIpcSinkAppend, append_files};
pub use views::{
    CONDA_PKG_TYPE, CondaPackage, CondaView, GEM_PKG_TYPE, GemPackage, GemView, MAVEN_PKG_TYPE,
    MavenPackage, MavenView, NPM_PKG_TYPE, NpmPackage, NpmView, PYTHON_PKG_TYPE, PythonKind,
    PythonPackage, PythonView, RUST_PKG_TYPE, RustPackage, RustView,
};

pub use index::{
    ArtifactMeta, ChunkLoc, IndexFilter, IndexFooter, MULTI_INDEX_MAGIC, ManifestEntry,
    SIGN_ARCHIVE_MODULE, SIGN_ARTIFACTS_MODULE, VerifyReport, ZNIPPY_INDEX_SCHEMA,
    build_arrow_metadata_for_config, build_metadata_batch, extract_config_from_arrow_metadata,
    get_all_files_meta, get_files_meta_with_prefix, interpret_footer, is_probably_compressed,
    is_reserved_module, list_archive_contents, locate_file, read_manifest_bytes,
    read_reserved_section_bytes, read_znippy_full_manifest, read_znippy_index,
    read_znippy_index_filtered, read_znippy_manifest, should_skip_compression,
    verify_archive_integrity, write_manifest_bytes, znippy_index_schema,
};

#[derive(Debug)]
pub struct CompressionReport {
    pub total_files: u64,
    pub compressed_files: u64,
    pub uncompressed_files: u64,
    pub total_dirs: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub compression_ratio: f32,
    pub chunks: u64,
}
