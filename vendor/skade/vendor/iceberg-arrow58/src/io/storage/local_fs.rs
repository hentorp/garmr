// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Local filesystem storage implementation for testing.
//!
//! This module provides a `LocalFsStorage` implementation that uses standard
//! Rust filesystem operations. It is primarily intended for unit testing
//! scenarios where tests need to read/write files on the local filesystem.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::io::{
    FileMetadata, FileRead, FileWrite, InputFile, OutputFile, Storage, StorageConfig,
    StorageFactory,
};
use crate::{Error, ErrorKind, Result};

/// Local filesystem storage implementation.
///
/// This storage implementation uses standard Rust filesystem operations,
/// making it suitable for unit tests that need to read/write files on disk.
///
/// # Path Normalization
///
/// The storage normalizes paths to handle various formats:
/// - `file:///path/to/file` -> `/path/to/file`
/// - `file:/path/to/file` -> `/path/to/file`
/// - `/path/to/file` -> `/path/to/file`
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalFsStorage;

impl LocalFsStorage {
    /// Create a new `LocalFsStorage` instance.
    pub fn new() -> Self {
        Self
    }

    /// Normalize a path by removing scheme prefixes.
    ///
    /// This handles the following formats:
    /// - `file:///path` -> `/path`
    /// - `file://path` -> `/path` (treats as absolute)
    /// - `file:/path` -> `/path`
    /// - `/path` -> `/path`
    pub(crate) fn normalize_path(path: &str) -> PathBuf {
        let path = if let Some(stripped) = path.strip_prefix("file://") {
            // file:///path -> /path or file://path -> /path
            if stripped.starts_with('/') {
                stripped.to_string()
            } else {
                format!("/{stripped}")
            }
        } else if let Some(stripped) = path.strip_prefix("file:") {
            // file:/path -> /path
            if stripped.starts_with('/') {
                stripped.to_string()
            } else {
                format!("/{stripped}")
            }
        } else {
            path.to_string()
        };
        PathBuf::from(path)
    }
}

/// A unique sibling temp path next to `final_path`, in the SAME directory so the
/// follow-up rename is atomic (same filesystem). The `.tmp.<pid>.<n>` suffix can
/// never collide with a real Iceberg file (they end in `.avro` / `.parquet` /
/// `.metadata.json`) nor match heal's `*.metadata.json` directory scan, so a
/// temp file left behind by a crash is inert and ignored.
fn temp_sibling(final_path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut s = final_path.as_os_str().to_owned();
    s.push(format!(".tmp.{}.{}", std::process::id(), n));
    PathBuf::from(s)
}

/// fsync the directory containing `path` so that a rename INTO it is durable —
/// without it, the new directory entry can be lost on power failure even after
/// the file's own bytes were fsync'd. Best-effort: a directory that cannot be
/// opened/fsync'd is ignored (durability degrades, the write does not fail).
fn fsync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

/// Durably and atomically materialize `bs` at `path`: create parents, write a
/// sibling temp file, fsync its contents, atomically rename it onto `path`, then
/// fsync the parent directory. A crash at any point leaves either the previous
/// file or the complete new one at `path` — never a torn/zero-byte stub. This is
/// what stops a SIGTERM mid-write from leaving a 0-byte manifest that a committed
/// snapshot still references (the torn-compaction failure mode this hardens).
fn atomic_write(path: &Path, bs: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = temp_sibling(path);
    // Write + flush the temp file, then close the fd before renaming.
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bs)?;
        f.sync_all()?;
    }
    // Atomic replace; never leak the temp file on failure.
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_parent_dir(path);
    Ok(())
}

#[async_trait]
#[typetag::serde]
impl Storage for LocalFsStorage {
    async fn exists(&self, path: &str) -> Result<bool> {
        let path = Self::normalize_path(path);
        Ok(path.exists())
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let path = Self::normalize_path(path);
        let metadata = fs::metadata(&path).map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Failed to get metadata for {}: {}", path.display(), e),
            )
        })?;
        Ok(FileMetadata {
            size: metadata.len(),
        })
    }

    async fn read(&self, path: &str) -> Result<Bytes> {
        let path = Self::normalize_path(path);
        let content = fs::read(&path).map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Failed to read file {}: {}", path.display(), e),
            )
        })?;
        Ok(Bytes::from(content))
    }

    async fn reader(&self, path: &str) -> Result<Box<dyn FileRead>> {
        let path = Self::normalize_path(path);
        let file = fs::File::open(&path).map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Failed to open file {}: {}", path.display(), e),
            )
        })?;
        Ok(Box::new(LocalFsFileRead::new(file)))
    }

    async fn write(&self, path: &str, bs: Bytes) -> Result<()> {
        let path = Self::normalize_path(path);

        // Atomic + durable: temp file -> fsync -> rename -> parent-dir fsync, so a
        // crash mid-write never leaves a torn/0-byte file (e.g. a manifest) at the
        // final path. `atomic_write` creates parent directories itself.
        atomic_write(&path, &bs).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to write file {}: {}", path.display(), e),
            )
        })?;
        Ok(())
    }

    async fn writer(&self, path: &str) -> Result<Box<dyn FileWrite>> {
        let path = Self::normalize_path(path);

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to create directory {}: {}", parent.display(), e),
                )
            })?;
        }

        // Stream into a sibling temp file; `close()` fsyncs it and atomically
        // renames it onto the final path, so a crash mid-stream never leaves a
        // torn file (0-byte manifest list / partial parquet) at the path a
        // committed snapshot references.
        let tmp = temp_sibling(&path);
        let file = fs::File::create(&tmp).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to create temp file {}: {}", tmp.display(), e),
            )
        })?;
        Ok(Box::new(LocalFsFileWrite::new(file, tmp, path)))
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let path = Self::normalize_path(path);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to delete file {}: {}", path.display(), e),
                )
            })?;
        }
        Ok(())
    }

    async fn delete_prefix(&self, path: &str) -> Result<()> {
        let path = Self::normalize_path(path);
        if path.is_dir() {
            fs::remove_dir_all(&path).map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to delete directory {}: {}", path.display(), e),
                )
            })?;
        }
        Ok(())
    }

    fn new_input(&self, path: &str) -> Result<InputFile> {
        Ok(InputFile::new(Arc::new(self.clone()), path.to_string()))
    }

    fn new_output(&self, path: &str) -> Result<OutputFile> {
        Ok(OutputFile::new(Arc::new(self.clone()), path.to_string()))
    }
}

/// File reader for local filesystem storage.
#[derive(Debug)]
pub struct LocalFsFileRead {
    file: std::sync::Mutex<fs::File>,
}

impl LocalFsFileRead {
    /// Create a new `LocalFsFileRead` with the given file.
    pub fn new(file: fs::File) -> Self {
        Self {
            file: std::sync::Mutex::new(file),
        }
    }
}

#[async_trait]
impl FileRead for LocalFsFileRead {
    async fn read(&self, range: Range<u64>) -> Result<Bytes> {
        let mut file = self.file.lock().map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to acquire file lock: {e}"),
            )
        })?;

        file.seek(SeekFrom::Start(range.start)).map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Failed to seek to position {}: {}", range.start, e),
            )
        })?;

        let len = (range.end - range.start) as usize;
        let mut buffer = vec![0u8; len];
        file.read_exact(&mut buffer).map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Failed to read {len} bytes: {e}"),
            )
        })?;

        Ok(Bytes::from(buffer))
    }
}

/// File writer for local filesystem storage.
///
/// Writes stream into `tmp`; [`FileWrite::close`] fsyncs it, atomically renames
/// it onto `final_path`, and fsyncs the parent directory — so the file only ever
/// appears at `final_path` complete and durable, never as a torn/0-byte stub.
#[derive(Debug)]
pub struct LocalFsFileWrite {
    file: Option<fs::File>,
    tmp: PathBuf,
    final_path: PathBuf,
}

impl LocalFsFileWrite {
    /// Create a new `LocalFsFileWrite` streaming into `tmp`, to be atomically
    /// renamed onto `final_path` on close.
    pub fn new(file: fs::File, tmp: PathBuf, final_path: PathBuf) -> Self {
        Self {
            file: Some(file),
            tmp,
            final_path,
        }
    }
}

#[async_trait]
impl FileWrite for LocalFsFileWrite {
    async fn write(&mut self, bs: Bytes) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "Cannot write to closed file"))?;

        file.write_all(&bs).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to write to file: {e}"),
            )
        })?;

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "File already closed"))?;

        // Flush the streamed contents, then close the fd before renaming.
        file.sync_all()
            .map_err(|e| Error::new(ErrorKind::Unexpected, format!("Failed to sync file: {e}")))?;
        drop(file);

        // Atomically publish the fully-written file at its final path; never leak
        // the temp file on a failed rename.
        if let Err(e) = fs::rename(&self.tmp, &self.final_path) {
            let _ = fs::remove_file(&self.tmp);
            return Err(Error::new(
                ErrorKind::Unexpected,
                format!(
                    "Failed to rename {} -> {}: {}",
                    self.tmp.display(),
                    self.final_path.display(),
                    e
                ),
            ));
        }
        // fsync the directory so the rename's new entry is itself durable.
        fsync_parent_dir(&self.final_path);

        Ok(())
    }
}

/// Factory for creating `LocalFsStorage` instances.
///
/// This factory implements `StorageFactory` and creates `LocalFsStorage`
/// instances for the "file" scheme.
///
/// # Example
///
/// ```rust,ignore
/// use iceberg::io::{StorageConfig, StorageFactory, LocalFsStorageFactory};
///
/// let factory = LocalFsStorageFactory;
/// let config = StorageConfig::new();
/// let storage = factory.build(&config)?;
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalFsStorageFactory;

#[typetag::serde]
impl StorageFactory for LocalFsStorageFactory {
    fn build(&self, _config: &StorageConfig) -> Result<Arc<dyn Storage>> {
        Ok(Arc::new(LocalFsStorage::new()))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_normalize_path() {
        // Test file:/// prefix
        assert_eq!(
            LocalFsStorage::normalize_path("file:///path/to/file"),
            PathBuf::from("/path/to/file")
        );

        // Test file:// prefix (without leading slash in path)
        assert_eq!(
            LocalFsStorage::normalize_path("file://path/to/file"),
            PathBuf::from("/path/to/file")
        );

        // Test file:/ prefix
        assert_eq!(
            LocalFsStorage::normalize_path("file:/path/to/file"),
            PathBuf::from("/path/to/file")
        );

        // Test bare path
        assert_eq!(
            LocalFsStorage::normalize_path("/path/to/file"),
            PathBuf::from("/path/to/file")
        );
    }

    #[tokio::test]
    async fn test_local_fs_storage_write_read() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();
        let content = Bytes::from("Hello, World!");

        // Write
        storage.write(path_str, content.clone()).await.unwrap();

        // Read
        let read_content = storage.read(path_str).await.unwrap();
        assert_eq!(read_content, content);
    }

    #[tokio::test]
    async fn test_local_fs_storage_exists() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();

        // File doesn't exist initially
        assert!(!storage.exists(path_str).await.unwrap());

        // Write file
        storage.write(path_str, Bytes::from("test")).await.unwrap();

        // File exists now
        assert!(storage.exists(path_str).await.unwrap());
    }

    #[tokio::test]
    async fn test_local_fs_storage_metadata() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();
        let content = Bytes::from("Hello, World!");

        storage.write(path_str, content.clone()).await.unwrap();

        let metadata = storage.metadata(path_str).await.unwrap();
        assert_eq!(metadata.size, content.len() as u64);
    }

    #[tokio::test]
    async fn test_local_fs_storage_delete() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();

        storage.write(path_str, Bytes::from("test")).await.unwrap();
        assert!(storage.exists(path_str).await.unwrap());

        storage.delete(path_str).await.unwrap();
        assert!(!storage.exists(path_str).await.unwrap());
    }

    #[tokio::test]
    async fn test_local_fs_storage_delete_prefix() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let dir_path = tmp_dir.path().join("subdir");
        let file1 = dir_path.join("file1.txt");
        let file2 = dir_path.join("file2.txt");

        // Create files in subdirectory
        storage
            .write(file1.to_str().unwrap(), Bytes::from("1"))
            .await
            .unwrap();
        storage
            .write(file2.to_str().unwrap(), Bytes::from("2"))
            .await
            .unwrap();

        // Delete prefix (directory)
        storage
            .delete_prefix(dir_path.to_str().unwrap())
            .await
            .unwrap();

        // Directory should be deleted
        assert!(!dir_path.exists());
    }

    #[tokio::test]
    async fn test_local_fs_storage_reader() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();
        let content = Bytes::from("Hello, World!");

        storage.write(path_str, content.clone()).await.unwrap();

        let reader = storage.reader(path_str).await.unwrap();
        let read_content = reader.read(0..content.len() as u64).await.unwrap();
        assert_eq!(read_content, content);

        // Test partial read
        let partial = reader.read(0..5).await.unwrap();
        assert_eq!(partial, Bytes::from("Hello"));
    }

    #[tokio::test]
    async fn test_local_fs_storage_writer() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();

        let mut writer = storage.writer(path_str).await.unwrap();
        writer.write(Bytes::from("Hello, ")).await.unwrap();
        writer.write(Bytes::from("World!")).await.unwrap();
        writer.close().await.unwrap();

        let content = storage.read(path_str).await.unwrap();
        assert_eq!(content, Bytes::from("Hello, World!"));
    }

    #[tokio::test]
    async fn test_local_fs_file_write_double_close() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();

        let mut writer = storage.writer(path_str).await.unwrap();
        writer.write(Bytes::from("test")).await.unwrap();
        writer.close().await.unwrap();

        // Second close should fail
        let result = writer.close().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_local_fs_file_write_after_close() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("test.txt");
        let path_str = path.to_str().unwrap();

        let mut writer = storage.writer(path_str).await.unwrap();
        writer.close().await.unwrap();

        // Write after close should fail
        let result = writer.write(Bytes::from("test")).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_local_fs_storage_factory() {
        let factory = LocalFsStorageFactory;
        let config = StorageConfig::new();
        let storage = factory.build(&config).unwrap();

        // Verify we got a valid storage instance
        assert!(format!("{storage:?}").contains("LocalFsStorage"));
    }

    #[tokio::test]
    async fn test_local_fs_creates_parent_directories() {
        let tmp_dir = TempDir::new().unwrap();
        let storage = LocalFsStorage::new();
        let path = tmp_dir.path().join("a/b/c/test.txt");
        let path_str = path.to_str().unwrap();

        // Write should create parent directories
        storage.write(path_str, Bytes::from("test")).await.unwrap();

        assert!(path.exists());
    }
}
