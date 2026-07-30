//! Native Conda plugin.
//!
//! Handles the classic **`.tar.bz2`** conda package: a bzip2-compressed tar whose
//! `info/index.json` carries the **authoritative** `name`, `version`, `build`, and
//! `subdir`. These are NOT reliably recoverable from the filename: a conda file is
//! named `{name}-{version}-{build}.tar.bz2`, and `build` itself contains hyphens
//! and digits (`py311h1234567_0`), so a naive split mis-attributes the version.
//! Parsing `info/index.json` (under the `host-decompressors` feature, via `lbzip2`
//! for the bunzip2 + the `tar` crate for the untar) is what lets the read-side
//! [`CondaView`](crate::views::CondaView) resolve conda coords correctly.
//!
//! The newer **`.conda`** format (a zip whose members are zstd-compressed tars
//! `info-*.tar.zst`) is recognized by extension, but its `info/index.json` is NOT
//! parsed here: extracting it needs a zip reader plus a zstd-tar path that the
//! available `host-decompressors` deps (`lgz`/`lbzip2`/`tar`) do not provide. For a
//! `.conda` file the plugin therefore falls back to the filename split and logs a
//! one-line note. Real `.conda` index parsing is a documented follow-up — we do
//! NOT fake the columns.
//!
//! When `host-decompressors` is off (or the package can't be parsed), the plugin
//! falls back to a best-effort `(name, version)` split from the filename — never
//! panics, always returns a row.

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use arrow::datatypes::{DataType, Field};
use std::collections::HashMap;

/// Native conda plugin. `name`/`version`/`build`/`subdir` come from
/// `info/index.json` for `.tar.bz2` packages when parseable, else from the
/// filename.
pub struct CondaPlugin;

/// Authoritative conda coords parsed from `info/index.json`.
struct CondaIndex {
    name: String,
    version: String,
    build: String,
    subdir: Option<String>,
}

impl CondaPlugin {
    /// Best-effort `(name, version)` from a conda filename like
    /// `{name}-{version}-{build}.tar.bz2` / `.conda`: strip the extension, then
    /// split off the trailing `-{build}` and the `-{version}` before it. The build
    /// string is NOT a distinct field here — that's exactly why `info/index.json`
    /// is preferred.
    fn parse_filename(path: &str) -> (String, Option<String>) {
        let filename = path.rsplit('/').next().unwrap_or(path);
        let stem = filename
            .strip_suffix(".tar.bz2")
            .or_else(|| filename.strip_suffix(".conda"))
            .unwrap_or(filename);
        // `name-version-build`: peel the last two `-`-separated segments as
        // build + version, leaving the (possibly hyphenated) name.
        let mut parts: Vec<&str> = stem.rsplitn(3, '-').collect();
        // rsplitn yields [build, version, name] reversed.
        if parts.len() == 3 {
            let name = parts.pop().unwrap();
            let version = parts.pop().unwrap();
            (name.to_string(), Some(version.to_string()))
        } else {
            (stem.to_string(), None)
        }
    }

    /// Parse `info/index.json` out of a `.tar.bz2` conda package: bunzip2 the
    /// outer layer, untar, find `info/index.json`, read the fields. `None` on any
    /// failure (caller falls back to the filename). Only compiled when host
    /// decompressors are available.
    #[cfg(feature = "host-decompressors")]
    fn parse_tar_bz2(data: &[u8]) -> Option<CondaIndex> {
        use crate::plugins::npm_native::MAX_INGEST_DECOMPRESS;
        use std::io::Read;
        // 1. bunzip2 the outer layer — capped so a bzip2 compression bomb errors
        //    here (→ filename fallback) instead of expanding to GB and OOM-aborting.
        let tar_bytes = lbzip2::stream::decompress_capped(data, MAX_INGEST_DECOMPRESS).ok()?;
        // 2. untar and find info/index.json.
        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let mut index_json: Option<Vec<u8>> = None;
        for entry in archive.entries().ok()? {
            let mut entry = entry.ok()?;
            let path = entry.path().ok()?.to_string_lossy().to_string();
            if path == "info/index.json" || path.ends_with("/info/index.json") {
                // Cap the per-tar-entry read so a huge index member can't OOM.
                let mut buf = Vec::new();
                let read = entry
                    .by_ref()
                    .take(MAX_INGEST_DECOMPRESS as u64)
                    .read_to_end(&mut buf)
                    .ok()?;
                if read >= MAX_INGEST_DECOMPRESS {
                    return None;
                }
                index_json = Some(buf);
                break;
            }
        }
        let index_json = index_json?;
        let v: serde_json::Value = serde_json::from_slice(&index_json).ok()?;
        let name = v.get("name")?.as_str()?.to_string();
        let version = v.get("version")?.as_str()?.to_string();
        let build = v
            .get("build")
            .and_then(|b| b.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let subdir = v
            .get("subdir")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some(CondaIndex {
            name,
            version,
            build,
            subdir,
        })
    }

    /// Parse the authoritative index for a conda package, if possible. `.tar.bz2`
    /// is fully supported; `.conda` is recognized but not yet parsed (documented
    /// follow-up) — returns `None` so the caller uses the filename.
    #[cfg(feature = "host-decompressors")]
    fn parse_index(path: &str, data: &[u8]) -> Option<CondaIndex> {
        let filename = path.rsplit('/').next().unwrap_or(path);
        if filename.ends_with(".tar.bz2") {
            return Self::parse_tar_bz2(data);
        }
        if filename.ends_with(".conda") {
            log::info!(
                "conda: .conda (zip+zstd) index parsing is a follow-up; \
                 falling back to filename coords for {filename}"
            );
        }
        None
    }

    /// Resolve `(name, version)`: authoritative `info/index.json` first
    /// (`.tar.bz2`), filename fallback otherwise.
    fn resolve_coords(path: &str, _data: &[u8]) -> (String, Option<String>) {
        #[cfg(feature = "host-decompressors")]
        if let Some(idx) = Self::parse_index(path, _data) {
            return (idx.name, Some(idx.version));
        }
        Self::parse_filename(path)
    }

    /// Resolve the conda build string (empty when unknown / filename mode).
    fn resolve_build(_path: &str, _data: &[u8]) -> String {
        #[cfg(feature = "host-decompressors")]
        if let Some(idx) = Self::parse_index(_path, _data) {
            return idx.build;
        }
        String::new()
    }

    /// Resolve the conda subdir (platform, e.g. `linux-64`). `None` when unknown.
    fn resolve_subdir(_path: &str, _data: &[u8]) -> Option<String> {
        #[cfg(feature = "host-decompressors")]
        if let Some(idx) = Self::parse_index(_path, _data) {
            return idx.subdir;
        }
        None
    }
}

impl ArchiveTypePlugin for CondaPlugin {
    fn name(&self) -> &str {
        "conda"
    }

    fn type_id(&self) -> i8 {
        14
    }

    fn meta(&self) -> HandlerMeta {
        HandlerMeta {
            name: "conda".into(),
            aliases: vec!["anaconda".into(), "mamba".into()],
            type_id: 14,
            ecosystem: "Conda packages (Anaconda / conda-forge)".into(),
            extensions: vec![".conda".into(), ".tar.bz2".into()],
            description:
                "Conda packages — authoritative name/version/build/subdir from info/index.json (.tar.bz2)"
                    .into(),
            commands: vec![HandlerCommand::new(
                "coords",
                "Print conda package name + version (info/index.json if readable, else filename)",
            )],
        }
    }

    fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
        match cmd {
            "coords" => {
                let path = args
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("usage: conda coords <file.tar.bz2|.conda>"))?;
                let (name, version) = Self::parse_filename(path);
                match version {
                    Some(v) => println!("{} {}", name, v),
                    None => println!("{}", name),
                }
                Ok(())
            }
            other => anyhow::bail!("conda: unknown subcommand '{}'", other),
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with(".tar.bz2") || path.ends_with(".conda")
    }

    /// Columns this handler contributes — the conda coords the read-side
    /// [`CondaView`](crate::views::CondaView) resolves on, plus the authoritative
    /// `build` and `subdir` (platform).
    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("version", DataType::Utf8, true),
            Field::new("build", DataType::Utf8, true),
            Field::new("subdir", DataType::Utf8, true),
        ]
    }

    fn extract_metadata(&self, path: &str, data: &[u8]) -> Option<ExtensionRow> {
        let (name, version) = Self::resolve_coords(path, data);
        let build = Self::resolve_build(path, data);
        let subdir = Self::resolve_subdir(path, data);
        let mut fields = HashMap::new();
        fields.insert("name".into(), ExtensionValue::Str(name));
        fields.insert("version".into(), ExtensionValue::OptStr(version));
        fields.insert("build".into(), ExtensionValue::Str(build));
        fields.insert("subdir".into(), ExtensionValue::OptStr(subdir));
        Some(ExtensionRow { fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_conda_extensions() {
        let p = CondaPlugin;
        assert!(p.matches_path("linux-64/numpy-1.26.0-py311h1234567_0.tar.bz2"));
        assert!(p.matches_path("linux-64/numpy-1.26.0-py311h1234567_0.conda"));
        assert!(!p.matches_path("foo.tgz"));
    }

    #[test]
    fn filename_fallback_splits_name_version() {
        let (n, v) = CondaPlugin::parse_filename("linux-64/numpy-1.26.0-py311h1234567_0.tar.bz2");
        assert_eq!(n, "numpy");
        assert_eq!(v.as_deref(), Some("1.26.0"));
    }

    #[test]
    fn schema_has_name_version_build_subdir() {
        let f = CondaPlugin.schema_fields();
        assert_eq!(f.len(), 4);
        assert_eq!(f[0].name(), "name");
        assert_eq!(f[1].name(), "version");
        assert_eq!(f[2].name(), "build");
        assert_eq!(f[3].name(), "subdir");
    }
}
