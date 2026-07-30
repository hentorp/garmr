//! Native npm registry plugin.
//!
//! Extracts the **authoritative** package `name` + `version` from the
//! `package/package.json` inside an npm `.tgz` tarball — not from the filename.
//! This matters for **scoped** packages: a registry tarball for `@scope/pkg` is
//! served as `…/-/pkg-1.2.3.tgz`, i.e. the scope is *dropped from the filename*.
//! Only `package.json` carries the real `"name": "@scope/pkg"`. Parsing it (under
//! the `host-decompressors` feature, via `lgz`'s gzip+tar filter) is what lets the
//! read-side [`NpmView`](crate::views::NpmView) resolve scoped coords correctly.
//!
//! When `host-decompressors` is off (or the tarball can't be parsed), the plugin
//! falls back to a best-effort `(name, version)` split from the filename — never
//! panics, always returns a row.

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use arrow::datatypes::{DataType, Field};
use std::collections::HashMap;

/// Hard cap on decompressed ingest output. Metadata files (package.json,
/// metadata.gz YAML, info/index.json) are tiny; a real package is far under this.
/// A small but highly compressible upload that would expand past this is rejected
/// by the capped decompressors (returning `Err`), so the plugin degrades to the
/// filename fallback instead of OOM-aborting the process.
#[cfg(feature = "host-decompressors")]
pub(crate) const MAX_INGEST_DECOMPRESS: usize = 256 * 1024 * 1024; // 256 MiB

/// Native npm plugin. `name`/`version` come from `package.json` when the tarball
/// is decompressable, else from the filename.
pub struct NpmPlugin;

impl NpmPlugin {
    /// Best-effort `(name, version)` from a tarball filename like
    /// `pkg-1.2.3.tgz`: strip `.tgz`, split at the last `-` immediately followed
    /// by a digit (the conventional version start). Scope is **not** recoverable
    /// from the filename — that's exactly why `package.json` is preferred.
    fn parse_filename(path: &str) -> (String, Option<String>) {
        let filename = path.rsplit('/').next().unwrap_or(path);
        let stem = filename.strip_suffix(".tgz").unwrap_or(filename);
        let mut split_pos = None;
        for (i, c) in stem.char_indices() {
            if c == '-' {
                if let Some(next) = stem[i + 1..].chars().next() {
                    if next.is_ascii_digit() {
                        split_pos = Some(i);
                    }
                }
            }
        }
        match split_pos {
            Some(pos) => (stem[..pos].to_string(), Some(stem[pos + 1..].to_string())),
            None => (stem.to_string(), None),
        }
    }

    /// Parse the **top-level** `name` + `version` out of an npm tarball's
    /// `package/package.json`. `None` on any failure (caller falls back to the
    /// filename). Only compiled when a host gzip+tar decompressor is available.
    #[cfg(feature = "host-decompressors")]
    fn parse_package_json(data: &[u8]) -> Option<(String, String)> {
        // Capped decompress: a bomb tarball errors here (→ `.ok()?` → filename
        // fallback) instead of expanding to many GB and OOM-aborting at ingest.
        let entries =
            lgz::decompress_tar_gz_filter_capped(data, "package.json", MAX_INGEST_DECOMPRESS)
                .ok()?;
        // npm roots everything under `package/`; prefer that exact path, but
        // accept a bare top-level `package.json` too.
        let (_, bytes) = entries
            .iter()
            .find(|(p, _)| p.ends_with("package/package.json") || p.as_str() == "package.json")
            .or_else(|| entries.first())?;
        let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let name = v.get("name")?.as_str()?.to_string();
        let version = v.get("version")?.as_str()?.to_string();
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name, version))
    }

    /// Resolve `(name, version)`: authoritative `package.json` first, filename
    /// fallback otherwise.
    fn resolve_coords(path: &str, _data: &[u8]) -> (String, Option<String>) {
        #[cfg(feature = "host-decompressors")]
        if let Some((name, version)) = Self::parse_package_json(_data) {
            return (name, Some(version));
        }
        Self::parse_filename(path)
    }
}

impl ArchiveTypePlugin for NpmPlugin {
    fn name(&self) -> &str {
        "npm"
    }

    fn type_id(&self) -> i8 {
        6
    }

    fn meta(&self) -> HandlerMeta {
        HandlerMeta {
            name: "npm".into(),
            aliases: vec!["node".into(), "yarn".into(), "pnpm".into()],
            type_id: 6,
            ecosystem: "JavaScript / npm (registry.npmjs.org)".into(),
            extensions: vec![".tgz".into()],
            description:
                "npm package tarballs — authoritative name (incl. @scope) + version from package.json"
                    .into(),
            commands: vec![HandlerCommand::new(
                "coords",
                "Print npm package name + version (package.json if readable, else filename)",
            )],
        }
    }

    fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
        match cmd {
            "coords" => {
                let path = args
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("usage: npm coords <file.tgz>"))?;
                let (name, version) = Self::parse_filename(path);
                match version {
                    Some(v) => println!("{} {}", name, v),
                    None => println!("{}", name),
                }
                Ok(())
            }
            other => anyhow::bail!("npm: unknown subcommand '{}'", other),
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with(".tgz")
    }

    /// Columns this handler contributes — the npm coords the read-side
    /// [`NpmView`](crate::views::NpmView) resolves on.
    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("version", DataType::Utf8, true),
        ]
    }

    fn extract_metadata(&self, path: &str, data: &[u8]) -> Option<ExtensionRow> {
        let (name, version) = Self::resolve_coords(path, data);
        let mut fields = HashMap::new();
        fields.insert("name".into(), ExtensionValue::Str(name));
        fields.insert("version".into(), ExtensionValue::OptStr(version));
        Some(ExtensionRow { fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_tgz_only() {
        let p = NpmPlugin;
        assert!(p.matches_path("react/-/react-18.2.0.tgz"));
        assert!(!p.matches_path("react/-/react-18.2.0.tar.gz"));
        assert!(!p.matches_path("foo.jar"));
    }

    #[test]
    fn filename_fallback_splits_at_version() {
        let (n, v) = NpmPlugin::parse_filename("@types/node/-/node-20.11.5.tgz");
        // Scope is NOT recoverable from the filename — this is the documented gap
        // that package.json parsing closes.
        assert_eq!(n, "node");
        assert_eq!(v.as_deref(), Some("20.11.5"));
    }

    #[test]
    fn schema_is_name_version() {
        let f = NpmPlugin.schema_fields();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].name(), "name");
        assert_eq!(f[1].name(), "version");
    }
}
