//! Native Cargo/crate registry plugin.
//! Extracts crate name + version from .crate filenames (zero decompression cost).
//! Optionally parses Cargo.toml inside the tarball for deps (only if needed).

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use arrow::datatypes::{DataType, Field};
use std::collections::HashMap;

/// Native plugin that extracts crate metadata from .crate file paths.
/// Name and version are parsed from the filename (no I/O needed).
pub struct CargoPlugin {
    /// If true, also decompress and parse Cargo.toml for dependency list
    pub parse_deps: bool,
}

impl CargoPlugin {
    pub fn new() -> Self {
        Self { parse_deps: false }
    }

    pub fn with_deps() -> Self {
        Self { parse_deps: true }
    }

    /// Parse name and version from filename like "serde-1.0.200.crate"
    fn parse_filename(path: &str) -> Option<(String, String)> {
        let filename = path.rsplit('/').next()?;
        let stem = filename.strip_suffix(".crate")?;
        // Split at last hyphen followed by a digit (version start)
        let mut split_pos = None;
        for (i, c) in stem.char_indices() {
            if c == '-' {
                // Check if next char is a digit
                if let Some(next) = stem[i + 1..].chars().next() {
                    if next.is_ascii_digit() {
                        split_pos = Some(i);
                    }
                }
            }
        }
        let pos = split_pos?;
        let name = &stem[..pos];
        let version = &stem[pos + 1..];
        Some((name.to_string(), version.to_string()))
    }

    /// Parse deps from .crate tarball (only when parse_deps = true).
    ///
    /// Uses the workspace's own `lgz` crate, which does gzip-decompress +
    /// tar-extract + filter-by-name in one parallel zero-copy call. We filter
    /// for `Cargo.toml`, pick the entry whose path ends in `Cargo.toml`
    /// (the top-level `<name-version>/Cargo.toml`), and feed it to
    /// `extract_dep_names`. Any error → empty dep list (never panic).
    #[cfg(feature = "host-decompressors")]
    fn parse_deps_from_tarball(data: &[u8]) -> Vec<String> {
        let entries = match lgz::decompress_tar_gz_filter(data, "Cargo.toml") {
            Ok(entries) => entries,
            Err(_) => return Vec::new(),
        };

        for (path, bytes) in &entries {
            if path.ends_with("/Cargo.toml") || path == "Cargo.toml" {
                let contents = String::from_utf8_lossy(bytes);
                return Self::extract_dep_names(&contents);
            }
        }
        Vec::new()
    }

    #[cfg(feature = "host-decompressors")]
    fn extract_dep_names(cargo_toml: &str) -> Vec<String> {
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in cargo_toml.lines() {
            let trimmed = line.trim();
            if trimmed == "[dependencies]" {
                in_deps = true;
            } else if trimmed.starts_with('[') {
                in_deps = false;
            } else if in_deps {
                if let Some(dep_name) = trimmed.split('=').next() {
                    let dep_name = dep_name.trim();
                    if !dep_name.is_empty() && !dep_name.starts_with('#') {
                        deps.push(dep_name.to_string());
                    }
                }
            }
        }
        deps
    }
}

impl ArchiveTypePlugin for CargoPlugin {
    fn name(&self) -> &str {
        "cargo"
    }

    fn type_id(&self) -> i8 {
        1
    }

    fn meta(&self) -> HandlerMeta {
        HandlerMeta {
            name: "cargo".into(),
            aliases: vec!["rust".into()],
            type_id: 1,
            ecosystem: "Rust / crates.io".into(),
            extensions: vec![".crate".into()],
            description:
                "Rust crate registry tarballs — name + version from filename, deps from Cargo.toml"
                    .into(),
            commands: vec![HandlerCommand::new(
                "coords",
                "Print crate name + version parsed from a .crate path",
            )],
        }
    }

    fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
        match cmd {
            "coords" => {
                let path = args
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("usage: cargo coords <file.crate>"))?;
                let (name, version) = Self::parse_filename(path)
                    .ok_or_else(|| anyhow::anyhow!("not a .crate path: {}", path))?;
                println!("{} {}", name, version);
                Ok(())
            }
            other => anyhow::bail!("cargo: unknown subcommand '{}'", other),
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with(".crate")
    }

    /// Columns this handler contributes to the index. These are the READ-side
    /// coords: the typed [`RustView`](crate::views::RustView) maps
    /// `crate_name`/`version` back into `(name, version)`. Without these declared,
    /// the writer never persists the columns and the view cannot resolve coords.
    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("crate_name", DataType::Utf8, true),
            Field::new("version", DataType::Utf8, true),
        ]
    }

    fn extract_metadata(&self, path: &str, data: &[u8]) -> Option<ExtensionRow> {
        let (crate_name, version) = Self::parse_filename(path)?;

        let mut fields = HashMap::new();
        fields.insert("crate_name".into(), ExtensionValue::Str(crate_name));
        fields.insert("version".into(), ExtensionValue::Str(version));

        #[cfg(feature = "host-decompressors")]
        if self.parse_deps {
            let deps = Self::parse_deps_from_tarball(data);
            fields.insert("deps".into(), ExtensionValue::StrList(deps));
        }

        #[cfg(not(feature = "host-decompressors"))]
        let _ = data; // suppress unused warning

        Some(ExtensionRow { fields })
    }
}
