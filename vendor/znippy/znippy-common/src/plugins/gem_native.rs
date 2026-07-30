//! Native RubyGems plugin.
//!
//! A `.gem` is an **uncompressed `ustar` tar** whose members include
//! `metadata.gz` (a gzipped YAML doc) and `data.tar.gz` (the actual files). The
//! **authoritative** `name`, `version`, and `platform` live in that YAML — NOT in
//! the filename. This matters for **platform-suffixed** gems: a native gem is
//! published as `foo-1.2.3-java.gem`, whose filename "version" naively parses as
//! `1.2.3-java`, while `metadata.gz` carries `version: 1.2.3` + `platform: java`.
//! Parsing it (under the `host-decompressors` feature, via the `tar` crate for the
//! outer tar + `lgz` for the inner `metadata.gz`) is what lets the read-side
//! [`GemView`](crate::views::GemView) resolve gem coords correctly.
//!
//! When `host-decompressors` is off (or the gem can't be parsed), the plugin falls
//! back to a best-effort `(name, version)` split from the filename — never panics,
//! always returns a row.

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use arrow::datatypes::{DataType, Field};
use std::collections::HashMap;

/// Native gem plugin. `name`/`version`/`platform` come from `metadata.gz` when the
/// `.gem` is parseable, else `(name, version)` from the filename.
pub struct GemPlugin;

impl GemPlugin {
    /// Best-effort `(name, version)` from a gem filename like `foo-1.2.3.gem` or
    /// `foo-1.2.3-java.gem`: strip `.gem`, split at the last `-` immediately
    /// followed by a digit (the conventional version start). The platform suffix
    /// (`-java`) is NOT recoverable as a distinct field from the filename — that's
    /// exactly why `metadata.gz` is preferred.
    fn parse_filename(path: &str) -> (String, Option<String>) {
        let filename = path.rsplit('/').next().unwrap_or(path);
        let stem = filename.strip_suffix(".gem").unwrap_or(filename);
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

    /// Parse the authoritative `(name, version, platform)` out of a `.gem`'s
    /// `metadata.gz`. The outer `.gem` is a plain (uncompressed) tar; find the
    /// `metadata.gz` member, gunzip it, then read the YAML fields. `None` on any
    /// failure (caller falls back to the filename). Only compiled when host
    /// decompressors are available.
    #[cfg(feature = "host-decompressors")]
    fn parse_metadata(data: &[u8]) -> Option<(String, String, String)> {
        use crate::plugins::npm_native::MAX_INGEST_DECOMPRESS;
        use std::io::Read;
        // 1. The outer `.gem` is a plain ustar tar — read it with the `tar` crate
        //    directly (no gzip wrapper on the outer layer).
        let mut archive = tar::Archive::new(data);
        let mut meta_gz: Option<Vec<u8>> = None;
        for entry in archive.entries().ok()? {
            let mut entry = entry.ok()?;
            let path = entry.path().ok()?.to_string_lossy().to_string();
            if path == "metadata.gz" || path.ends_with("/metadata.gz") {
                // Cap the per-tar-entry read: a huge `metadata.gz` member can't
                // blow up memory at ingest — bail to the filename fallback.
                let mut buf = Vec::new();
                let read = entry
                    .by_ref()
                    .take(MAX_INGEST_DECOMPRESS as u64)
                    .read_to_end(&mut buf)
                    .ok()?;
                if read >= MAX_INGEST_DECOMPRESS {
                    return None;
                }
                meta_gz = Some(buf);
                break;
            }
        }
        let meta_gz = meta_gz?;
        // 2. gunzip the YAML doc — capped so a compression-bomb metadata.gz
        //    errors here (→ filename fallback) instead of OOM-aborting.
        let yaml = lgz::decompress_gz_capped(&meta_gz, MAX_INGEST_DECOMPRESS).ok()?;
        let yaml = String::from_utf8_lossy(&yaml);
        Self::parse_metadata_yaml(&yaml)
    }

    /// Minimal hand parse of the two (three) fields we need out of a gem
    /// `metadata.gz` YAML doc. The relevant shape is:
    ///
    /// ```yaml
    /// --- !ruby/object:Gem::Specification
    /// name: foo
    /// version: !ruby/object:Gem::Version
    ///   version: 1.2.3
    /// platform: java
    /// ```
    ///
    /// `name` and `platform` are top-level scalars; `version` is nested one level
    /// under a `version:` key (the top-level `version:` line itself has no scalar —
    /// it introduces the `!ruby/object:Gem::Version` mapping). We therefore take the
    /// FIRST indented `version: X` we see after the top-level `version:` key.
    /// Platform defaults to `ruby` when absent. Returns `None` if name/version
    /// can't be found (caller falls back to the filename).
    #[cfg(feature = "host-decompressors")]
    fn parse_metadata_yaml(yaml: &str) -> Option<(String, String, String)> {
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut platform = "ruby".to_string();
        let mut in_version_block = false;

        let strip_quotes = |s: &str| -> String {
            let t = s.trim();
            t.trim_matches('"').trim_matches('\'').to_string()
        };

        for line in yaml.lines() {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();

            if indent == 0 {
                // A new top-level key ends any version block.
                if let Some(rest) = trimmed.strip_prefix("name:") {
                    let v = strip_quotes(rest);
                    if !v.is_empty() && name.is_none() {
                        name = Some(v);
                    }
                    in_version_block = false;
                } else if let Some(rest) = trimmed.strip_prefix("platform:") {
                    let v = strip_quotes(rest);
                    if !v.is_empty() {
                        platform = v;
                    }
                    in_version_block = false;
                } else if trimmed.starts_with("version:") {
                    // The top-level `version:` key introduces the Gem::Version
                    // mapping; the actual string is on an indented `version:` line.
                    let rest = strip_quotes(&trimmed["version:".len()..]);
                    if !rest.is_empty() && !rest.starts_with('!') {
                        // Inline scalar form (rare, but accept it).
                        version.get_or_insert(rest);
                        in_version_block = false;
                    } else {
                        in_version_block = true;
                    }
                } else {
                    in_version_block = false;
                }
            } else if in_version_block && version.is_none() {
                if let Some(rest) = trimmed.strip_prefix("version:") {
                    let v = strip_quotes(rest);
                    if !v.is_empty() && !v.starts_with('!') {
                        version = Some(v);
                    }
                }
            }
        }

        let name = name?;
        let version = version?;
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name, version, platform))
    }

    /// Resolve `(name, version)`: authoritative `metadata.gz` first, filename
    /// fallback otherwise.
    fn resolve_coords(path: &str, _data: &[u8]) -> (String, Option<String>) {
        #[cfg(feature = "host-decompressors")]
        if let Some((name, version, _platform)) = Self::parse_metadata(_data) {
            return (name, Some(version));
        }
        Self::parse_filename(path)
    }

    /// Resolve the gem platform (`ruby` default). Only meaningful with the feature
    /// on; filename mode can't recover it, so returns `ruby`.
    fn resolve_platform(_data: &[u8]) -> String {
        #[cfg(feature = "host-decompressors")]
        if let Some((_n, _v, platform)) = Self::parse_metadata(_data) {
            return platform;
        }
        "ruby".to_string()
    }
}

impl ArchiveTypePlugin for GemPlugin {
    fn name(&self) -> &str {
        "gem"
    }

    fn type_id(&self) -> i8 {
        11
    }

    fn meta(&self) -> HandlerMeta {
        HandlerMeta {
            name: "gem".into(),
            aliases: vec!["ruby".into(), "rubygems".into()],
            type_id: 11,
            ecosystem: "Ruby / RubyGems (rubygems.org)".into(),
            extensions: vec![".gem".into()],
            description: "RubyGems packages — authoritative name/version/platform from metadata.gz"
                .into(),
            commands: vec![HandlerCommand::new(
                "coords",
                "Print gem name + version (metadata.gz if readable, else filename)",
            )],
        }
    }

    fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
        match cmd {
            "coords" => {
                let path = args
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("usage: gem coords <file.gem>"))?;
                let (name, version) = Self::parse_filename(path);
                match version {
                    Some(v) => println!("{} {}", name, v),
                    None => println!("{}", name),
                }
                Ok(())
            }
            other => anyhow::bail!("gem: unknown subcommand '{}'", other),
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with(".gem")
    }

    /// Columns this handler contributes — the gem coords the read-side
    /// [`GemView`](crate::views::GemView) resolves on, plus the authoritative
    /// `platform` (defaults to `ruby`).
    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("version", DataType::Utf8, true),
            Field::new("platform", DataType::Utf8, true),
        ]
    }

    fn extract_metadata(&self, path: &str, data: &[u8]) -> Option<ExtensionRow> {
        let (name, version) = Self::resolve_coords(path, data);
        let platform = Self::resolve_platform(data);
        let mut fields = HashMap::new();
        fields.insert("name".into(), ExtensionValue::Str(name));
        fields.insert("version".into(), ExtensionValue::OptStr(version));
        fields.insert("platform".into(), ExtensionValue::Str(platform));
        Some(ExtensionRow { fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_gem_only() {
        let p = GemPlugin;
        assert!(p.matches_path("gems/rails-7.0.0.gem"));
        assert!(!p.matches_path("foo.tgz"));
    }

    #[test]
    fn filename_fallback_splits_at_version() {
        let (n, v) = GemPlugin::parse_filename("gems/nokogiri-1.15.0.gem");
        assert_eq!(n, "nokogiri");
        assert_eq!(v.as_deref(), Some("1.15.0"));
    }

    #[test]
    fn filename_platform_suffix_is_not_a_distinct_field() {
        // The naive filename split folds the platform into the "version" — exactly
        // the gap metadata.gz parsing closes.
        let (n, v) = GemPlugin::parse_filename("foo-1.2.3-java.gem");
        assert_eq!(n, "foo");
        assert_eq!(v.as_deref(), Some("1.2.3-java"));
    }

    #[test]
    fn schema_has_name_version_platform() {
        let f = GemPlugin.schema_fields();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].name(), "name");
        assert_eq!(f[1].name(), "version");
        assert_eq!(f[2].name(), "platform");
    }

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn parse_metadata_yaml_reads_name_version_platform() {
        let yaml = "--- !ruby/object:Gem::Specification\n\
                    name: foo\n\
                    version: !ruby/object:Gem::Version\n  version: 1.2.3\n\
                    platform: java\n";
        let (n, v, p) = GemPlugin::parse_metadata_yaml(yaml).unwrap();
        assert_eq!(n, "foo");
        assert_eq!(v, "1.2.3");
        assert_eq!(p, "java");
    }

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn parse_metadata_yaml_defaults_platform_to_ruby() {
        let yaml = "name: bar\nversion: !ruby/object:Gem::Version\n  version: 2.0.0\n";
        let (n, v, p) = GemPlugin::parse_metadata_yaml(yaml).unwrap();
        assert_eq!(n, "bar");
        assert_eq!(v, "2.0.0");
        assert_eq!(p, "ruby");
    }
}
