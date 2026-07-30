//! Skeleton package handlers — dummy implementations for additional ecosystems.
//!
//! Each handler here is a *stub*: it self-describes via [`meta()`](ArchiveTypePlugin::meta)
//! so it shows up in `znippy handlers` and is selectable with `--format <name>`,
//! and it implements a generic filename-based `coords` subcommand +
//! `extract_metadata` (package name + best-effort version parsed from the
//! filename, zero decompression cost). Real per-ecosystem parsing (manifest
//! files inside the archive, signatures, dep graphs) is left as a TODO for
//! whoever promotes the stub to a full handler.
//!
//! To promote a skeleton: replace the generated `extract_metadata` body with
//! real parsing, add `schema_fields()`, and add any ecosystem-specific
//! subcommands to its `meta().commands` + `run_command`.
//!
//! `type_id` registry continues from the native handlers (1=cargo, 2=python,
//! 3=maven, 6=npm, 11=gem, 14=conda — npm is `plugins::npm_native`, gem is
//! `plugins::gem_native`, conda is `plugins::conda_native`, NONE a skeleton). See
//! `design_plugins.md` for the authoritative table.

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use std::collections::HashMap;

/// Best-effort `(name, version?)` split from a package filename.
///
/// Strips the first matching extension, then splits at the last `-`/`_`/`@`
/// that is immediately followed by a digit (the conventional version start).
/// Falls back to `(stem, None)` for formats without an embedded version
/// (e.g. raw ELF binaries).
fn parse_coords(path: &str, extensions: &[&str]) -> (String, Option<String>) {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let stem = extensions
        .iter()
        .find_map(|ext| filename.strip_suffix(ext))
        .unwrap_or(filename);

    let mut split_pos = None;
    for (i, c) in stem.char_indices() {
        if matches!(c, '-' | '_' | '@') {
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

/// Stamp out a skeleton handler that parses `name` + best-effort `version`
/// from the filename and advertises a single `coords` subcommand.
macro_rules! skeleton_handler {
    (
        struct: $struct:ident,
        name: $name:literal,
        type_id: $tid:literal,
        aliases: [$($alias:literal),* $(,)?],
        ecosystem: $eco:literal,
        extensions: [$($ext:literal),* $(,)?],
        description: $desc:literal $(,)?
    ) => {
        #[doc = concat!("Skeleton handler for the ", $eco, " ecosystem (stub).")]
        pub struct $struct;

        impl $struct {
            const EXTENSIONS: &'static [&'static str] = &[$($ext),*];
        }

        impl ArchiveTypePlugin for $struct {
            fn name(&self) -> &str { $name }

            fn type_id(&self) -> i8 { $tid }

            fn meta(&self) -> HandlerMeta {
                HandlerMeta {
                    name: $name.into(),
                    aliases: vec![$($alias.into()),*],
                    type_id: $tid,
                    ecosystem: $eco.into(),
                    extensions: vec![$($ext.into()),*],
                    description: concat!($desc, " (skeleton — filename-only)").into(),
                    commands: vec![
                        HandlerCommand::new(
                            "coords",
                            concat!("Print ", $name, " package name + version parsed from a path"),
                        ),
                    ],
                }
            }

            fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
                match cmd {
                    "coords" => {
                        let path = args.first().ok_or_else(|| {
                            anyhow::anyhow!(concat!("usage: ", $name, " coords <file>"))
                        })?;
                        let (name, version) = parse_coords(path, Self::EXTENSIONS);
                        match version {
                            Some(v) => println!("{} {}", name, v),
                            None => println!("{}", name),
                        }
                        Ok(())
                    }
                    other => anyhow::bail!(concat!($name, ": unknown subcommand '{}'"), other),
                }
            }

            fn matches_path(&self, path: &str) -> bool {
                Self::EXTENSIONS.iter().any(|ext| path.ends_with(ext))
            }

            fn extract_metadata(&self, path: &str, _data: &[u8]) -> Option<ExtensionRow> {
                let (name, version) = parse_coords(path, Self::EXTENSIONS);
                let mut fields = HashMap::new();
                fields.insert("name".into(), ExtensionValue::Str(name));
                fields.insert(
                    "version".into(),
                    ExtensionValue::OptStr(version),
                );
                Some(ExtensionRow { fields })
            }
        }
    };
}

skeleton_handler! {
    struct: GoPlugin,
    name: "go",
    type_id: 4,
    aliases: ["golang"],
    ecosystem: "Go / Go modules (proxy.golang.org)",
    extensions: [".zip", ".mod", ".info"],
    description: "Go module zips published to the module proxy",
}

skeleton_handler! {
    struct: NugetPlugin,
    name: "nuget",
    type_id: 5,
    aliases: ["dotnet", ".net"],
    ecosystem: ".NET / NuGet (nuget.org)",
    extensions: [".nupkg", ".snupkg"],
    description: ".NET NuGet packages (zip with a .nuspec manifest)",
}

// npm (type_id 6) is a REAL handler now — see `plugins::npm_native::NpmPlugin`
// (authoritative name+version from package.json). It is intentionally absent from
// the skeleton list below; `register` folds in `NpmPlugin` from `npm_native`.

skeleton_handler! {
    struct: ElfPlugin,
    name: "elf",
    type_id: 7,
    aliases: ["binary", "so"],
    ecosystem: "Linux ELF binaries / shared objects",
    extensions: [".elf", ".so", ".bin", ".out"],
    description: "Raw ELF executables / shared libraries (no embedded version)",
}

// rpm (type_id 8) is a REAL handler now — see `plugins::rpm_native::RpmPlugin`
// (authoritative NEVRA incl. epoch from the header tag table). It is intentionally
// absent from the skeleton list below; `builtin_handlers` folds in `RpmPlugin`.

// deb (type_id 9) is a REAL handler now — see `plugins::deb_native::DebPlugin`
// (authoritative control fields from the control tarball: ar → control.tar.* →
// control). Intentionally absent from the skeleton list; `builtin_handlers` folds
// in `DebPlugin`.

skeleton_handler! {
    struct: FlatpakPlugin,
    name: "flatpak",
    type_id: 10,
    aliases: ["flatpakref"],
    ecosystem: "Flatpak bundles (Flathub)",
    extensions: [".flatpak", ".flatpakref"],
    description: "Flatpak single-file application bundles (OSTree)",
}

// gem (type_id 11) is a REAL handler now — see `plugins::gem_native::GemPlugin`
// (authoritative name/version/platform from metadata.gz). It is intentionally
// absent from the skeleton list; `builtin_handlers` folds in `GemPlugin`.

skeleton_handler! {
    struct: DockerPlugin,
    name: "docker",
    type_id: 12,
    aliases: ["oci", "container", "image"],
    ecosystem: "OCI / Docker container images",
    extensions: [".oci", ".docker"],
    description: "OCI image layouts / docker save tarballs (manifest + layers)",
}

skeleton_handler! {
    struct: HelmPlugin,
    name: "helm",
    type_id: 13,
    aliases: ["chart", "k8s"],
    ecosystem: "Helm charts (Kubernetes / Artifact Hub)",
    extensions: [".tgz"],
    description: "Helm chart archives (Chart.yaml + templates)",
}

// conda (type_id 14) is a REAL handler now — see
// `plugins::conda_native::CondaPlugin` (authoritative name/version/build/subdir
// from info/index.json for .tar.bz2). It is intentionally absent from the
// skeleton list; `builtin_handlers` folds in `CondaPlugin`.

skeleton_handler! {
    struct: SnapPlugin,
    name: "snap",
    type_id: 15,
    aliases: ["snapcraft", "snapd"],
    ecosystem: "Snap packages (Snapcraft / Snap Store)",
    extensions: [".snap"],
    description: "Snap application packages (squashfs image)",
}

skeleton_handler! {
    struct: AppImagePlugin,
    name: "appimage",
    type_id: 16,
    aliases: ["appdir"],
    ecosystem: "AppImage portable Linux applications",
    extensions: [".AppImage", ".appimage"],
    description: "AppImage self-mounting application bundles (ELF + squashfs)",
}

skeleton_handler! {
    struct: ComposerPlugin,
    name: "composer",
    type_id: 17,
    aliases: ["php", "packagist"],
    ecosystem: "PHP / Composer (Packagist)",
    extensions: [".zip", ".phar"],
    description: "Composer/PHP packages (zip with composer.json, or PHAR)",
}

skeleton_handler! {
    struct: HexPlugin,
    name: "hex",
    type_id: 18,
    aliases: ["elixir", "erlang", "mix"],
    ecosystem: "Erlang / Elixir (hex.pm)",
    extensions: [".tar"],
    description: "Hex packages (tar of metadata + contents.tar.gz)",
}

skeleton_handler! {
    struct: CabalPlugin,
    name: "cabal",
    type_id: 19,
    aliases: ["haskell", "hackage"],
    ecosystem: "Haskell / Cabal (Hackage)",
    extensions: [".tar.gz"],
    description: "Cabal source packages (sdist tarball with a .cabal file)",
}

skeleton_handler! {
    struct: SwiftPlugin,
    name: "swift",
    type_id: 20,
    aliases: ["swiftpm", "spm"],
    ecosystem: "Swift / Swift Package Manager",
    extensions: [".zip"],
    description: "Swift package archives (Package.swift + sources)",
}

skeleton_handler! {
    struct: ParquetPlugin,
    name: "parquet",
    type_id: 21,
    aliases: ["geoparquet", "pq"],
    ecosystem: "Apache Parquet / GeoParquet columnar data",
    extensions: [".parquet", ".geoparquet"],
    description: "Parquet column files (GeoParquet adds a geo metadata key)",
}

skeleton_handler! {
    struct: DatasetPlugin,
    name: "dataset",
    type_id: 22,
    aliases: ["hf", "huggingface", "hub"],
    ecosystem: "ML datasets (Hugging Face Hub / Croissant)",
    extensions: [".dataset", ".hf"],
    description: "Versioned ML dataset bundles (data shards + dataset card)",
}

skeleton_handler! {
    struct: ArrowPlugin,
    name: "arrow",
    type_id: 23,
    aliases: ["ipc", "feather"],
    ecosystem: "Apache Arrow IPC / Feather",
    extensions: [".arrow", ".feather", ".ipc"],
    description: "Arrow IPC record-batch files (zero-copy columnar)",
}

skeleton_handler! {
    struct: GeoJsonPlugin,
    name: "geojson",
    type_id: 24,
    aliases: ["geo", "gis", "shapefile"],
    ecosystem: "GIS vector data (GeoJSON / Shapefile / GeoPackage)",
    extensions: [".geojson", ".gpkg", ".shp", ".fgb"],
    description: "Geospatial vector datasets (features + CRS)",
}

/// Every skeleton handler, in `type_id` order. The register in `znippy-cli`
/// folds these in alongside the native handlers.
pub fn skeleton_handlers() -> Vec<Box<dyn ArchiveTypePlugin>> {
    vec![
        Box::new(GoPlugin),
        Box::new(NugetPlugin),
        Box::new(ElfPlugin),
        Box::new(FlatpakPlugin),
        Box::new(DockerPlugin),
        Box::new(HelmPlugin),
        Box::new(SnapPlugin),
        Box::new(AppImagePlugin),
        Box::new(ComposerPlugin),
        Box::new(HexPlugin),
        Box::new(CabalPlugin),
        Box::new(SwiftPlugin),
        Box::new(ParquetPlugin),
        Box::new(DatasetPlugin),
        Box::new(ArrowPlugin),
        Box::new(GeoJsonPlugin),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_coords_splits_name_and_version() {
        assert_eq!(
            parse_coords("foo/bar-1.2.3.nupkg", &[".nupkg"]),
            ("bar".to_string(), Some("1.2.3".to_string()))
        );
        assert_eq!(
            parse_coords("lodash-4.17.21.tgz", &[".tgz"]),
            ("lodash".to_string(), Some("4.17.21".to_string()))
        );
    }

    #[test]
    fn parse_coords_handles_no_version() {
        assert_eq!(
            parse_coords("/usr/bin/ls.elf", &[".elf"]),
            ("ls".to_string(), None)
        );
    }

    #[test]
    fn skeletons_have_unique_sequential_type_ids() {
        let mut ids: Vec<i8> = skeleton_handlers().iter().map(|h| h.type_id()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "type_ids must be unique");
        ids.sort();
        assert_eq!(*ids.first().unwrap(), 4, "skeletons start at type_id 4");
        assert_eq!(*ids.last().unwrap(), 24);
    }

    #[test]
    fn every_skeleton_matches_and_extracts() {
        for h in skeleton_handlers() {
            let m = h.meta();
            assert!(!m.extensions.is_empty(), "{} has no extensions", m.name);
            let sample = format!("pkg-1.0{}", m.extensions[0]);
            assert!(
                h.matches_path(&sample),
                "{} should match {}",
                m.name,
                sample
            );
            let row = h.extract_metadata(&sample, &[]).expect("row");
            assert!(row.fields.contains_key("name"));
        }
    }
}
