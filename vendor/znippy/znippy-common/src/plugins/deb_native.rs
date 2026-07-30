//! Native Debian plugin.
//!
//! A `.deb` is a Unix **ar** archive whose members are `debian-binary`,
//! `control.tar[.gz|.xz|.zst|.bz2]`, and `data.tar.*`. The authoritative
//! Package/Version/Architecture (plus Depends, Maintainer, Description, …) live in
//! the `control` file inside the **control tarball** — NOT the filename. Parsing it
//! (under the `host-decompressors` feature: `tar` for the inner tar, plus
//! `lgz`/`lbzip2`/`lzma-rs`/`ruzstd` for the gz/bz2/xz/zst codecs) is what lets the
//! read-side [`DebView`](crate::views::DebView) surface real control metadata.
//!
//! On any failure (off-feature, unknown codec, malformed) the plugin falls back to
//! the `{name}_{version}_{arch}.deb` filename — never panics, always returns a row,
//! exactly like the `gem`/`conda` native plugins.

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use arrow::datatypes::{DataType, Field};
use std::collections::HashMap;

/// Native deb plugin. `name`/`version`/`arch` + the raw `control` stanza come from
/// the control tarball when the `.deb` is parseable, else `(name, version, arch)`
/// from the filename (no control stanza).
pub struct DebPlugin;

impl DebPlugin {
    /// `{name}_{version}_{arch}.deb` filename fallback. Neither the package name
    /// nor the version contains `_` in a valid pool filename, so a 3-way split is
    /// exact.
    fn parse_filename(path: &str) -> (String, Option<String>, Option<String>) {
        let fname = path.rsplit('/').next().unwrap_or(path);
        let stem = fname
            .strip_suffix(".deb")
            .or_else(|| fname.strip_suffix(".udeb"))
            .unwrap_or(fname);
        let mut it = stem.splitn(3, '_');
        let name = it.next().unwrap_or(stem).to_string();
        let version = it.next().filter(|s| !s.is_empty()).map(str::to_string);
        let arch = it.next().filter(|s| !s.is_empty()).map(str::to_string);
        (name, version, arch)
    }

    /// Parse the authoritative `control` stanza out of a `.deb` (ar → control
    /// tarball → `control`). Returns the raw stanza text. `None` on any failure.
    #[cfg(feature = "host-decompressors")]
    fn parse_control(data: &[u8]) -> Option<String> {
        let member = ar_find_member(data, "control.tar")?;
        let tar_bytes = decompress_control(member.name, member.data)?;
        let control = tar_find_file(&tar_bytes, "control")?;
        let text = String::from_utf8_lossy(&control).into_owned();
        text.lines()
            .any(|l| l.starts_with("Package:"))
            .then_some(text)
    }

    /// `(name, version, arch)` from a control stanza's single-line Package /
    /// Version / Architecture fields.
    fn control_coords(control: &str) -> (Option<String>, Option<String>, Option<String>) {
        let field = |key: &str| -> Option<String> {
            control
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(|v| v.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        (field("Package:"), field("Version:"), field("Architecture:"))
    }

    /// Resolve coords + the raw control stanza: authoritative control first,
    /// filename fallback (no control) otherwise.
    fn resolve(
        path: &str,
        data: &[u8],
    ) -> (String, Option<String>, Option<String>, Option<String>) {
        #[cfg(feature = "host-decompressors")]
        if let Some(control) = Self::parse_control(data) {
            let (n, v, a) = Self::control_coords(&control);
            if let Some(name) = n {
                return (name, v, a, Some(control));
            }
        }
        let _ = data;
        let (name, version, arch) = Self::parse_filename(path);
        (name, version, arch, None)
    }
}

// ── ar + control-tarball helpers (host-decompressors only) ──────────────────

#[cfg(feature = "host-decompressors")]
struct ArMember<'a> {
    name: &'a str,
    data: &'a [u8],
}

/// Find the first ar member whose (trimmed) name starts with `name_prefix`. The
/// `.deb` ar uses short, space-padded names (`control.tar.xz`, `debian-binary`).
/// Fully bounds-checked; `None` on any malformation.
#[cfg(feature = "host-decompressors")]
fn ar_find_member<'a>(data: &'a [u8], name_prefix: &str) -> Option<ArMember<'a>> {
    if data.get(0..8)? != b"!<arch>\n" {
        return None;
    }
    let mut pos = 8usize;
    while pos.checked_add(60)? <= data.len() {
        let hdr = &data[pos..pos + 60];
        let name = std::str::from_utf8(&hdr[0..16])
            .ok()?
            .trim_end()
            .trim_end_matches('/');
        let size: usize = std::str::from_utf8(&hdr[48..58])
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let dstart = pos.checked_add(60)?;
        let dend = dstart.checked_add(size)?;
        if dend > data.len() {
            return None;
        }
        if name.starts_with(name_prefix) {
            return Some(ArMember {
                name,
                data: &data[dstart..dend],
            });
        }
        pos = dend.checked_add(size & 1)?; // members are padded to an even boundary
    }
    None
}

/// Decompress a control tarball member by its codec extension: uncompressed, gz
/// (lgz), bz2 (lbzip2), xz (lzma-rs), zst (ruzstd). Any unknown codec returns
/// `None` (the caller falls back to the filename).
#[cfg(feature = "host-decompressors")]
fn decompress_control(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    use crate::plugins::npm_native::MAX_INGEST_DECOMPRESS;
    use std::io::Read;
    if name == "control.tar" {
        Some(data.to_vec())
    } else if name.ends_with(".gz") {
        lgz::decompress_gz_capped(data, MAX_INGEST_DECOMPRESS).ok()
    } else if name.ends_with(".xz") {
        let mut out = Vec::new();
        let mut w = CappedWriter {
            out: &mut out,
            cap: MAX_INGEST_DECOMPRESS,
        };
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut w).ok()?;
        Some(out)
    } else if name.ends_with(".bz2") {
        lbzip2::stream::decompress_capped(data, MAX_INGEST_DECOMPRESS).ok()
    } else if name.ends_with(".zst") {
        // Pure-Rust zstd (ruzstd), capped so a bomb can't OOM at ingest.
        let mut dec = ruzstd::StreamingDecoder::new(std::io::Cursor::new(data)).ok()?;
        let mut out = Vec::new();
        dec.take(MAX_INGEST_DECOMPRESS as u64)
            .read_to_end(&mut out)
            .ok()?;
        (out.len() < MAX_INGEST_DECOMPRESS).then_some(out)
    } else {
        None
    }
}

/// Extract the `control` member (`control` or `./control`) from an uncompressed
/// control tarball, capped so a tar bomb can't OOM at ingest.
#[cfg(feature = "host-decompressors")]
fn tar_find_file(tar_bytes: &[u8], want: &str) -> Option<Vec<u8>> {
    use crate::plugins::npm_native::MAX_INGEST_DECOMPRESS;
    use std::io::Read;
    let mut archive = tar::Archive::new(tar_bytes);
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_string_lossy().to_string();
        if path.trim_start_matches("./") == want {
            let mut buf = Vec::new();
            let read = entry
                .by_ref()
                .take(MAX_INGEST_DECOMPRESS as u64)
                .read_to_end(&mut buf)
                .ok()?;
            if read >= MAX_INGEST_DECOMPRESS {
                return None;
            }
            return Some(buf);
        }
    }
    None
}

/// An `io::Write` that errors once `cap` bytes have been written — bounds a
/// decompression bomb at ingest (the streaming codecs write into this).
#[cfg(feature = "host-decompressors")]
struct CappedWriter<'a> {
    out: &'a mut Vec<u8>,
    cap: usize,
}

#[cfg(feature = "host-decompressors")]
impl std::io::Write for CappedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len().saturating_add(buf.len()) > self.cap {
            return Err(std::io::Error::other(
                "control tarball decompress cap exceeded",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ArchiveTypePlugin for DebPlugin {
    fn name(&self) -> &str {
        "deb"
    }

    fn type_id(&self) -> i8 {
        9
    }

    fn meta(&self) -> HandlerMeta {
        HandlerMeta {
            name: "deb".into(),
            aliases: vec![
                "debian".into(),
                "ubuntu".into(),
                "apt".into(),
                "dpkg".into(),
            ],
            type_id: 9,
            ecosystem: "Debian packages (Debian / Ubuntu)".into(),
            extensions: vec![".deb".into(), ".udeb".into()],
            description: "Debian packages — authoritative control fields from the control tarball"
                .into(),
            commands: vec![HandlerCommand::new(
                "coords",
                "Print deb name + version (control if readable, else filename)",
            )],
        }
    }

    fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
        match cmd {
            "coords" => {
                let path = args
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("usage: deb coords <file.deb>"))?;
                let (name, version, _arch) = Self::parse_filename(path);
                match version {
                    Some(v) => println!("{} {}", name, v),
                    None => println!("{}", name),
                }
                Ok(())
            }
            other => anyhow::bail!("deb: unknown subcommand '{}'", other),
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with(".deb") || path.ends_with(".udeb")
    }

    /// Columns the read-side [`DebView`](crate::views::DebView) resolves on: the
    /// coords plus the raw `control` stanza (the real Depends/Maintainer/Description
    /// the filename can't carry).
    fn schema_fields(&self) -> Vec<Field> {
        vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("version", DataType::Utf8, true),
            Field::new("arch", DataType::Utf8, true),
            Field::new("control", DataType::Utf8, true),
        ]
    }

    fn extract_metadata(&self, path: &str, data: &[u8]) -> Option<ExtensionRow> {
        let (name, version, arch, control) = Self::resolve(path, data);
        let mut fields = HashMap::new();
        fields.insert("name".into(), ExtensionValue::Str(name));
        fields.insert("version".into(), ExtensionValue::OptStr(version));
        fields.insert("arch".into(), ExtensionValue::OptStr(arch));
        fields.insert("control".into(), ExtensionValue::OptStr(control));
        Some(ExtensionRow { fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_fallback_splits_name_version_arch() {
        let (n, v, a) = DebPlugin::parse_filename("pool/main/h/hello/hello_2.10-3_amd64.deb");
        assert_eq!(n, "hello");
        assert_eq!(v.as_deref(), Some("2.10-3"));
        assert_eq!(a.as_deref(), Some("amd64"));
    }

    #[test]
    fn matches_deb_and_udeb_only() {
        assert!(DebPlugin.matches_path("pool/main/x_1_amd64.deb"));
        assert!(DebPlugin.matches_path("pool/main/x_1_amd64.udeb"));
        assert!(!DebPlugin.matches_path("foo.rpm"));
    }

    #[test]
    fn schema_has_name_version_arch_control() {
        let f = DebPlugin.schema_fields();
        let names: Vec<&str> = f.iter().map(|x| x.name().as_str()).collect();
        assert_eq!(names, vec!["name", "version", "arch", "control"]);
    }

    #[test]
    fn extract_falls_back_to_filename_for_garbage() {
        let row = DebPlugin
            .extract_metadata("pool/main/zlib_1.2.11_amd64.deb", b"not a deb")
            .expect("row");
        assert_eq!(
            row.fields.get("name"),
            Some(&ExtensionValue::Str("zlib".into()))
        );
        assert_eq!(
            row.fields.get("version"),
            Some(&ExtensionValue::OptStr(Some("1.2.11".into())))
        );
        assert_eq!(
            row.fields.get("control"),
            Some(&ExtensionValue::OptStr(None))
        );
    }

    // ── host-decompressors: real control-tarball parsing ────────────────────

    /// Build a one-file `control` tar (uncompressed `ustar`).
    #[cfg(feature = "host-decompressors")]
    fn control_tar(control: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_path("./control").unwrap();
        header.set_size(control.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        b.append(&header, control.as_bytes()).unwrap();
        b.into_inner().unwrap()
    }

    /// Wrap members into a `.deb` ar archive (`!<arch>\n` + 60-byte headers).
    #[cfg(feature = "host-decompressors")]
    fn ar_build(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let mut hdr = [b' '; 60];
            let nb = name.as_bytes();
            hdr[0..nb.len()].copy_from_slice(nb);
            let size = format!("{}", data.len());
            hdr[48..48 + size.len()].copy_from_slice(size.as_bytes());
            hdr[58] = b'`';
            hdr[59] = b'\n';
            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    const SAMPLE_CONTROL: &str = "Package: hello\n\
        Version: 2.10-3\n\
        Architecture: amd64\n\
        Maintainer: Someone <a@b.c>\n\
        Depends: libc6 (>= 2.2.5)\n\
        Description: example\n\
        \x20more description\n";

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn parses_control_from_uncompressed_control_tar() {
        let tar = control_tar(SAMPLE_CONTROL);
        let deb = ar_build(&[("debian-binary", b"2.0\n"), ("control.tar", &tar)]);
        let control = DebPlugin::parse_control(&deb).expect("parses");
        let (n, v, a) = DebPlugin::control_coords(&control);
        assert_eq!(n.as_deref(), Some("hello"));
        assert_eq!(v.as_deref(), Some("2.10-3"));
        assert_eq!(a.as_deref(), Some("amd64"));
        assert!(
            control.contains("Depends: libc6 (>= 2.2.5)"),
            "real Depends flows through"
        );
    }

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn parses_control_from_xz_control_tar() {
        // dpkg's modern default control compression.
        let tar = control_tar(SAMPLE_CONTROL);
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(&tar), &mut xz).unwrap();
        let deb = ar_build(&[("debian-binary", b"2.0\n"), ("control.tar.xz", &xz)]);
        let row = DebPlugin
            .extract_metadata("pool/main/wrong_0_all.deb", &deb)
            .expect("row");
        // Header is authoritative over the (deliberately wrong) filename.
        assert_eq!(
            row.fields.get("name"),
            Some(&ExtensionValue::Str("hello".into()))
        );
        assert_eq!(
            row.fields.get("version"),
            Some(&ExtensionValue::OptStr(Some("2.10-3".into())))
        );
        match row.fields.get("control") {
            Some(ExtensionValue::OptStr(Some(c))) => assert!(c.contains("Maintainer:")),
            other => panic!("expected control stanza, got {other:?}"),
        }
    }

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn parses_control_from_zst_control_tar() {
        // Newer Ubuntu / dpkg zstd control compression, decoded via ruzstd. The
        // committed fixture is `zstd(tar(control))` for a `Package: hello` control.
        let zst = include_bytes!("testdata/control.tar.zst");
        let deb = ar_build(&[("debian-binary", b"2.0\n"), ("control.tar.zst", zst)]);
        let row = DebPlugin
            .extract_metadata("pool/main/wrong_0_all.deb", &deb)
            .expect("row");
        assert_eq!(
            row.fields.get("name"),
            Some(&ExtensionValue::Str("hello".into()))
        );
        assert_eq!(
            row.fields.get("version"),
            Some(&ExtensionValue::OptStr(Some("2.10-3".into())))
        );
        match row.fields.get("control") {
            Some(ExtensionValue::OptStr(Some(c))) => {
                assert!(
                    c.contains("Depends: libc6 (>= 2.2.5)"),
                    "real control from the .zst"
                );
            }
            other => panic!("expected control stanza, got {other:?}"),
        }
    }

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn unknown_codec_falls_back_to_filename() {
        // A codec we don't support (e.g. lzip) must degrade to the filename, not error.
        let deb = ar_build(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.lz", b"\x00\x01\x02"),
        ]);
        let (n, v, a, control) = DebPlugin::resolve("pool/main/curl_8.5.0_arm64.deb", &deb);
        assert_eq!(n, "curl");
        assert_eq!(v.as_deref(), Some("8.5.0"));
        assert_eq!(a.as_deref(), Some("arm64"));
        assert!(
            control.is_none(),
            "no control stanza for an unsupported codec"
        );
    }

    #[cfg(feature = "host-decompressors")]
    #[test]
    fn malformed_ar_never_panics() {
        for bad in [&b"!<arch>\n"[..], b"not ar at all", b"!<arch>\nshort"] {
            assert!(DebPlugin::parse_control(bad).is_none());
        }
    }
}
