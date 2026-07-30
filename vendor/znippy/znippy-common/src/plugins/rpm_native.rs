//! Native RPM plugin.
//!
//! An `.rpm` is a **Lead** (96 bytes) + a **signature header** + the **main
//! header**, then a compressed cpio payload. The authoritative NEVRA — Name,
//! Epoch, Version, Release, Arch — lives in the main header's **tag table**, NOT
//! the filename: the filename omits `Epoch` entirely (`foo-1.2-3.x86_64.rpm` says
//! nothing about `Epoch: 2`), and a renamed file would mislead a filename parser.
//!
//! The header is **uncompressed** (only the cpio payload is compressed), so
//! extraction needs no decompressor — we parse the tag table directly. The data is
//! attacker-influenced, so every read is bounds-checked; on any malformation we
//! fall back to the filename (never panic, always return a row), exactly like the
//! `gem`/`conda` native plugins.

use crate::plugin::{ArchiveTypePlugin, ExtensionRow, ExtensionValue, HandlerCommand, HandlerMeta};
use arrow::datatypes::{DataType, Field};
use std::collections::HashMap;

/// Native RPM plugin. NEVRA from the header tag table when the `.rpm` is parseable,
/// else a best-effort `(name, version, release, arch)` split from the filename.
pub struct RpmPlugin;

/// RPM lead magic (`\xed\xab\xee\xdb`).
const RPM_LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
/// RPM header-structure magic (`\x8e\xad\xe8`), shared by the signature + main header.
const RPM_HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

// Main-header tag ids.
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_SUMMARY: u32 = 1004;
const RPMTAG_VENDOR: u32 = 1011;
const RPMTAG_LICENSE: u32 = 1014;
const RPMTAG_URL: u32 = 1020;
const RPMTAG_ARCH: u32 = 1022;
const RPMTAG_SOURCERPM: u32 = 1044;
const RPMTAG_PROVIDENAME: u32 = 1047;
const RPMTAG_REQUIRENAME: u32 = 1049;

// Index-entry value types.
const RPM_TYPE_INT32: u32 = 4;
const RPM_TYPE_STRING: u32 = 6;
const RPM_TYPE_STRING_ARRAY: u32 = 8;
const RPM_TYPE_I18NSTRING: u32 = 9;

/// Metadata parsed out of an RPM main header — NEVRA plus the rpm-md `primary.xml`
/// fields (summary / license / url / vendor / sourcerpm + the provide/require
/// dependency names). All optional: a field absent from the header stays `None`/`[]`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RpmMeta {
    pub name: Option<String>,
    pub epoch: Option<u32>,
    pub version: Option<String>,
    pub release: Option<String>,
    pub arch: Option<String>,
    pub summary: Option<String>,
    pub license: Option<String>,
    pub url: Option<String>,
    pub vendor: Option<String>,
    pub sourcerpm: Option<String>,
    pub provides: Vec<String>,
    pub requires: Vec<String>,
}

impl RpmPlugin {
    fn be_u32(b: &[u8], off: usize) -> Option<u32> {
        let s = b.get(off..off.checked_add(4)?)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Parse a header structure at `pos`. Returns
    /// `(entries_offset, nindex, data_offset, data_len, total_len)` where
    /// `total_len` is the full byte length (16-byte intro + index + data). `None`
    /// if the magic is wrong or the header runs past the buffer.
    fn header_extent(b: &[u8], pos: usize) -> Option<(usize, usize, usize, usize, usize)> {
        // intro = 3 magic + 1 version + 4 reserved + 4 nindex + 4 hsize = 16 bytes
        if b.get(pos..pos.checked_add(3)?)? != RPM_HEADER_MAGIC {
            return None;
        }
        let nindex = Self::be_u32(b, pos + 8)? as usize;
        let hsize = Self::be_u32(b, pos + 12)? as usize;
        let index_bytes = nindex.checked_mul(16)?;
        let entries_off = pos.checked_add(16)?;
        let data_off = entries_off.checked_add(index_bytes)?;
        let total = 16usize.checked_add(index_bytes)?.checked_add(hsize)?;
        if pos.checked_add(total)? > b.len() {
            return None;
        }
        Some((entries_off, nindex, data_off, hsize, total))
    }

    /// Parse the metadata out of an `.rpm`'s main header. `None` on any
    /// malformation (or a header carrying no NAME/VERSION).
    pub(crate) fn parse_meta(data: &[u8]) -> Option<RpmMeta> {
        // 1. Lead magic.
        if data.get(0..4)? != RPM_LEAD_MAGIC {
            return None;
        }
        // 2. Signature header at offset 96; skip it. The main header that follows is
        //    aligned up to an 8-byte boundary.
        let (_e, _n, _d, _h, sig_total) = Self::header_extent(data, 96)?;
        let after_sig = 96usize.checked_add(sig_total)?;
        let main_pos = after_sig.checked_add(7)? & !7;
        // 3. Main header: walk the index entries, reading values out of the store.
        let (entries_off, nindex, data_off, hsize, _total) = Self::header_extent(data, main_pos)?;
        let store = data.get(data_off..data_off.checked_add(hsize)?)?;
        let mut m = RpmMeta::default();
        for i in 0..nindex {
            let e = entries_off.checked_add(i.checked_mul(16)?)?;
            let tag = Self::be_u32(data, e)?;
            let typ = Self::be_u32(data, e + 4)?;
            let off = Self::be_u32(data, e + 8)? as usize;
            let count = Self::be_u32(data, e + 12)? as usize;
            match tag {
                RPMTAG_NAME if typ == RPM_TYPE_STRING => m.name = read_cstr(store, off),
                RPMTAG_VERSION if typ == RPM_TYPE_STRING => m.version = read_cstr(store, off),
                RPMTAG_RELEASE if typ == RPM_TYPE_STRING => m.release = read_cstr(store, off),
                RPMTAG_ARCH if typ == RPM_TYPE_STRING => m.arch = read_cstr(store, off),
                RPMTAG_LICENSE if typ == RPM_TYPE_STRING => m.license = read_cstr(store, off),
                RPMTAG_URL if typ == RPM_TYPE_STRING => m.url = read_cstr(store, off),
                RPMTAG_VENDOR if typ == RPM_TYPE_STRING => m.vendor = read_cstr(store, off),
                RPMTAG_SOURCERPM if typ == RPM_TYPE_STRING => m.sourcerpm = read_cstr(store, off),
                // SUMMARY is an I18NSTRING (one string per locale); the first is the
                // C-locale default. Accept a plain STRING too, defensively.
                RPMTAG_SUMMARY if typ == RPM_TYPE_I18NSTRING || typ == RPM_TYPE_STRING => {
                    m.summary = read_cstr(store, off)
                }
                RPMTAG_EPOCH if typ == RPM_TYPE_INT32 => m.epoch = Self::be_u32(store, off),
                RPMTAG_PROVIDENAME if typ == RPM_TYPE_STRING_ARRAY => {
                    m.provides = read_string_array(store, off, count)
                }
                RPMTAG_REQUIRENAME if typ == RPM_TYPE_STRING_ARRAY => {
                    m.requires = read_string_array(store, off, count)
                }
                _ => {}
            }
        }
        // A real main header carries at least NAME + VERSION.
        (m.name.is_some() && m.version.is_some()).then_some(m)
    }

    /// Best-effort `(name, version, release, arch)` from a canonical NEVRA filename
    /// `{name}-{version}-{release}.{arch}.rpm` (no epoch — that only lives in the
    /// header). The fallback when the `.rpm` can't be parsed.
    fn parse_filename(path: &str) -> (String, Option<String>, Option<String>, Option<String>) {
        let fname = path.rsplit('/').next().unwrap_or(path);
        let Some(stem) = fname.strip_suffix(".rpm") else {
            return (fname.to_string(), None, None, None);
        };
        let Some((rest, arch)) = stem.rsplit_once('.') else {
            return (stem.to_string(), None, None, None);
        };
        let Some((name_ver, release)) = rest.rsplit_once('-') else {
            return (stem.to_string(), None, None, Some(arch.to_string()));
        };
        let Some((name, version)) = name_ver.rsplit_once('-') else {
            return (rest.to_string(), None, None, Some(arch.to_string()));
        };
        (
            name.to_string(),
            Some(version.to_string()),
            Some(release.to_string()),
            Some(arch.to_string()),
        )
    }
}

/// Read a NUL-terminated UTF-8(-lossy) string from `store` at `off`.
fn read_cstr(store: &[u8], off: usize) -> Option<String> {
    let s = store.get(off..)?;
    let end = s.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&s[..end]).into_owned())
}

/// Read `count` consecutive NUL-terminated strings (an RPM `STRING_ARRAY`) from
/// `store` at `off`. Bounded + bounds-checked: stops at the store end (a truncated
/// array yields the strings read so far) and caps the iteration so a lying `count`
/// can't spin.
fn read_string_array(store: &[u8], off: usize, count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(count.min(1024));
    let mut pos = off;
    for _ in 0..count.min(100_000) {
        let Some(s) = store.get(pos..) else { break };
        let Some(end) = s.iter().position(|&b| b == 0) else {
            break;
        };
        out.push(String::from_utf8_lossy(&s[..end]).into_owned());
        pos = pos.saturating_add(end + 1);
    }
    out
}

/// Join a dependency-name list into a newline-separated column value (`None` when
/// empty), the shape [`RpmView`](crate::views::RpmView) splits back apart.
fn join_lines(v: &[String]) -> Option<String> {
    (!v.is_empty()).then(|| v.join("\n"))
}

impl ArchiveTypePlugin for RpmPlugin {
    fn name(&self) -> &str {
        "rpm"
    }

    fn type_id(&self) -> i8 {
        8
    }

    fn meta(&self) -> HandlerMeta {
        HandlerMeta {
            name: "rpm".into(),
            aliases: vec!["yum".into(), "dnf".into(), "redhat".into()],
            type_id: 8,
            ecosystem: "RPM / Red Hat family (dnf/yum)".into(),
            extensions: vec![".rpm".into()],
            description:
                "RPM packages — authoritative NEVRA (incl. epoch) from the header tag table".into(),
            commands: vec![HandlerCommand::new(
                "coords",
                "Print rpm name + version (header if readable, else filename)",
            )],
        }
    }

    fn run_command(&self, cmd: &str, args: &[String]) -> anyhow::Result<()> {
        match cmd {
            "coords" => {
                let path = args
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("usage: rpm coords <file.rpm>"))?;
                let (name, version, _r, _a) = Self::parse_filename(path);
                match version {
                    Some(v) => println!("{} {}", name, v),
                    None => println!("{}", name),
                }
                Ok(())
            }
            other => anyhow::bail!("rpm: unknown subcommand '{}'", other),
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        path.ends_with(".rpm")
    }

    /// Columns the read-side [`RpmView`](crate::views::RpmView) resolves on: the
    /// NEVRA (`epoch` is the field the filename can't supply) plus the rpm-md
    /// `primary.xml` metadata — summary/license/url/vendor/sourcerpm and the
    /// newline-joined provide/require dependency names.
    fn schema_fields(&self) -> Vec<Field> {
        [
            "name",
            "version",
            "release",
            "arch",
            "epoch",
            "summary",
            "license",
            "url",
            "vendor",
            "sourcerpm",
            "provides",
            "requires",
        ]
        .iter()
        .map(|n| Field::new(*n, DataType::Utf8, true))
        .collect()
    }

    fn extract_metadata(&self, path: &str, data: &[u8]) -> Option<ExtensionRow> {
        // Authoritative header first; on any parse failure fall back to the
        // filename NEVRA (no rich metadata, exactly as before).
        let m = Self::parse_meta(data);
        let mut fields = HashMap::new();
        let put = |fields: &mut HashMap<String, ExtensionValue>, k: &str, v: Option<String>| {
            fields.insert(k.to_string(), ExtensionValue::OptStr(v));
        };
        match m {
            Some(m) => {
                fields.insert(
                    "name".into(),
                    ExtensionValue::Str(m.name.unwrap_or_default()),
                );
                put(&mut fields, "version", m.version);
                put(&mut fields, "release", m.release);
                put(&mut fields, "arch", m.arch);
                put(&mut fields, "epoch", m.epoch.map(|e| e.to_string()));
                put(&mut fields, "summary", m.summary);
                put(&mut fields, "license", m.license);
                put(&mut fields, "url", m.url);
                put(&mut fields, "vendor", m.vendor);
                put(&mut fields, "sourcerpm", m.sourcerpm);
                put(&mut fields, "provides", join_lines(&m.provides));
                put(&mut fields, "requires", join_lines(&m.requires));
            }
            None => {
                let (name, version, release, arch) = Self::parse_filename(path);
                fields.insert("name".into(), ExtensionValue::Str(name));
                put(&mut fields, "version", version);
                put(&mut fields, "release", release);
                put(&mut fields, "arch", arch);
                for k in [
                    "epoch",
                    "summary",
                    "license",
                    "url",
                    "vendor",
                    "sourcerpm",
                    "provides",
                    "requires",
                ] {
                    put(&mut fields, k, None);
                }
            }
        }
        Some(ExtensionRow { fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RPM header structure (intro + index entries + data store).
    fn build_header(entries: &[(u32, u32, u32, u32)], store: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&RPM_HEADER_MAGIC);
        h.push(0x01); // version
        h.extend_from_slice(&[0, 0, 0, 0]); // reserved
        h.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        h.extend_from_slice(&(store.len() as u32).to_be_bytes());
        for (tag, typ, off, count) in entries {
            h.extend_from_slice(&tag.to_be_bytes());
            h.extend_from_slice(&typ.to_be_bytes());
            h.extend_from_slice(&off.to_be_bytes());
            h.extend_from_slice(&count.to_be_bytes());
        }
        h.extend_from_slice(store);
        h
    }

    /// A whole synthetic `.rpm`: lead + (empty) signature header + main header.
    fn build_rpm(nevra_entries: &[(u32, u32, u32, u32)], store: &[u8]) -> Vec<u8> {
        let mut rpm = vec![0u8; 96];
        rpm[0..4].copy_from_slice(&RPM_LEAD_MAGIC);
        // Empty signature header (0 index entries, 0 data).
        let sig = build_header(&[], &[]);
        rpm.extend_from_slice(&sig);
        // Pad to an 8-byte boundary before the main header.
        while rpm.len() % 8 != 0 {
            rpm.push(0);
        }
        rpm.extend_from_slice(&build_header(nevra_entries, store));
        rpm
    }

    #[test]
    fn parses_real_nevra_including_epoch_from_header() {
        // store: "bash\0" @0, "5.1.8\0" @5, "1.el9\0" @11, "x86_64\0" @17
        let mut store = Vec::new();
        let name_off = store.len() as u32;
        store.extend_from_slice(b"bash\0");
        let ver_off = store.len() as u32;
        store.extend_from_slice(b"5.1.8\0");
        let rel_off = store.len() as u32;
        store.extend_from_slice(b"1.el9\0");
        let arch_off = store.len() as u32;
        store.extend_from_slice(b"x86_64\0");
        let epoch_off = store.len() as u32;
        store.extend_from_slice(&2u32.to_be_bytes()); // EPOCH = 2 (INT32)

        let entries = [
            (RPMTAG_NAME, RPM_TYPE_STRING, name_off, 1),
            (RPMTAG_VERSION, RPM_TYPE_STRING, ver_off, 1),
            (RPMTAG_RELEASE, RPM_TYPE_STRING, rel_off, 1),
            (RPMTAG_ARCH, RPM_TYPE_STRING, arch_off, 1),
            (RPMTAG_EPOCH, RPM_TYPE_INT32, epoch_off, 1),
        ];
        let rpm = build_rpm(&entries, &store);
        let n = RpmPlugin::parse_meta(&rpm).expect("parses");
        assert_eq!(n.name.as_deref(), Some("bash"));
        assert_eq!(n.version.as_deref(), Some("5.1.8"));
        assert_eq!(n.release.as_deref(), Some("1.el9"));
        assert_eq!(n.arch.as_deref(), Some("x86_64"));
        assert_eq!(
            n.epoch,
            Some(2),
            "epoch comes from the header — the filename omits it"
        );
    }

    #[test]
    fn falls_back_to_filename_when_not_an_rpm() {
        // Bytes without the lead magic ⇒ parse_nevra None ⇒ filename fallback.
        assert!(RpmPlugin::parse_meta(b"not an rpm").is_none());
        let row = RpmPlugin
            .extract_metadata("Packages/zlib-1.2.11-31.el9.x86_64.rpm", b"garbage")
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
            row.fields.get("arch"),
            Some(&ExtensionValue::OptStr(Some("x86_64".into())))
        );
        // No epoch recoverable from a filename.
        assert_eq!(row.fields.get("epoch"), Some(&ExtensionValue::OptStr(None)));
    }

    #[test]
    fn extract_prefers_header_over_filename() {
        // A header that says epoch=7/version=9.9 while the filename says version=1.0:
        // the header wins.
        let mut store = Vec::new();
        store.extend_from_slice(b"curl\0"); // name @0
        let ver_off = store.len() as u32;
        store.extend_from_slice(b"9.9\0"); // version
        let epoch_off = store.len() as u32;
        store.extend_from_slice(&7u32.to_be_bytes());
        let entries = [
            (RPMTAG_NAME, RPM_TYPE_STRING, 0, 1),
            (RPMTAG_VERSION, RPM_TYPE_STRING, ver_off, 1),
            (RPMTAG_EPOCH, RPM_TYPE_INT32, epoch_off, 1),
        ];
        let rpm = build_rpm(&entries, &store);
        let row = RpmPlugin
            .extract_metadata("Packages/curl-1.0-1.noarch.rpm", &rpm)
            .unwrap();
        assert_eq!(
            row.fields.get("name"),
            Some(&ExtensionValue::Str("curl".into()))
        );
        assert_eq!(
            row.fields.get("version"),
            Some(&ExtensionValue::OptStr(Some("9.9".into())))
        );
        assert_eq!(
            row.fields.get("epoch"),
            Some(&ExtensionValue::OptStr(Some("7".into())))
        );
    }

    #[test]
    fn matches_rpm_only() {
        assert!(RpmPlugin.matches_path("Packages/foo-1.0-1.x86_64.rpm"));
        assert!(!RpmPlugin.matches_path("foo.deb"));
    }

    #[test]
    fn schema_has_nevra_and_primary_columns() {
        let f = RpmPlugin.schema_fields();
        let names: Vec<&str> = f.iter().map(|x| x.name().as_str()).collect();
        assert_eq!(
            names,
            vec![
                "name",
                "version",
                "release",
                "arch",
                "epoch",
                "summary",
                "license",
                "url",
                "vendor",
                "sourcerpm",
                "provides",
                "requires"
            ]
        );
    }

    #[test]
    fn extracts_rich_primary_fields() {
        // A header carrying the rpm-md primary fields — summary (I18NSTRING),
        // license/url/sourcerpm (STRING), and provide/require names (STRING_ARRAY).
        let mut store = Vec::new();
        store.extend_from_slice(b"curl\0"); // name @0
        let ver = store.len() as u32;
        store.extend_from_slice(b"8.0\0");
        let sum = store.len() as u32;
        store.extend_from_slice(b"A URL transfer tool\0");
        let lic = store.len() as u32;
        store.extend_from_slice(b"MIT\0");
        let url = store.len() as u32;
        store.extend_from_slice(b"https://curl.se\0");
        let src = store.len() as u32;
        store.extend_from_slice(b"curl-8.0-1.src.rpm\0");
        let prov = store.len() as u32;
        store.extend_from_slice(b"curl\0libcurl\0"); // 2 strings
        let req = store.len() as u32;
        store.extend_from_slice(b"/bin/sh\0libc.so.6\0"); // 2 strings
        let entries = [
            (RPMTAG_NAME, RPM_TYPE_STRING, 0, 1),
            (RPMTAG_VERSION, RPM_TYPE_STRING, ver, 1),
            (RPMTAG_SUMMARY, RPM_TYPE_I18NSTRING, sum, 1),
            (RPMTAG_LICENSE, RPM_TYPE_STRING, lic, 1),
            (RPMTAG_URL, RPM_TYPE_STRING, url, 1),
            (RPMTAG_SOURCERPM, RPM_TYPE_STRING, src, 1),
            (RPMTAG_PROVIDENAME, RPM_TYPE_STRING_ARRAY, prov, 2),
            (RPMTAG_REQUIRENAME, RPM_TYPE_STRING_ARRAY, req, 2),
        ];
        let rpm = build_rpm(&entries, &store);
        let m = RpmPlugin::parse_meta(&rpm).unwrap();
        assert_eq!(m.summary.as_deref(), Some("A URL transfer tool"));
        assert_eq!(m.license.as_deref(), Some("MIT"));
        assert_eq!(m.url.as_deref(), Some("https://curl.se"));
        assert_eq!(m.sourcerpm.as_deref(), Some("curl-8.0-1.src.rpm"));
        assert_eq!(m.provides, vec!["curl", "libcurl"]);
        assert_eq!(m.requires, vec!["/bin/sh", "libc.so.6"]);
        // extract_metadata surfaces them as columns (dep names newline-joined).
        let row = RpmPlugin.extract_metadata("x.rpm", &rpm).unwrap();
        assert_eq!(
            row.fields.get("license"),
            Some(&ExtensionValue::OptStr(Some("MIT".into())))
        );
        assert_eq!(
            row.fields.get("provides"),
            Some(&ExtensionValue::OptStr(Some("curl\nlibcurl".into())))
        );
        assert_eq!(
            row.fields.get("requires"),
            Some(&ExtensionValue::OptStr(Some("/bin/sh\nlibc.so.6".into())))
        );
    }

    #[test]
    fn malformed_headers_never_panic() {
        // Truncated / lying-length inputs must return None, not panic.
        for bad in [
            vec![0xed, 0xab, 0xee, 0xdb], // lead magic only
            {
                let mut v = vec![0u8; 96];
                v[0..4].copy_from_slice(&RPM_LEAD_MAGIC);
                v.extend_from_slice(&RPM_HEADER_MAGIC); // sig magic, then truncated
                v
            },
            {
                // sig header claims a huge nindex
                let mut v = vec![0u8; 96];
                v[0..4].copy_from_slice(&RPM_LEAD_MAGIC);
                v.extend_from_slice(&RPM_HEADER_MAGIC);
                v.push(1);
                v.extend_from_slice(&[0, 0, 0, 0]);
                v.extend_from_slice(&u32::MAX.to_be_bytes()); // nindex = huge
                v.extend_from_slice(&u32::MAX.to_be_bytes()); // hsize = huge
                v
            },
        ] {
            assert!(RpmPlugin::parse_meta(&bad).is_none());
        }
    }
}
