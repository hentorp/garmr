// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 11 — the pure air-gap BUNDLE vocabulary: a content-addressed manifest of
//! a whole release + its deterministic signed-over encoding + offline verifiers.
//! No I/O, no crypto, no new dep (blake3 + serde + `frame` only). All signing and
//! file I/O live at the garmr-cli edge, so garmr-core stays runtime-free (the same
//! boundary rule as [`crate::egress`]).
//!
//! A bundle is "a signed release": the manifest lists every shipped artifact by
//! BLAKE3 digest, is framed by hand (domain-separated, fixed field order, entries
//! sorted so the id is filesystem-walk-order independent), and is ed25519-signed
//! with the operator's audit key. Verification recomputes every digest + the
//! manifest digest and checks the signature against an OUT-OF-BAND trusted key —
//! the bundle's own embedded public key is NEVER a trust root.

use serde::{Deserialize, Serialize};

use crate::{frame, registry::ReleaseSpec};

/// Bundle manifest format version.
pub const BUNDLE_FORMAT: u16 = 1;

/// What a bundle entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleEntryKind {
    Binary,
    SigmaRule,
    CorrelationRule,
    Hunt,
    ConfigTemplate,
    RegistryRecord,
    Sbom,
    Provenance,
    ModelNote,
    Other,
    #[default]
    #[serde(other)]
    Unknown,
}

impl BundleEntryKind {
    pub fn tag(self) -> &'static str {
        match self {
            BundleEntryKind::Binary => "binary",
            BundleEntryKind::SigmaRule => "sigma_rule",
            BundleEntryKind::CorrelationRule => "correlation_rule",
            BundleEntryKind::Hunt => "hunt",
            BundleEntryKind::ConfigTemplate => "config_template",
            BundleEntryKind::RegistryRecord => "registry_record",
            BundleEntryKind::Sbom => "sbom",
            BundleEntryKind::Provenance => "provenance",
            BundleEntryKind::ModelNote => "model_note",
            BundleEntryKind::Other => "other",
            BundleEntryKind::Unknown => "unknown",
        }
    }
}

/// One content-addressed file in the bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleEntry {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub kind: BundleEntryKind,
    /// BLAKE3-hex of the file contents.
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub size_bytes: u64,
}

/// A note about a model the release EXPECTS (as an external process — never the
/// weights). Commits to WHICH model answered, for provenance/reproducibility.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelNote {
    #[serde(default)]
    pub logical_name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub descriptor_digest: String,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub note: String,
}

/// The bundle manifest (the signed-over content).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    #[serde(default)]
    pub format_version: u16,
    /// The content id = the manifest digest (set after framing; NOT signed over).
    #[serde(default)]
    pub bundle_id: String,
    #[serde(default)]
    pub created_at_us: i64,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub garmr_version: String,
    #[serde(default)]
    pub git_commit: String,
    #[serde(default)]
    pub release_name: String,
    #[serde(default)]
    pub release_version: String,
    /// The canonical [`release_digest`] of the release this bundle carries.
    #[serde(default)]
    pub release_digest: String,
    #[serde(default)]
    pub entries: Vec<BundleEntry>,
    #[serde(default)]
    pub model_notes: Vec<ModelNote>,
    #[serde(default)]
    pub notes: String,
}

/// A manifest + its signature. `public_key` is a DISPLAY convenience copy only —
/// verification requires an out-of-band trusted key, never this field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    #[serde(default)]
    pub manifest: BundleManifest,
    #[serde(default)]
    pub manifest_digest: String,
    #[serde(default)]
    pub signature_format: String,
    #[serde(default)]
    pub signing_key_id: String,
    /// A copy of the signer's public key (hex) for display/key-id — NOT a trust
    /// root. An out-of-band trusted key is required to verify.
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub signature: String,
}

/// A verification finding — empty vec == the checked property holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFinding {
    /// `missing_file` | `digest_mismatch` | `unexpected_file` | `unsafe_path` |
    /// `manifest_digest` | `release_binding`.
    pub category: String,
    pub coord: String,
    pub detail: String,
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u64).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
}

fn put_u64(b: &mut Vec<u8>, n: u64) {
    b.extend_from_slice(&n.to_le_bytes());
}

/// The exact bytes signed over: domain-separated, fixed field order, entries +
/// model notes SORTED (so the signature is independent of the filesystem walk
/// order). Excludes `bundle_id` (which IS this body's digest) and the signature.
pub fn canonical_manifest_body(m: &BundleManifest) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"garmr-bundle-manifest\x01");
    put_u64(&mut b, m.format_version as u64);
    put_u64(&mut b, m.created_at_us as u64);
    put_str(&mut b, &m.node_id);
    put_str(&mut b, &m.garmr_version);
    put_str(&mut b, &m.git_commit);
    put_str(&mut b, &m.release_name);
    put_str(&mut b, &m.release_version);
    put_str(&mut b, &m.release_digest);

    let mut entries = m.entries.clone();
    entries.sort_by(|a, b| (a.kind.tag(), &a.path).cmp(&(b.kind.tag(), &b.path)));
    put_u64(&mut b, entries.len() as u64);
    for e in &entries {
        put_str(&mut b, e.kind.tag());
        put_str(&mut b, &e.path);
        put_str(&mut b, &e.digest);
        put_u64(&mut b, e.size_bytes);
    }

    let mut notes = m.model_notes.clone();
    notes.sort_by(|a, b| a.logical_name.cmp(&b.logical_name));
    put_u64(&mut b, notes.len() as u64);
    for n in &notes {
        put_str(&mut b, &n.logical_name);
        put_str(&mut b, &n.provider);
        put_str(&mut b, &n.descriptor_digest);
        put_u64(&mut b, n.external as u64);
        put_str(&mut b, &n.note);
    }
    put_str(&mut b, &m.notes);
    b
}

/// The manifest content digest (BLAKE3-hex of the canonical body).
pub fn manifest_digest(m: &BundleManifest) -> String {
    blake3::hash(&canonical_manifest_body(m))
        .to_hex()
        .to_string()
}

/// THE canonical release digest — length-framed over the [`ReleaseSpec`] fields
/// in a fixed order (FIX#3: one function, used by build + verify + import, so the
/// release binding is real and not an ad-hoc recompute).
pub fn release_digest(spec: &ReleaseSpec) -> String {
    frame(&[
        b"garmr-release",
        spec.model_ref.as_bytes(),
        spec.embed_ref.as_deref().unwrap_or("").as_bytes(),
        spec.reranker_ref.as_deref().unwrap_or("").as_bytes(),
        spec.prompt_ref.as_bytes(),
        spec.toolset_ref.as_bytes(),
        spec.ruleset_digest.as_bytes(),
        spec.detector_config_ref.as_bytes(),
        spec.feature_refs.join(",").as_bytes(),
        spec.eval_evidence.join(",").as_bytes(),
    ])
}

/// Is a manifest/tree path safe to write on import? Rejects absolute paths, a
/// leading slash, any `..` component, and Windows drive/backslash forms — the
/// string half of FIX#2 (the CLI adds the symlink/canonicalize check).
pub fn is_safe_relative_path(p: &str) -> bool {
    if p.is_empty() || p.starts_with('/') || p.starts_with('\\') || p.contains('\\') {
        return false;
    }
    if p.len() >= 2 && p.as_bytes()[1] == b':' {
        return false; // drive letter
    }
    !std::path::Path::new(p).components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    })
}

/// Compare the manifest's declared entries against the digests actually computed
/// from the bundle tree. `strict_extra` (FIX#2) flags any computed file NOT in the
/// manifest as an `unexpected_file` (the caller pre-excludes the envelope files).
/// Also flags any entry whose path is unsafe. Empty vec == the bundle matches.
pub fn diff_entries(
    manifest: &BundleManifest,
    computed: &std::collections::BTreeMap<String, String>,
    strict_extra: bool,
) -> Vec<BundleFinding> {
    let mut out = Vec::new();
    let declared: std::collections::BTreeSet<&str> =
        manifest.entries.iter().map(|e| e.path.as_str()).collect();
    for e in &manifest.entries {
        if !is_safe_relative_path(&e.path) {
            out.push(BundleFinding {
                category: "unsafe_path".into(),
                coord: e.path.clone(),
                detail: "manifest entry path is absolute, escaping, or malformed".into(),
            });
            continue;
        }
        match computed.get(&e.path) {
            None => out.push(BundleFinding {
                category: "missing_file".into(),
                coord: e.path.clone(),
                detail: "declared in the manifest but absent from the bundle".into(),
            }),
            Some(d) if *d != e.digest => out.push(BundleFinding {
                category: "digest_mismatch".into(),
                coord: e.path.clone(),
                detail: format!("expected {}, computed {d}", e.digest),
            }),
            Some(_) => {}
        }
    }
    if strict_extra {
        for path in computed.keys() {
            if !declared.contains(path.as_str()) {
                out.push(BundleFinding {
                    category: "unexpected_file".into(),
                    coord: path.clone(),
                    detail: "present in the bundle but NOT covered by the signed manifest".into(),
                });
            }
        }
    }
    out
}

/// Verify the stamped manifest digest matches the recomputed canonical body.
pub fn verify_manifest_digest(sb: &SignedBundle) -> bool {
    !sb.manifest_digest.is_empty() && sb.manifest_digest == manifest_digest(&sb.manifest)
}

/// Verify the manifest's release binding: the carried `ReleaseSpec` re-derives to
/// the manifest's `release_digest` AND to the record's `content_digest` (catches
/// a swapped release — FIX#3).
pub fn verify_release_binding(
    m: &BundleManifest,
    spec: &ReleaseSpec,
    record_digest: &str,
) -> Vec<BundleFinding> {
    let mut out = Vec::new();
    let d = release_digest(spec);
    if d != m.release_digest {
        out.push(BundleFinding {
            category: "release_binding".into(),
            coord: m.release_name.clone(),
            detail: format!(
                "release spec digest {d} != manifest release_digest {}",
                m.release_digest
            ),
        });
    }
    if d != record_digest {
        out.push(BundleFinding {
            category: "release_binding".into(),
            coord: m.release_name.clone(),
            detail: format!("release spec digest {d} != record content_digest {record_digest}"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn entry(path: &str, kind: BundleEntryKind, digest: &str) -> BundleEntry {
        BundleEntry {
            path: path.into(),
            kind,
            digest: digest.into(),
            size_bytes: 1,
        }
    }

    fn manifest() -> BundleManifest {
        BundleManifest {
            format_version: BUNDLE_FORMAT,
            release_name: "garmr".into(),
            entries: vec![
                entry("bin/garmr", BundleEntryKind::Binary, "d1"),
                entry("rules/a.yml", BundleEntryKind::SigmaRule, "d2"),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn empty_object_decodes() {
        let _: SignedBundle = serde_json::from_str("{}").unwrap();
        let _: BundleManifest = serde_json::from_str("{}").unwrap();
    }

    #[test]
    fn manifest_digest_is_walk_order_independent_but_content_sensitive() {
        let a = manifest();
        let mut b = manifest();
        b.entries.reverse(); // different walk order, same content
        assert_eq!(manifest_digest(&a), manifest_digest(&b));
        let mut c = manifest();
        c.entries[0].digest = "TAMPERED".into();
        assert_ne!(manifest_digest(&a), manifest_digest(&c));
    }

    #[test]
    fn framing_is_injective() {
        // ["a","bc"] frames differently from ["ab","c"] (length-framed).
        let m1 = BundleManifest {
            node_id: "a".into(),
            garmr_version: "bc".into(),
            ..Default::default()
        };
        let m2 = BundleManifest {
            node_id: "ab".into(),
            garmr_version: "c".into(),
            ..Default::default()
        };
        assert_ne!(manifest_digest(&m1), manifest_digest(&m2));
    }

    #[test]
    fn diff_flags_missing_mismatch_and_strict_extra() {
        let m = manifest();
        let mut computed = BTreeMap::new();
        computed.insert("bin/garmr".to_string(), "d1".to_string()); // ok
        computed.insert("rules/a.yml".to_string(), "WRONG".to_string()); // mismatch
        computed.insert("rules/evil.yml".to_string(), "x".to_string()); // unmanifested
        let f = diff_entries(&m, &computed, true);
        assert!(f.iter().any(|x| x.category == "digest_mismatch"));
        assert!(f
            .iter()
            .any(|x| x.category == "unexpected_file" && x.coord == "rules/evil.yml"));
        // A missing declared file.
        computed.remove("bin/garmr");
        assert!(diff_entries(&m, &computed, false)
            .iter()
            .any(|x| x.category == "missing_file"));
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        assert!(is_safe_relative_path("rules/a.yml"));
        assert!(!is_safe_relative_path("/etc/passwd"));
        assert!(!is_safe_relative_path("../../etc/cron.d/x"));
        assert!(!is_safe_relative_path("a/../../b"));
        assert!(!is_safe_relative_path("C:\\x"));
        let m = BundleManifest {
            entries: vec![entry("../evil", BundleEntryKind::Other, "d")],
            ..Default::default()
        };
        let f = diff_entries(&m, &BTreeMap::new(), false);
        assert!(f.iter().any(|x| x.category == "unsafe_path"));
    }

    #[test]
    fn release_digest_is_stable_and_field_sensitive() {
        let mut spec = ReleaseSpec {
            model_ref: "m".into(),
            prompt_ref: "p".into(),
            ..Default::default()
        };
        let d1 = release_digest(&spec);
        assert_eq!(d1, release_digest(&spec.clone()));
        spec.prompt_ref = "p2".into();
        assert_ne!(d1, release_digest(&spec));
    }
}
