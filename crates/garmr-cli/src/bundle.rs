// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr bundle` — build/sign/verify (and, in c3, import/rollback) a signed,
//! content-addressed AIR-GAP release bundle. All crypto + file I/O live here; the
//! pure manifest vocabulary + verifiers are in `garmr_core::bundle`. Build/verify
//! reach NO network (no egress).
//!
//! Trust model (FIX#1): verification requires an OUT-OF-BAND trusted key — an
//! explicit `--key`, else the operator's OWN local `audit.dir/public_key.hex`.
//! The public key EMBEDDED in the bundle is NEVER a trust root; without a local
//! trusted key, verify reports UNVERIFIED and exits non-zero (never "OK").

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use garmr_audit::action::BUNDLE_IMPORT;
use garmr_audit::{Signer, SoftwareSigner};
use garmr_core::{
    diff_entries, is_safe_relative_path, manifest_digest, release_digest, verify_manifest_digest,
    verify_release_binding, BundleEntry, BundleEntryKind, BundleManifest, ModelNote, RegistryKind,
    RegistryRecord, ReleaseSpec, SignedBundle,
};
use garmr_store::Store;

use crate::cli::{BundleCmd, Cli};

const ENVELOPE_FILES: &[&str] = &["bundle.json", "public_key.hex"];

pub(crate) async fn bundle_cmd(cli: &Cli, what: &BundleCmd) -> Result<()> {
    match what {
        BundleCmd::Build {
            dir,
            binary,
            signing_key,
        } => build(cli, dir, binary.as_deref(), signing_key.as_deref()),
        BundleCmd::Verify { dir, key } => {
            let findings = verify(cli, dir, key.as_deref())?;
            if !findings.is_empty() {
                bail!("bundle verification FAILED: {} finding(s)", findings.len());
            }
            println!("bundle OK");
            Ok(())
        }
        BundleCmd::Show { dir } => show(dir),
        BundleCmd::Import {
            dir,
            key,
            channel,
            version,
            reason,
            dry_run,
        } => {
            import(
                cli,
                dir,
                key.as_deref(),
                channel,
                version.as_deref(),
                reason,
                *dry_run,
            )
            .await
        }
        BundleCmd::Rollback {
            to_version,
            channel,
            reason,
        } => rollback(cli, to_version, channel, reason).await,
    }
}

fn parse_key(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("--key must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("--key must be exactly 32 bytes (64 hex chars)"))
}

/// Append an audited (fail-closed) promotion for the release. Reused by import
/// (Promote) and rollback (Rollback), both OFFLINE via direct store writes — so
/// reversal works serve-stopped on an air-gap host (FIX#4).
fn audited_promotion(
    store: &Store,
    op: &str,
    version: &str,
    target_digest: &str,
    channel: &str,
    reason: &str,
) -> Result<()> {
    let coord = format!("garmr@{version}");
    let audit_id = crate::audit::record_admin_local(
        BUNDLE_IMPORT,
        "registry_promotion",
        Some(&coord),
        Some(&format!("{op}: {reason}")),
    )?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "auditing is disabled — a bundle apply must be audited (set audit.enabled = true)"
        )
    })?;
    let ev: garmr_core::PromotionEvent = serde_json::from_value(serde_json::json!({
        "promotion_id": uuid::Uuid::new_v4().to_string(),
        "kind": "release",
        "name": "garmr",
        "op": op,
        "to_version": version,
        "to_state": "approved",
        "channel": channel,
        "target_digest": target_digest,
        "reason": reason,
        "actor": "cli",
        "audit_id": audit_id,
    }))?;
    store.state.append_promotion(&ev)?;
    Ok(())
}

async fn import(
    cli: &Cli,
    dir: &Path,
    key: Option<&str>,
    channel: &str,
    version: Option<&str>,
    reason: &str,
    dry_run: bool,
) -> Result<()> {
    let cfg = crate::load_config(cli)?;
    // FIX#1: import REQUIRES an out-of-band trusted key (only --dry-run may skip).
    let trust = match key {
        Some(k) => Some(parse_key(k)?),
        None if dry_run => None,
        None => bail!(
            "import requires --key <hex> (the out-of-band trusted key); use --dry-run to preview"
        ),
    };

    // Verify FIRST — verify-before-apply (invariant #4).
    let findings = verify_bundle(dir, trust)?;

    // Read the release record + FIX#3: the digests must agree, never override.
    let record: RegistryRecord = serde_json::from_slice(&std::fs::read(dir.join("release.json"))?)
        .context("decoding release.json")?;
    let spec: ReleaseSpec =
        serde_json::from_value(record.spec.clone()).context("decoding the release spec")?;
    let sb: SignedBundle = serde_json::from_slice(&std::fs::read(dir.join("bundle.json"))?)?;
    let computed = release_digest(&spec);
    let digests_agree = computed == record.content_digest && computed == sb.manifest.release_digest;

    let ver = version.unwrap_or(&record.version).to_string();
    if dry_run {
        println!("dry-run: would import release garmr@{ver} (release {computed}) to {channel}");
        println!("  verification findings: {}", findings.len());
        println!("  release digests agree: {digests_agree}");
        println!("  nothing written");
        return Ok(());
    }

    if !findings.is_empty() {
        bail!(
            "refusing to import — {} verification finding(s) (run `garmr bundle verify --key …`)",
            findings.len()
        );
    }
    if !digests_agree {
        bail!(
            "refusing to import — release digest mismatch (record {}, manifest {}, computed {computed})",
            record.content_digest,
            sb.manifest.release_digest
        );
    }
    crate::audit::ensure_init(&cfg.audit)?;
    // Refuse an UNAUDITABLE import BEFORE any store write (review fix): ensure_init
    // is a no-op when audit.enabled=false, so check up front — otherwise the
    // record would be committed and only the later promotion would fail.
    if !cfg.audit.enabled {
        bail!("auditing is disabled — an import must be audited (set audit.enabled = true)");
    }

    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable) — run with serve stopped")?;
    // Register the immutable record. A same-version/different-digest Conflict is
    // FATAL (review fix): promoting to a digest whose record was NOT stored would
    // leave a dangling pointer and knock the live release offline. Re-import a
    // changed bundle under a fresh --version.
    let mut rec = record.clone();
    rec.version = ver.clone();
    match store.state.register_record(&rec)? {
        garmr_store::state::RegisterOutcome::Conflict { existing_digest } => bail!(
            "release garmr@{ver} already registered with a DIFFERENT digest ({existing_digest}); \
             re-import under a fresh --version",
        ),
        garmr_store::state::RegisterOutcome::Inserted
        | garmr_store::state::RegisterOutcome::AlreadyIdentical => {}
    }
    audited_promotion(
        &store,
        "promote",
        &ver,
        &record.content_digest,
        channel,
        reason,
    )?;
    println!("imported release garmr@{ver} → active on {channel} (reversible: garmr bundle rollback <prev-version>)");
    Ok(())
}

async fn rollback(cli: &Cli, to_version: &str, channel: &str, reason: &str) -> Result<()> {
    let cfg = crate::load_config(cli)?;
    crate::audit::ensure_init(&cfg.audit)?;
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable) — run with serve stopped")?;
    let rec = store
        .state
        .get_record(RegistryKind::Release, "garmr", to_version)?
        .with_context(|| format!("no release record garmr@{to_version} to roll back to"))?;
    audited_promotion(
        &store,
        "rollback",
        to_version,
        &rec.content_digest,
        channel,
        reason,
    )?;
    println!("rolled back garmr → {to_version} active on {channel}");
    Ok(())
}

// ---- build -----------------------------------------------------------------

pub(crate) fn stream_digest(path: &Path) -> Result<(String, u64)> {
    let mut hasher = blake3::Hasher::new();
    let mut f = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let n = std::io::copy(&mut f, &mut hasher).context("hashing")?;
    Ok((hasher.finalize().to_hex().to_string(), n))
}

/// Copy a file into the bundle at `rel`, recording a BundleEntry.
fn add_file(
    bundle_dir: &Path,
    rel: &str,
    src_bytes: &[u8],
    kind: BundleEntryKind,
    entries: &mut Vec<BundleEntry>,
) -> Result<()> {
    let dest = bundle_dir.join(rel);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(&dest, src_bytes)?;
    entries.push(BundleEntry {
        path: rel.to_string(),
        kind,
        digest: blake3::hash(src_bytes).to_hex().to_string(),
        size_bytes: src_bytes.len() as u64,
    });
    Ok(())
}

/// Copy every regular file with an allowed extension from `src` into
/// `bundle_dir/<sub>/`, recording entries.
fn add_dir(
    bundle_dir: &Path,
    src: &Path,
    sub: &str,
    exts: &[&str],
    kind: BundleEntryKind,
    entries: &mut Vec<BundleEntry>,
) -> Result<()> {
    if !src.is_dir() {
        return Ok(());
    }
    let mut names: Vec<String> = std::fs::read_dir(src)?
        .flatten()
        .filter(|e| e.path().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| exts.contains(&x))
                .unwrap_or(false)
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    for name in names {
        let bytes = std::fs::read(src.join(&name))?;
        add_file(bundle_dir, &format!("{sub}/{name}"), &bytes, kind, entries)?;
    }
    Ok(())
}

/// A deterministic SBOM from Cargo.lock (name + version per package). Best-effort
/// — an absent lockfile yields a note, never a failure.
fn sbom_from_lockfile() -> String {
    let Ok(text) = std::fs::read_to_string("Cargo.lock") else {
        return "# no Cargo.lock found at build time\n".to_string();
    };
    let mut out = String::from("# garmr bundle SBOM (name version) from Cargo.lock\n");
    let mut name = None;
    for line in text.lines() {
        if let Some(n) = line.strip_prefix("name = ") {
            name = Some(n.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                out.push_str(&format!("{n} {}\n", v.trim_matches('"')));
            }
        }
    }
    out
}

fn build(cli: &Cli, dir: &Path, binary: Option<&Path>, signing_key: Option<&Path>) -> Result<()> {
    let cfg = crate::load_config(cli)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut entries: Vec<BundleEntry> = Vec::new();

    // 1) the garmr binary (streamed, bounded memory).
    let bin_src = match binary {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().context("locating the running garmr binary")?,
    };
    let (bin_digest, bin_size) = stream_digest(&bin_src)?;
    std::fs::create_dir_all(dir.join("bin"))?;
    std::fs::copy(&bin_src, dir.join("bin/garmr"))?;
    entries.push(BundleEntry {
        path: "bin/garmr".into(),
        kind: BundleEntryKind::Binary,
        digest: bin_digest.clone(),
        size_bytes: bin_size,
    });

    // 2) detection content.
    add_dir(
        dir,
        &cfg.detect.rules_dir,
        "rules",
        &["yml", "yaml"],
        BundleEntryKind::SigmaRule,
        &mut entries,
    )?;
    add_dir(
        dir,
        &cfg.detect.correlations_dir,
        "correlations",
        &["toml"],
        BundleEntryKind::CorrelationRule,
        &mut entries,
    )?;
    add_dir(
        dir,
        &cfg.detect.hunts_dir,
        "hunts",
        &["toml"],
        BundleEntryKind::Hunt,
        &mut entries,
    )?;

    // 3) config TEMPLATE (never a live config with secrets).
    if Path::new("garmr.example.toml").is_file() {
        let bytes = std::fs::read("garmr.example.toml")?;
        add_file(
            dir,
            "garmr.example.toml",
            &bytes,
            BundleEntryKind::ConfigTemplate,
            &mut entries,
        )?;
    }

    // 4) SBOM + provenance.
    add_file(
        dir,
        "supply-chain/sbom.txt",
        sbom_from_lockfile().as_bytes(),
        BundleEntryKind::Sbom,
        &mut entries,
    )?;
    let now = chrono::Utc::now();
    let git_commit = std::env::var("GARMR_GIT_COMMIT").unwrap_or_default();
    let provenance = format!(
        "garmr air-gap bundle\nversion: {}\ngit_commit: {}\nbuilt_at: {}\nnode: {}\n",
        env!("CARGO_PKG_VERSION"),
        git_commit,
        now.to_rfc3339(),
        cfg.audit.node_id,
    );
    add_file(
        dir,
        "provenance.txt",
        provenance.as_bytes(),
        BundleEntryKind::Provenance,
        &mut entries,
    )?;

    // 5) the release spec (built from the content), addressed by release_digest.
    let ruleset_digest = {
        let mut ds: Vec<&str> = entries
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    BundleEntryKind::SigmaRule | BundleEntryKind::CorrelationRule
                )
            })
            .map(|e| e.digest.as_str())
            .collect();
        ds.sort();
        blake3::hash(ds.join(",").as_bytes()).to_hex().to_string()
    };
    let spec = ReleaseSpec {
        model_ref: cfg.agent.model.clone(),
        prompt_ref: garmr_agent::system_prompt_digest(),
        ruleset_digest,
        ..Default::default()
    };
    let rel_digest = release_digest(&spec);
    // RegistryRecord has no Default; build via serde (all fields #[serde(default)]).
    let record: RegistryRecord = serde_json::from_value(serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "kind": "release",
        "name": "garmr",
        "version": env!("CARGO_PKG_VERSION"),
        "content_digest": rel_digest,
        "rationale": "air-gap bundle release",
        "registered_by": "bundle",
        "spec": spec,
    }))?;
    let record_bytes = serde_json::to_vec_pretty(&record)?;
    add_file(
        dir,
        "release.json",
        &record_bytes,
        BundleEntryKind::RegistryRecord,
        &mut entries,
    )?;

    // 6) model notes (which models the release expects — external-process only).
    let mut model_notes = vec![ModelNote {
        logical_name: "agent".into(),
        provider: format!("{:?}", cfg.agent.backend),
        descriptor_digest: garmr_core::model_descriptor_digest(
            cfg.agent.backend,
            &cfg.agent.model,
            cfg.agent.openai_base_url.as_deref().unwrap_or(""),
        ),
        external: true,
        note: "external OpenAI-compat/Anthropic process; weights not bundled".into(),
    }];
    for e in &cfg.route.router.models {
        model_notes.push(ModelNote {
            logical_name: e.name.clone(),
            provider: format!("{:?}", e.backend),
            descriptor_digest: e.descriptor_digest(),
            external: !e.is_local(),
            note: e.role.clone(),
        });
    }

    // 7) assemble + sign.
    let mut manifest = BundleManifest {
        format_version: garmr_core::BUNDLE_FORMAT,
        created_at_us: now.timestamp_micros(),
        node_id: cfg.audit.node_id.clone(),
        garmr_version: env!("CARGO_PKG_VERSION").into(),
        git_commit,
        release_name: "garmr".into(),
        release_version: env!("CARGO_PKG_VERSION").into(),
        release_digest: rel_digest,
        entries,
        model_notes,
        notes: String::new(),
        bundle_id: String::new(),
    };
    manifest.bundle_id = manifest_digest(&manifest);

    let key = signing_key
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_key_path(&cfg));
    let signer = SoftwareSigner::load_or_create(&key)
        .with_context(|| format!("loading the signing key {}", key.display()))?;
    let body = garmr_core::canonical_manifest_body(&manifest);
    let sig = signer.sign(&body);
    let pk = signer.public_key();
    let signed = SignedBundle {
        manifest_digest: manifest.bundle_id.clone(),
        manifest,
        signature_format: "ed25519".into(),
        signing_key_id: signer.key_id().to_string(),
        public_key: hex::encode(pk),
        signature: sig.to_hex(),
    };
    std::fs::write(dir.join("bundle.json"), serde_json::to_vec_pretty(&signed)?)?;
    std::fs::write(dir.join("public_key.hex"), hex::encode(pk))?;

    println!(
        "built bundle {} ({} entries)",
        dir.display(),
        signed.manifest.entries.len()
    );
    println!("  bundle_id:   {}", signed.manifest_digest);
    println!("  signing key: {}", signed.signing_key_id);
    println!(
        "  verify with an OUT-OF-BAND trusted key: garmr bundle verify {} --key <hex>",
        dir.display()
    );
    Ok(())
}

pub(crate) fn default_key_path(cfg: &garmr_core::Config) -> PathBuf {
    cfg.audit
        .key_path
        .clone()
        .unwrap_or_else(|| cfg.audit.dir.join("signing.key"))
}

// ---- verify ----------------------------------------------------------------

/// Resolve the trust-root public key (FIX#1): `--key`, else the operator's LOCAL
/// `audit.dir/public_key.hex`. NEVER the bundle-embedded key. `None` when no
/// local trusted key exists — the caller then reports UNVERIFIED, fail-closed.
pub(crate) fn resolve_trust_key(
    cfg: &garmr_core::Config,
    key_override: Option<&str>,
) -> Result<Option<[u8; 32]>> {
    if let Some(hex_str) = key_override {
        let bytes = hex::decode(hex_str.trim()).context("--key must be hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("--key must be exactly 32 bytes (64 hex chars)"))?;
        return Ok(Some(arr));
    }
    let local = cfg.audit.dir.join("public_key.hex");
    if local.is_file() {
        let s = std::fs::read_to_string(&local)?;
        let bytes = hex::decode(s.trim()).context("local public_key.hex must be hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("local public_key.hex must be 32 bytes"))?;
        return Ok(Some(arr));
    }
    Ok(None)
}

/// Walk the bundle tree (excluding the envelope files), rejecting symlinks and
/// any path escaping the tree, returning `rel_path -> blake3-hex`.
fn walk_bundle(dir: &Path) -> Result<(BTreeMap<String, String>, Vec<garmr_core::BundleFinding>)> {
    let mut computed = BTreeMap::new();
    let mut findings = Vec::new();
    let root = dir
        .canonicalize()
        .with_context(|| format!("bundle dir {}", dir.display()))?;
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)?.flatten() {
            let p = e.path();
            let meta = std::fs::symlink_metadata(&p)?;
            if meta.file_type().is_symlink() {
                findings.push(garmr_core::BundleFinding {
                    category: "unsafe_path".into(),
                    coord: p.display().to_string(),
                    detail: "symlink in the bundle tree".into(),
                });
                continue;
            }
            if meta.is_dir() {
                stack.push(p);
                continue;
            }
            // Only REGULAR files are hashed. A hostile FIFO/socket/device would
            // otherwise block stream_digest's blocking open forever (review fix).
            if !meta.is_file() {
                findings.push(garmr_core::BundleFinding {
                    category: "unsafe_path".into(),
                    coord: p.display().to_string(),
                    detail: "non-regular file (fifo/socket/device) in the bundle tree".into(),
                });
                continue;
            }
            let rel = p
                .strip_prefix(&root)
                .ok()
                .and_then(|r| r.to_str())
                .map(|s| s.replace('\\', "/"))
                .unwrap_or_default();
            if ENVELOPE_FILES.contains(&rel.as_str()) {
                continue;
            }
            if !is_safe_relative_path(&rel) {
                findings.push(garmr_core::BundleFinding {
                    category: "unsafe_path".into(),
                    coord: rel,
                    detail: "file path escapes the bundle tree".into(),
                });
                continue;
            }
            let (digest, _) = stream_digest(&p)?;
            computed.insert(rel, digest);
        }
    }
    Ok((computed, findings))
}

/// Verify a bundle offline, fail-closed. Resolves the trust key (FIX#1) then
/// delegates to [`verify_bundle`].
fn verify(
    cli: &Cli,
    dir: &Path,
    key_override: Option<&str>,
) -> Result<Vec<garmr_core::BundleFinding>> {
    let cfg = crate::load_config(cli)?;
    let trust_key = resolve_trust_key(&cfg, key_override)?;
    verify_bundle(dir, trust_key)
}

/// The trust-key-parameterized verify core (testable without config). `None`
/// trust key ⇒ UNVERIFIED, fail-closed — the embedded key is never a trust root.
pub(crate) fn verify_bundle(
    dir: &Path,
    trust_key: Option<[u8; 32]>,
) -> Result<Vec<garmr_core::BundleFinding>> {
    let mut findings: Vec<garmr_core::BundleFinding> = Vec::new();

    let raw = std::fs::read(dir.join("bundle.json"))
        .with_context(|| format!("reading {}/bundle.json", dir.display()))?;
    let sb: SignedBundle = serde_json::from_slice(&raw).context("decoding bundle.json")?;

    let Some(trust_key) = trust_key else {
        println!("UNVERIFIED: no trusted key (pass --key <hex> or publish audit public_key.hex)");
        return Ok(vec![garmr_core::BundleFinding {
            category: "no_trusted_key".into(),
            coord: dir.display().to_string(),
            detail: "no out-of-band trusted key; the embedded key is never a trust root".into(),
        }]);
    };

    // Signature over the canonical body, against the TRUSTED key.
    let body = garmr_core::canonical_manifest_body(&sb.manifest);
    let sig_bytes = hex::decode(sb.signature.trim()).unwrap_or_default();
    if !garmr_audit::verify_signature(&trust_key, &body, &garmr_audit::Sig(sig_bytes)) {
        findings.push(garmr_core::BundleFinding {
            category: "signature".into(),
            coord: sb.signing_key_id.clone(),
            detail: "signature does not verify against the trusted key".into(),
        });
    }
    if !verify_manifest_digest(&sb) {
        findings.push(garmr_core::BundleFinding {
            category: "manifest_digest".into(),
            coord: sb.manifest_digest.clone(),
            detail: "stamped manifest digest != recomputed".into(),
        });
    }

    // Every file: recompute + STRICT extra-file detection (FIX#2).
    let (computed, walk_findings) = walk_bundle(dir)?;
    findings.extend(walk_findings);
    findings.extend(diff_entries(&sb.manifest, &computed, true));

    // Release binding (FIX#3): the carried release.json re-derives to both digests.
    if let Some(e) = sb
        .manifest
        .entries
        .iter()
        .find(|e| matches!(e.kind, BundleEntryKind::RegistryRecord) && e.path == "release.json")
    {
        let _ = e;
        if let Ok(bytes) = std::fs::read(dir.join("release.json")) {
            if let Ok(rec) = serde_json::from_slice::<RegistryRecord>(&bytes) {
                if let Ok(spec) = serde_json::from_value::<ReleaseSpec>(rec.spec.clone()) {
                    findings.extend(verify_release_binding(
                        &sb.manifest,
                        &spec,
                        &rec.content_digest,
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        println!(
            "verified {} entries against key {}",
            sb.manifest.entries.len(),
            sb.signing_key_id
        );
    } else {
        for f in &findings {
            println!("  [{}] {}: {}", f.category, f.coord, f.detail);
        }
    }
    Ok(findings)
}

fn show(dir: &Path) -> Result<()> {
    let raw = std::fs::read(dir.join("bundle.json"))
        .with_context(|| format!("reading {}/bundle.json", dir.display()))?;
    let sb: SignedBundle = serde_json::from_slice(&raw).context("decoding bundle.json")?;
    let m = &sb.manifest;
    println!("bundle {} v{}", m.release_name, m.release_version);
    println!("  bundle_id:  {}", m.bundle_id);
    println!("  release:    {}", m.release_digest);
    println!(
        "  signed by:  {} (key {})",
        sb.signing_key_id,
        short_str(&sb.public_key, 16)
    );
    println!("  entries:    {}", m.entries.len());
    for e in &m.entries {
        println!(
            "    {:<28} [{}] {}",
            e.path,
            e.kind.tag(),
            short_str(&e.digest, 12)
        );
    }
    Ok(())
}

/// Truncate to `n` CHARS (not bytes), so an attacker-crafted non-ASCII field in
/// an unverified bundle.json can't panic `show` on a non-char-boundary slice.
fn short_str(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_audit::{Signer, SoftwareSigner};

    fn make_bundle(dir: &Path) -> [u8; 32] {
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        let content = b"detection: a\n";
        std::fs::write(dir.join("rules/a.yml"), content).unwrap();
        let mut manifest = BundleManifest {
            format_version: garmr_core::BUNDLE_FORMAT,
            release_name: "garmr".into(),
            entries: vec![BundleEntry {
                path: "rules/a.yml".into(),
                kind: BundleEntryKind::SigmaRule,
                digest: blake3::hash(content).to_hex().to_string(),
                size_bytes: content.len() as u64,
            }],
            ..Default::default()
        };
        manifest.bundle_id = manifest_digest(&manifest);
        let signer = SoftwareSigner::from_seed([7u8; 32]);
        let sig = signer.sign(&garmr_core::canonical_manifest_body(&manifest));
        let pk = signer.public_key();
        let signed = SignedBundle {
            manifest_digest: manifest.bundle_id.clone(),
            manifest,
            signature_format: "ed25519".into(),
            signing_key_id: signer.key_id().to_string(),
            public_key: hex::encode(pk),
            signature: sig.to_hex(),
        };
        std::fs::write(
            dir.join("bundle.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("public_key.hex"), hex::encode(pk)).unwrap();
        pk
    }

    #[test]
    fn valid_bundle_verifies_with_the_trusted_key() {
        let tmp = tempfile::tempdir().unwrap();
        let pk = make_bundle(tmp.path());
        assert!(verify_bundle(tmp.path(), Some(pk)).unwrap().is_empty());
    }

    #[test]
    fn no_key_is_unverified_never_ok() {
        let tmp = tempfile::tempdir().unwrap();
        make_bundle(tmp.path());
        assert!(verify_bundle(tmp.path(), None)
            .unwrap()
            .iter()
            .any(|x| x.category == "no_trusted_key"));
    }

    #[test]
    fn a_foreign_key_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        make_bundle(tmp.path());
        let foreign = SoftwareSigner::from_seed([9u8; 32]).public_key();
        assert!(verify_bundle(tmp.path(), Some(foreign))
            .unwrap()
            .iter()
            .any(|x| x.category == "signature"));
    }

    #[test]
    fn a_tampered_file_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let pk = make_bundle(tmp.path());
        std::fs::write(tmp.path().join("rules/a.yml"), b"detection: EVIL\n").unwrap();
        assert!(verify_bundle(tmp.path(), Some(pk))
            .unwrap()
            .iter()
            .any(|x| x.category == "digest_mismatch"));
    }

    #[test]
    fn an_unmanifested_file_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let pk = make_bundle(tmp.path());
        std::fs::write(tmp.path().join("rules/evil.yml"), b"x").unwrap();
        assert!(verify_bundle(tmp.path(), Some(pk))
            .unwrap()
            .iter()
            .any(|x| x.category == "unexpected_file"));
    }
}
