//! Detached, streaming CMS provenance signatures (feature `sign`).
//!
//! This module adds **provenance / authenticity** on top of znippy's existing
//! per-chunk BLAKE3 integrity. It never re-hashes file content: the per-artifact
//! and per-archive digests are a *merkle-fold of the chunk BLAKE3 hashes that the
//! compress path already produced* (`ChunkMeta.checksum`, ordered by `chunk_seq`,
//! Law 3). The signature is a **detached CMS `SignedData`** (RFC 5652) over that
//! digest — content bytes are never buffered or streamed through the signer.
//!
//! Everything here is pure Rust (RustCrypto: `cms`, `der`, `x509-cert`, `spki`,
//! `signature`, `ed25519-dalek`, `p256`/`ecdsa`, `sha2`). The whole module is
//! behind the off-by-default `sign` feature, so default builds, behaviour, and
//! the on-disk archive format are byte-for-byte unchanged.
//!
//! ## What gets signed
//! * Per-artifact: `file_digest(file)` — fold of one `FileMeta`'s chunk hashes.
//! * Per-archive: `archive_root(file_digests, footer)` — fold of every artifact
//!   digest plus the footer identity.
//!
//! The CMS message presented to the signer is the 32-byte digest; the
//! `messageDigest` signed attribute is `SHA-256(digest)` and `eContent` is
//! **absent** (detached, RFC 5652 §5.2). Verification recomputes the digest from
//! the index (the sunk-cost chunk hashes) and checks the CMS + cert chain.

use anyhow::{Result, anyhow, bail, ensure};

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

use crate::meta::{ChunkMeta, FileMeta};

// ─────────────────────────── Object identifiers ────────────────────────────

/// `id-sha256` (NIST). Digest algorithm for the CMS message-digest attribute.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `ecdsa-with-SHA256`. Signature algorithm for the P-256 signer.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `id-Ed25519`. Signature algorithm for the Ed25519 signer.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `id-data` — the encapsulated content type (RFC 5652).
const OID_ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `id-signedData`.
const OID_ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// `id-contentType` signed attribute.
const OID_ATTR_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// `id-messageDigest` signed attribute.
const OID_ATTR_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// `commonName` (CN) RDN.
const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Domain-separation tags so a per-artifact fold can never collide with a
/// per-archive fold (or with a raw chunk hash).
const ARTIFACT_TAG: &[u8] = b"znippy.artifact.v1\0";
const ARCHIVE_TAG: &[u8] = b"znippy.archive.v1\0";

// ─────────────────────────── Algorithm identity ────────────────────────────

/// Signature algorithm carried in the CMS `SignerInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    Ed25519,
    EcdsaP256,
}

impl SigAlg {
    /// Parse a CLI/config algorithm name (`p256`/`ecdsa` or `ed25519`).
    pub fn from_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "p256" | "ecdsa" | "ecdsa-p256" => Ok(SigAlg::EcdsaP256),
            "ed25519" | "ed" => Ok(SigAlg::Ed25519),
            other => bail!("unknown signature algorithm '{other}' (expected p256|ed25519)"),
        }
    }

    fn signature_algorithm_id(self) -> AlgorithmIdentifierOwned {
        match self {
            // RFC 8419/8410: Ed25519 parameters are absent.
            SigAlg::Ed25519 => AlgorithmIdentifierOwned {
                oid: OID_ED25519,
                parameters: None,
            },
            // RFC 5758: ecdsa-with-SHA256 parameters are absent.
            SigAlg::EcdsaP256 => AlgorithmIdentifierOwned {
                oid: OID_ECDSA_SHA256,
                parameters: None,
            },
        }
    }
}

fn sha256_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: None,
    }
}

// ───────────────────────────── Digest folds ────────────────────────────────

/// Per-artifact digest: a merkle-fold of one file's chunk BLAKE3 hashes, ordered
/// by `chunk_seq` (Law 3). Reuses the existing per-chunk hashes — content bytes
/// are never re-read. Binds the relative path so two files with identical bytes
/// still get distinct provenance digests.
pub fn file_digest(file: &FileMeta) -> [u8; 32] {
    let mut chunks: Vec<&ChunkMeta> = file.chunks.iter().collect();
    chunks.sort_by_key(|c| c.chunk_seq);
    file_digest_from_parts(
        &file.relative_path,
        chunks.iter().map(|c| (c.chunk_seq, &c.checksum)),
        chunks.len(),
    )
}

/// Same fold as [`file_digest`], but driven directly from `(chunk_seq, checksum)`
/// pairs (e.g. the on-disk index / lookup sub-index) so the verify path needs no
/// `FileMeta`. Caller passes the chunk count; pairs MUST already be sorted by
/// `chunk_seq`.
pub fn file_digest_from_parts<'a, I>(
    relative_path: &str,
    ordered_chunks: I,
    count: usize,
) -> [u8; 32]
where
    I: Iterator<Item = (u32, &'a [u8; 32])>,
{
    let mut h = blake3::Hasher::new();
    h.update(ARTIFACT_TAG);
    h.update(&(relative_path.len() as u64).to_le_bytes());
    h.update(relative_path.as_bytes());
    h.update(&(count as u64).to_le_bytes());
    for (seq, ck) in ordered_chunks {
        h.update(&seq.to_le_bytes());
        h.update(ck);
    }
    *h.finalize().as_bytes()
}

/// Per-archive root: a merkle-fold of every artifact digest (sorted by path for
/// determinism) plus the footer identity, so the archive signature commits to the
/// exact set of artifacts and to the index layout.
pub fn archive_root(
    file_digests: &[(String, [u8; 32])],
    footer: &crate::index::IndexFooter,
) -> [u8; 32] {
    let mut sorted: Vec<&(String, [u8; 32])> = file_digests.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut h = blake3::Hasher::new();
    h.update(ARCHIVE_TAG);
    // Bind the footer KIND (stable at write time), not the volatile manifest/index
    // offset — the signature sections are written *before* the manifest, so the
    // offset is not yet known when the archive root is signed.
    let footer_kind: u8 = match footer {
        crate::index::IndexFooter::Single { .. } => 0,
        crate::index::IndexFooter::Multi { .. } => 1,
    };
    h.update(&[footer_kind]);
    h.update(&(sorted.len() as u64).to_le_bytes());
    for (path, dig) in sorted {
        h.update(&(path.len() as u64).to_le_bytes());
        h.update(path.as_bytes());
        h.update(dig);
    }
    *h.finalize().as_bytes()
}

// ──────────────────────────── Signer abstraction ───────────────────────────

/// Produces a detached CMS `SignedData` (DER) over a 32-byte digest.
pub trait ArchiveSigner {
    fn algorithm(&self) -> SigAlg;
    /// Returns a DETACHED CMS `SignedData` (DER) over `digest`.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>>;
}

/// Ed25519 signer (`ed25519-dalek`).
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
    /// DER of the signer certificate (carries the public key + identity, chains
    /// to a CA the verifier trusts). Embedded in the CMS `certificates` field.
    cert_der: Vec<u8>,
}

impl Ed25519Signer {
    /// `cert_der` is the signer's X.509 certificate (DER) whose subject public
    /// key matches `key`.
    pub fn new(key: ed25519_dalek::SigningKey, cert_der: Vec<u8>) -> Self {
        Self { key, cert_der }
    }
}

impl ArchiveSigner for Ed25519Signer {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Ed25519
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        let (attrs, attrs_der) = build_signed_attrs(digest)?;
        let sig = self.key.sign(&attrs_der); // PureEdDSA over the signed attributes
        assemble_cms(
            attrs,
            sig.to_bytes().to_vec(),
            SigAlg::Ed25519,
            &self.cert_der,
        )
    }
}

/// ECDSA P-256 signer (`p256` / `ecdsa`).
pub struct EcdsaP256Signer {
    key: p256::ecdsa::SigningKey,
    cert_der: Vec<u8>,
}

impl EcdsaP256Signer {
    pub fn new(key: p256::ecdsa::SigningKey, cert_der: Vec<u8>) -> Self {
        Self { key, cert_der }
    }
}

impl ArchiveSigner for EcdsaP256Signer {
    fn algorithm(&self) -> SigAlg {
        SigAlg::EcdsaP256
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use signature::Signer;
        let (attrs, attrs_der) = build_signed_attrs(digest)?;
        // ecdsa-with-SHA256: SigningKey hashes the message with SHA-256 then signs;
        // DerSignature is the ASN.1 ECDSA-Sig-Value that X.509/CMS expects.
        let sig: p256::ecdsa::DerSignature = self.key.sign(&attrs_der);
        assemble_cms(
            attrs,
            sig.as_bytes().to_vec(),
            SigAlg::EcdsaP256,
            &self.cert_der,
        )
    }
}

/// Build a boxed [`ArchiveSigner`] from a PKCS#8 (DER) private key and the DER of
/// the signer's X.509 certificate. The certificate's subject public key must match
/// `pkcs8_key`. This is the loader seam the CLI / a key-store calls — it keeps all
/// RustCrypto key types inside this crate so callers only handle bytes + a `SigAlg`.
pub fn signer_from_pkcs8(
    alg: SigAlg,
    pkcs8_key: &[u8],
    cert_der: &[u8],
) -> Result<Box<dyn ArchiveSigner + Send>> {
    match alg {
        SigAlg::Ed25519 => {
            use ed25519_dalek::pkcs8::DecodePrivateKey;
            let key = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_key)
                .map_err(|e| anyhow!("load Ed25519 PKCS#8 key: {e}"))?;
            Ok(Box::new(Ed25519Signer::new(key, cert_der.to_vec())))
        }
        SigAlg::EcdsaP256 => {
            use p256::pkcs8::DecodePrivateKey;
            let secret = p256::SecretKey::from_pkcs8_der(pkcs8_key)
                .map_err(|e| anyhow!("load P-256 PKCS#8 key: {e}"))?;
            Ok(Box::new(EcdsaP256Signer::new(
                p256::ecdsa::SigningKey::from(secret),
                cert_der.to_vec(),
            )))
        }
    }
}

// ───────────────────────────── CMS construction ────────────────────────────

/// Build the CMS signed attributes (content-type = id-data, message-digest =
/// SHA-256(digest)) and return them together with their DER `SET OF` encoding —
/// the exact bytes the signer signs (RFC 5652 §5.4).
fn build_signed_attrs(digest: &[u8; 32]) -> Result<(SetOfVec<Attribute>, Vec<u8>)> {
    let message_digest = Sha256::digest(digest); // SHA-256 of the 32-byte content

    let content_type_attr = Attribute {
        oid: OID_ATTR_CONTENT_TYPE,
        values: SetOfVec::try_from(vec![Any::encode_from(&OID_ID_DATA)?])
            .map_err(|e| anyhow!("content-type attr: {e}"))?,
    };
    let md_octets = OctetString::new(message_digest.as_slice())?;
    let message_digest_attr = Attribute {
        oid: OID_ATTR_MESSAGE_DIGEST,
        values: SetOfVec::try_from(vec![Any::encode_from(&md_octets)?])
            .map_err(|e| anyhow!("message-digest attr: {e}"))?,
    };

    let attrs = SetOfVec::try_from(vec![content_type_attr, message_digest_attr])
        .map_err(|e| anyhow!("signed attrs: {e}"))?;
    // SignedAttributes are signed in their DER SET OF (tag 0x31) form.
    let attrs_der = attrs.to_der()?;
    Ok((attrs, attrs_der))
}

/// Assemble a detached CMS `SignedData` `ContentInfo` (DER) from pre-signed
/// attributes + the raw signature + the signer cert.
fn assemble_cms(
    signed_attrs: SetOfVec<Attribute>,
    signature: Vec<u8>,
    alg: SigAlg,
    cert_der: &[u8],
) -> Result<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).map_err(|e| anyhow!("signer cert: {e}"))?;
    let iasn = IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    };

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(iasn),
        digest_alg: sha256_alg_id(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: alg.signature_algorithm_id(),
        signature: OctetString::new(signature)?,
        unsigned_attrs: None,
    };

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![sha256_alg_id()])
            .map_err(|e| anyhow!("digest algs: {e}"))?,
        // Detached: eContentType present, eContent absent.
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: OID_ID_DATA,
            econtent: None,
        },
        certificates: Some(
            CertificateSet::try_from(vec![CertificateChoices::Certificate(cert)])
                .map_err(|e| anyhow!("cert set: {e}"))?,
        ),
        crls: None,
        signer_infos: SignerInfos::try_from(vec![signer_info])
            .map_err(|e| anyhow!("signer infos: {e}"))?,
    };

    let content_info = ContentInfo {
        content_type: OID_ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data)?,
    };
    Ok(content_info.to_der()?)
}

// ───────────────────────────── Verification ────────────────────────────────

/// A trusted set of root certificates (DER), used to chain a signer cert.
#[derive(Default, Clone)]
pub struct CertStore {
    roots: Vec<Certificate>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Build from a list of DER-encoded root certificates.
    pub fn from_der_certs(ders: &[Vec<u8>]) -> Result<Self> {
        let mut s = Self::default();
        for d in ders {
            s.add_root_der(d)?;
        }
        Ok(s)
    }
    pub fn add_root_der(&mut self, der: &[u8]) -> Result<()> {
        self.roots
            .push(Certificate::from_der(der).map_err(|e| anyhow!("root cert: {e}"))?);
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Identity recovered from a verified signer certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerId {
    /// commonName (CN) of the signer cert subject, if present.
    pub common_name: String,
    /// Full RFC 4514 subject string.
    pub subject: String,
}

/// Verifies a detached CMS over `digest`.
pub trait ArchiveVerifier {
    /// Verify a detached CMS over `digest`, chain the signer cert to `roots`, and
    /// return the signer identity. Algorithm-agnostic: the signature algorithm is
    /// read from the CMS `SignerInfo`, so one call handles both Ed25519 and P-256.
    fn verify_digest(
        &self,
        digest: &[u8; 32],
        cms_der: &[u8],
        roots: &CertStore,
    ) -> Result<SignerId>;
}

/// The single, algorithm-agnostic verifier (reads the algorithm OID from the CMS).
pub struct CmsVerifier;

impl ArchiveVerifier for CmsVerifier {
    fn verify_digest(
        &self,
        digest: &[u8; 32],
        cms_der: &[u8],
        roots: &CertStore,
    ) -> Result<SignerId> {
        verify_digest(digest, cms_der, roots)
    }
}

/// Free-function form of [`CmsVerifier::verify_digest`] — the core verify routine.
pub fn verify_digest(digest: &[u8; 32], cms_der: &[u8], roots: &CertStore) -> Result<SignerId> {
    let ci = ContentInfo::from_der(cms_der).map_err(|e| anyhow!("parse ContentInfo: {e}"))?;
    ensure!(
        ci.content_type == OID_ID_SIGNED_DATA,
        "not a CMS SignedData"
    );
    let sd = SignedData::from_der(&ci.content.to_der()?)
        .map_err(|e| anyhow!("parse SignedData: {e}"))?;

    let signer_info = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| anyhow!("no SignerInfo"))?;

    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("detached CMS requires signed attributes"))?;

    // 1. The signed message-digest attribute must equal SHA-256(recomputed digest).
    let expected_md = Sha256::digest(digest);
    let got_md = attr_octet_string(signed_attrs, &OID_ATTR_MESSAGE_DIGEST)?;
    ensure!(
        got_md.as_slice() == expected_md.as_slice(),
        "message-digest mismatch (content does not match signature)"
    );
    // 2. The content-type attribute must match the encapsulated content type.
    let got_ct = attr_oid(signed_attrs, &OID_ATTR_CONTENT_TYPE)?;
    ensure!(got_ct == OID_ID_DATA, "unexpected content-type attribute");

    // 3. Recover the signer certificate from the CMS.
    let signer_cert = signer_certificate(&sd)?;
    let spki_der = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;

    // 4. Verify the signature over the DER SET OF signed attributes (RFC 5652 §5.4).
    let signed_bytes = signed_attrs.to_der()?;
    let sig_bytes = signer_info.signature.as_bytes();
    let alg = &signer_info.signature_algorithm.oid;
    verify_signature(alg, &spki_der, &signed_bytes, sig_bytes)?;

    // 5. Chain the signer cert to a trusted root.
    chain_to_roots(signer_cert, roots)?;

    Ok(signer_id_of(signer_cert)?)
}

fn signer_certificate(sd: &SignedData) -> Result<&Certificate> {
    let set = sd
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow!("CMS carries no signer certificate"))?;
    for choice in set.0.iter() {
        if let CertificateChoices::Certificate(c) = choice {
            return Ok(c);
        }
    }
    bail!("no X.509 certificate in CMS")
}

/// Verify a signature given the signer's SPKI DER, the signed bytes, and the
/// signature, dispatching on the signature-algorithm OID.
fn verify_signature(
    alg: &ObjectIdentifier,
    spki_der: &[u8],
    signed_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    if *alg == OID_ED25519 {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| anyhow!("ed25519 spki: {e}"))?;
        let sig = Signature::from_slice(sig_bytes).map_err(|e| anyhow!("ed25519 sig: {e}"))?;
        vk.verify(signed_bytes, &sig)
            .map_err(|_| anyhow!("Ed25519 signature verification failed"))
    } else if *alg == OID_ECDSA_SHA256 {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{DerSignature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;
        let vk =
            VerifyingKey::from_public_key_der(spki_der).map_err(|e| anyhow!("p256 spki: {e}"))?;
        let sig = DerSignature::try_from(sig_bytes).map_err(|e| anyhow!("p256 sig: {e}"))?;
        vk.verify(signed_bytes, &sig)
            .map_err(|_| anyhow!("ECDSA P-256 signature verification failed"))
    } else {
        bail!("unsupported signature algorithm OID: {alg}")
    }
}

/// Verify `leaf` was signed by one of the trusted roots.
fn chain_to_roots(leaf: &Certificate, roots: &CertStore) -> Result<()> {
    ensure!(!roots.is_empty(), "no trusted roots configured");
    for root in &roots.roots {
        if leaf.tbs_certificate.issuer == root.tbs_certificate.subject
            && cert_signed_by(leaf, root).is_ok()
        {
            return Ok(());
        }
    }
    bail!("signer certificate does not chain to any trusted root")
}

/// Verify `leaf`'s signature using `issuer`'s public key.
fn cert_signed_by(leaf: &Certificate, issuer: &Certificate) -> Result<()> {
    let tbs = leaf.tbs_certificate.to_der()?;
    let sig = leaf.signature.raw_bytes();
    let issuer_spki = issuer.tbs_certificate.subject_public_key_info.to_der()?;
    verify_signature(&leaf.signature_algorithm.oid, &issuer_spki, &tbs, sig)
}

fn signer_id_of(cert: &Certificate) -> Result<SignerId> {
    let subject = cert.tbs_certificate.subject.to_string();
    let common_name = extract_cn(cert).unwrap_or_default();
    Ok(SignerId {
        common_name,
        subject,
    })
}

/// Pull the commonName out of a cert subject, if present.
fn extract_cn(cert: &Certificate) -> Option<String> {
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == OID_CN {
                if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef<'_>>() {
                    return Some(s.as_str().to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef<'_>>() {
                    return Some(s.as_str().to_string());
                }
            }
        }
    }
    None
}

// ── signed-attribute extraction helpers ──

fn find_attr<'a>(attrs: &'a SetOfVec<Attribute>, oid: &ObjectIdentifier) -> Result<&'a Attribute> {
    attrs
        .iter()
        .find(|a| &a.oid == oid)
        .ok_or_else(|| anyhow!("missing signed attribute {oid}"))
}

fn attr_octet_string(attrs: &SetOfVec<Attribute>, oid: &ObjectIdentifier) -> Result<Vec<u8>> {
    let attr = find_attr(attrs, oid)?;
    let val = attr
        .values
        .iter()
        .next()
        .ok_or_else(|| anyhow!("empty attribute {oid}"))?;
    let os =
        OctetString::from_der(&val.to_der()?).map_err(|e| anyhow!("attr octet string: {e}"))?;
    Ok(os.as_bytes().to_vec())
}

fn attr_oid(attrs: &SetOfVec<Attribute>, oid: &ObjectIdentifier) -> Result<ObjectIdentifier> {
    let attr = find_attr(attrs, oid)?;
    let val = attr
        .values
        .iter()
        .next()
        .ok_or_else(|| anyhow!("empty attribute {oid}"))?;
    ObjectIdentifier::from_der(&val.to_der()?).map_err(|e| anyhow!("attr oid: {e}"))
}

// ───────────────────── Archive-level read + verify (Phase B/C) ──────────────

use std::collections::BTreeMap;
use std::path::Path;

/// The detached signatures recovered from a signed archive.
pub struct ArchiveSignatures {
    /// Per-archive detached CMS over the archive root digest.
    pub archive_cms: Vec<u8>,
    /// Per-artifact detached CMS, keyed by `relative_path`.
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

/// Read the detached signature sections from an archive, if it was sealed with a
/// signer. Returns `None` for an unsigned archive (no signature sections).
pub fn read_archive_signatures(path: &Path) -> Result<Option<ArchiveSignatures>> {
    let archive_cms =
        match crate::index::read_reserved_section_bytes(path, crate::index::SIGN_ARCHIVE_MODULE)? {
            Some(b) => b,
            None => return Ok(None),
        };
    let artifacts =
        match crate::index::read_reserved_section_bytes(path, crate::index::SIGN_ARTIFACTS_MODULE)?
        {
            Some(b) => deserialize_artifact_signatures(&b)?,
            None => BTreeMap::new(),
        };
    Ok(Some(ArchiveSignatures {
        archive_cms,
        artifacts,
    }))
}

/// Decode the per-artifact signatures Arrow IPC stream into `path → cms`.
fn deserialize_artifact_signatures(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    use arrow::array::{BinaryArray, StringArray};
    use arrow::ipc::reader::StreamReader;

    let reader = StreamReader::try_new(std::io::Cursor::new(bytes), None)?;
    let mut out = BTreeMap::new();
    for batch in reader {
        let batch = batch?;
        let paths = batch
            .column_by_name("relative_path")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| anyhow!("artifact-sig: missing relative_path"))?;
        let cms = batch
            .column_by_name("cms")
            .and_then(|c| c.as_any().downcast_ref::<BinaryArray>())
            .ok_or_else(|| anyhow!("artifact-sig: missing cms"))?;
        for i in 0..batch.num_rows() {
            out.insert(paths.value(i).to_string(), cms.value(i).to_vec());
        }
    }
    Ok(out)
}

/// Recompute every artifact's digest from the archive index — i.e. from the
/// sunk-cost per-chunk BLAKE3 hashes — without reading any file bytes.
fn recompute_file_digests(path: &Path) -> Result<BTreeMap<String, [u8; 32]>> {
    use arrow::array::{FixedSizeBinaryArray, StringArray, UInt32Array};

    let (_schema, batches) = crate::index::read_znippy_index(path)?;
    let mut chunks: BTreeMap<String, Vec<(u32, [u8; 32])>> = BTreeMap::new();
    for batch in &batches {
        let paths = batch
            .column_by_name("relative_path")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| anyhow!("index: missing relative_path"))?;
        let seqs = batch
            .column_by_name("chunk_seq")
            .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
            .ok_or_else(|| anyhow!("index: missing chunk_seq"))?;
        let cks = batch
            .column_by_name("checksum")
            .and_then(|c| c.as_any().downcast_ref::<FixedSizeBinaryArray>())
            .ok_or_else(|| anyhow!("index: missing checksum"))?;
        for i in 0..batch.num_rows() {
            let mut ck = [0u8; 32];
            ck.copy_from_slice(cks.value(i));
            chunks
                .entry(paths.value(i).to_string())
                .or_default()
                .push((seqs.value(i), ck));
        }
    }
    let mut out = BTreeMap::new();
    for (p, mut cs) in chunks {
        cs.sort_by_key(|(seq, _)| *seq);
        let n = cs.len();
        let dig = file_digest_from_parts(&p, cs.iter().map(|(s, c)| (*s, c)), n);
        out.insert(p, dig);
    }
    Ok(out)
}

/// Result of verifying an archive's provenance.
#[derive(Debug, Clone)]
pub struct ArchiveVerifyReport {
    /// Identity of the archive-level signer.
    pub signer: SignerId,
    /// Number of artifacts whose per-artifact signature verified.
    pub artifacts_verified: usize,
}

/// Verify a served artifact: recompute its digest from `file` (the sunk-cost
/// chunk hashes) and verify the detached CMS against the trusted roots.
///
/// **This is the per-artifact entry point holger calls** when serving a file:
/// `verify_artifact(&file_meta, &stored_cms, &roots)`.
pub fn verify_artifact(file: &FileMeta, cms_der: &[u8], roots: &CertStore) -> Result<SignerId> {
    let digest = file_digest(file);
    verify_digest(&digest, cms_der, roots)
}

/// Verify a whole signed archive: every per-artifact signature against its
/// recomputed digest, and the per-archive signature against the recomputed root.
/// Recomputes all digests from the index — never reads file bytes.
pub fn verify_archive(path: &Path, roots: &CertStore) -> Result<ArchiveVerifyReport> {
    let sigs = read_archive_signatures(path)?
        .ok_or_else(|| anyhow!("archive carries no provenance signatures"))?;
    let digests = recompute_file_digests(path)?;

    // Every signed artifact must verify against its recomputed digest.
    let mut artifacts_verified = 0usize;
    for (rel, cms) in &sigs.artifacts {
        let digest = digests
            .get(rel)
            .ok_or_else(|| anyhow!("signed artifact {rel} not present in index"))?;
        verify_digest(digest, cms, roots).map_err(|e| anyhow!("artifact {rel} signature: {e}"))?;
        artifacts_verified += 1;
    }

    // The per-archive signature commits to the exact set of artifacts.
    let footer = crate::index::IndexFooter::Multi { manifest_offset: 0 };
    let file_digests: Vec<(String, [u8; 32])> = digests.into_iter().collect();
    let root = archive_root(&file_digests, &footer);
    let signer = verify_digest(&root, &sigs.archive_cms, roots)
        .map_err(|e| anyhow!("archive signature: {e}"))?;

    Ok(ArchiveVerifyReport {
        signer,
        artifacts_verified,
    })
}

/// Look up a single served artifact's stored CMS by path (for holger, which
/// verifies one artifact at a time).
pub fn artifact_signature_for(path: &Path, relative_path: &str) -> Result<Option<Vec<u8>>> {
    Ok(read_archive_signatures(path)?.and_then(|s| s.artifacts.get(relative_path).cloned()))
}

/// Test / dev / bootstrap helpers: mint an in-memory PKI (a P-256 CA mirroring
/// holger/mannequin) and build ready-to-use signers. Pure Rust (x509-cert
/// builder). Used by the unit tests and the seal-throughput bench; also handy for
/// dev/bootstrap where a real CA is not yet wired up.
pub mod dev {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    /// Mint a self-signed P-256 CA. Returns `(signing key, cert DER)`.
    pub fn mint_ca(cn: &str) -> Result<(p256::ecdsa::SigningKey, Vec<u8>)> {
        let ca_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let ca_vk = p256::ecdsa::VerifyingKey::from(&ca_key);
        let subject = Name::from_str(&format!("CN={cn}")).map_err(|e| anyhow!("name: {e}"))?;
        let spki = SubjectPublicKeyInfoOwned::from_key(ca_vk).map_err(|e| anyhow!("spki: {e}"))?;
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(3600)).map_err(|e| anyhow!("validity: {e}"))?,
            subject,
            spki,
            &ca_key,
        )
        .map_err(|e| anyhow!("ca builder: {e}"))?;
        let cert = builder
            .build::<p256::ecdsa::DerSignature>()
            .map_err(|e| anyhow!("ca sign: {e}"))?;
        Ok((ca_key, cert.to_der()?))
    }

    /// Issue a leaf cert for an arbitrary subject public key, signed by the CA.
    pub fn issue_leaf(
        ca_key: &p256::ecdsa::SigningKey,
        ca_der: &[u8],
        cn: &str,
        leaf_spki: SubjectPublicKeyInfoOwned,
        serial: u32,
    ) -> Result<Vec<u8>> {
        let ca = Certificate::from_der(ca_der)?;
        let issuer = ca.tbs_certificate.subject.clone();
        let subject = Name::from_str(&format!("CN={cn}")).map_err(|e| anyhow!("name: {e}"))?;
        let builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(serial),
            Validity::from_now(Duration::from_secs(3600)).map_err(|e| anyhow!("validity: {e}"))?,
            subject,
            leaf_spki,
            ca_key,
        )
        .map_err(|e| anyhow!("leaf builder: {e}"))?;
        let cert = builder
            .build::<p256::ecdsa::DerSignature>()
            .map_err(|e| anyhow!("leaf sign: {e}"))?;
        Ok(cert.to_der()?)
    }

    /// Build a P-256 signer with a fresh key + leaf cert issued by `ca`.
    pub fn new_p256_signer(
        ca_key: &p256::ecdsa::SigningKey,
        ca_der: &[u8],
        cn: &str,
    ) -> Result<EcdsaP256Signer> {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let vk = p256::ecdsa::VerifyingKey::from(&key);
        let spki = SubjectPublicKeyInfoOwned::from_key(vk).map_err(|e| anyhow!("spki: {e}"))?;
        let leaf = issue_leaf(ca_key, ca_der, cn, spki, 10)?;
        Ok(EcdsaP256Signer::new(key, leaf))
    }

    /// Build an Ed25519 signer with a fresh key + leaf cert issued by `ca`.
    pub fn new_ed25519_signer(
        ca_key: &p256::ecdsa::SigningKey,
        ca_der: &[u8],
        cn: &str,
    ) -> Result<Ed25519Signer> {
        let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key())
            .map_err(|e| anyhow!("spki: {e}"))?;
        let leaf = issue_leaf(ca_key, ca_der, cn, spki, 11)?;
        Ok(Ed25519Signer::new(key, leaf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::ChunkMeta;

    fn mint_ca(cn: &str) -> (p256::ecdsa::SigningKey, Vec<u8>) {
        dev::mint_ca(cn).unwrap()
    }
    fn p256_signer(ca_key: &p256::ecdsa::SigningKey, ca_der: &[u8], cn: &str) -> EcdsaP256Signer {
        dev::new_p256_signer(ca_key, ca_der, cn).unwrap()
    }
    fn ed25519_signer(ca_key: &p256::ecdsa::SigningKey, ca_der: &[u8], cn: &str) -> Ed25519Signer {
        dev::new_ed25519_signer(ca_key, ca_der, cn).unwrap()
    }

    fn chunk(seq: u32, fill: u8) -> ChunkMeta {
        ChunkMeta {
            fdata_offset: 0,
            file_index: 0,
            chunk_seq: seq,
            checksum: [fill; 32],
            compressed: false,
            uncompressed_size: 100,
            compressed_size: 100,
        }
    }

    fn sample_file() -> FileMeta {
        FileMeta {
            relative_path: "pkg/artifact-1.0.0.jar".into(),
            compressed: false,
            uncompressed_size: 300,
            chunks: vec![chunk(0, 0xaa), chunk(1, 0xbb), chunk(2, 0xcc)],
        }
    }

    #[test]
    fn ed25519_round_trip() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = ed25519_signer(&ca_key, &ca_der, "ed-signer");
        assert_eq!(signer.algorithm(), SigAlg::Ed25519);

        let digest = file_digest(&sample_file());
        let cms = signer.sign_digest(&digest).unwrap();
        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();

        let id = verify_digest(&digest, &cms, &roots).unwrap();
        assert_eq!(id.common_name, "ed-signer");
    }

    #[test]
    fn p256_round_trip() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = p256_signer(&ca_key, &ca_der, "p256-signer");
        assert_eq!(signer.algorithm(), SigAlg::EcdsaP256);

        let digest = file_digest(&sample_file());
        let cms = signer.sign_digest(&digest).unwrap();
        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();

        let id = verify_digest(&digest, &cms, &roots).unwrap();
        assert_eq!(id.common_name, "p256-signer");
        // The same verifier handles both algorithms (algorithm read from CMS).
        let v = CmsVerifier;
        assert!(v.verify_digest(&digest, &cms, &roots).is_ok());
    }

    #[test]
    fn signer_from_pkcs8_round_trip_both_algs() {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;

        let (ca_key, ca_der) = mint_ca("Znippy Loader CA");
        let roots = CertStore::from_der_certs(&[ca_der.clone()]).unwrap();
        let digest = file_digest(&sample_file());

        // ── P-256: mint a key, PKCS#8-encode it, issue a matching leaf, reload ──
        let p_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let p_spki =
            SubjectPublicKeyInfoOwned::from_key(p256::ecdsa::VerifyingKey::from(&p_key)).unwrap();
        let p_leaf = dev::issue_leaf(&ca_key, &ca_der, "loaded-p256", p_spki, 20).unwrap();
        let p_pkcs8 = p256::SecretKey::from(&p_key).to_pkcs8_der().unwrap();
        let p_signer = signer_from_pkcs8(SigAlg::EcdsaP256, p_pkcs8.as_bytes(), &p_leaf).unwrap();
        let p_cms = p_signer.sign_digest(&digest).unwrap();
        assert_eq!(
            verify_digest(&digest, &p_cms, &roots).unwrap().common_name,
            "loaded-p256"
        );

        // ── Ed25519: same flow through the loader ──
        let e_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let e_spki = SubjectPublicKeyInfoOwned::from_key(e_key.verifying_key()).unwrap();
        let e_leaf = dev::issue_leaf(&ca_key, &ca_der, "loaded-ed", e_spki, 21).unwrap();
        let e_pkcs8 = e_key.to_pkcs8_der().unwrap();
        let e_signer = signer_from_pkcs8(SigAlg::Ed25519, e_pkcs8.as_bytes(), &e_leaf).unwrap();
        let e_cms = e_signer.sign_digest(&digest).unwrap();
        assert_eq!(
            verify_digest(&digest, &e_cms, &roots).unwrap().common_name,
            "loaded-ed"
        );

        assert_eq!(SigAlg::from_name("p256").unwrap(), SigAlg::EcdsaP256);
        assert_eq!(SigAlg::from_name("ed25519").unwrap(), SigAlg::Ed25519);
        assert!(SigAlg::from_name("rsa").is_err());
    }

    #[test]
    fn tamper_chunk_hash_breaks_verification() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = p256_signer(&ca_key, &ca_der, "p256-signer");
        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();

        let file = sample_file();
        let digest = file_digest(&file);
        let cms = signer.sign_digest(&digest).unwrap();
        assert!(verify_digest(&digest, &cms, &roots).is_ok());

        // Flip one chunk's BLAKE3 → the recomputed digest changes → verify fails.
        let mut tampered = file;
        tampered.chunks[1].checksum[0] ^= 0x01;
        let bad_digest = file_digest(&tampered);
        assert_ne!(digest, bad_digest);
        assert!(verify_digest(&bad_digest, &cms, &roots).is_err());
    }

    #[test]
    fn wrong_ca_is_rejected() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = ed25519_signer(&ca_key, &ca_der, "ed-signer");
        let digest = file_digest(&sample_file());
        let cms = signer.sign_digest(&digest).unwrap();

        // A different, untrusted CA.
        let (_other_key, other_ca_der) = mint_ca("Some Other CA");
        let roots = CertStore::from_der_certs(&[other_ca_der]).unwrap();
        let err = verify_digest(&digest, &cms, &roots).unwrap_err();
        assert!(err.to_string().contains("chain"), "unexpected error: {err}");
    }

    #[test]
    fn archive_root_changes_when_an_artifact_changes() {
        let footer = crate::index::IndexFooter::Multi {
            manifest_offset: 4096,
        };
        let d1 = file_digest(&sample_file());
        let mut other = sample_file();
        other.relative_path = "pkg/other-2.0.0.jar".into();
        let d2 = file_digest(&other);

        let root_a = archive_root(&[("a".into(), d1), ("b".into(), d2)], &footer);
        // Order-independent (sorted by path).
        let root_b = archive_root(&[("b".into(), d2), ("a".into(), d1)], &footer);
        assert_eq!(root_a, root_b);

        // Tamper one artifact digest → root changes.
        let mut d2_bad = d2;
        d2_bad[0] ^= 0xff;
        let root_c = archive_root(&[("a".into(), d1), ("b".into(), d2_bad)], &footer);
        assert_ne!(root_a, root_c);
    }

    #[test]
    fn archive_round_trip_signs_root() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = p256_signer(&ca_key, &ca_der, "archive-signer");
        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();
        let footer = crate::index::IndexFooter::Multi {
            manifest_offset: 8192,
        };

        let digests = vec![
            ("pkg/a.jar".to_string(), file_digest(&sample_file())),
            ("pkg/b.jar".to_string(), [0x42u8; 32]),
        ];
        let root = archive_root(&digests, &footer);
        let cms = signer.sign_digest(&root).unwrap();
        assert!(verify_digest(&root, &cms, &roots).is_ok());
    }

    // ── Phase B: seal a real signed archive via ArrowIpcSink, then verify ──

    use crate::index::{
        lookup_schema, read_znippy_full_manifest, read_znippy_index, read_znippy_manifest,
    };
    use crate::meta_sink::{ArchiveMetaSink, ArrowIpcSink, GroupKey};
    use arrow::array::{
        BooleanBuilder, FixedSizeBinaryBuilder, RecordBatch, StringBuilder, UInt32Builder,
        UInt64Builder,
    };
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;
    use std::sync::Arc;

    /// Build a base-schema sub-index batch from `(path, [chunk_checksums])`.
    fn base_batch(files: &[(&str, Vec<[u8; 32]>)]) -> (Arc<arrow::datatypes::Schema>, RecordBatch) {
        let schema = lookup_schema();
        let mut path_b = StringBuilder::new();
        let mut seq_b = UInt32Builder::new();
        let mut fdata_b = UInt64Builder::new();
        let mut comp_b = BooleanBuilder::new();
        let mut usz_b = UInt64Builder::new();
        let mut boff_b = UInt64Builder::new();
        let mut bsz_b = UInt64Builder::new();
        let mut ck_b = FixedSizeBinaryBuilder::with_capacity(8, 32);
        let mut blob_off = 0u64;
        for (path, cks) in files {
            for (seq, ck) in cks.iter().enumerate() {
                path_b.append_value(path);
                seq_b.append_value(seq as u32);
                fdata_b.append_value(seq as u64 * 100);
                comp_b.append_value(false);
                usz_b.append_value(100);
                boff_b.append_value(blob_off);
                bsz_b.append_value(100);
                ck_b.append_value(ck).unwrap();
                blob_off += 100;
            }
        }
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(path_b.finish()),
                Arc::new(seq_b.finish()),
                Arc::new(fdata_b.finish()),
                Arc::new(comp_b.finish()),
                Arc::new(usz_b.finish()),
                Arc::new(boff_b.finish()),
                Arc::new(bsz_b.finish()),
                Arc::new(ck_b.finish()),
            ],
        )
        .unwrap();
        (schema, batch)
    }

    /// Seal a signed archive at `path` and return the data row count.
    fn seal_signed(path: &std::path::Path, signer: Box<dyn ArchiveSigner + Send>) -> usize {
        let files = vec![
            ("pkg/a-1.0.0.jar", vec![[0x11u8; 32], [0x12u8; 32]]),
            ("pkg/b-2.0.0.jar", vec![[0x21u8; 32]]),
            (
                "pkg/c-3.0.0.jar",
                vec![[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]],
            ),
        ];
        let row_count: usize = files.iter().map(|(_, c)| c.len()).sum();
        let (schema, batch) = base_batch(&files);

        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        // 16 bytes of dummy "blob" region before the metadata layer.
        f.write_all_at(&[0u8; 16], 0).unwrap();
        let file = Arc::new(f);
        let mut sink = ArrowIpcSink::new(file, 16).with_signer(signer);
        sink.push_subindex(
            &schema,
            &[batch],
            GroupKey {
                pkg_type: 0,
                repo: "repo".into(),
                module_name: "data".into(),
            },
        )
        .unwrap();
        Box::new(sink).finish().unwrap();
        row_count
    }

    #[test]
    fn seal_signed_archive_round_trip() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = ed25519_signer(&ca_key, &ca_der, "archive-signer");
        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.znippy");
        let rows = seal_signed(&path, Box::new(signer));

        // The default-path index reader ignores the (reserved) signature sections.
        let (_s, batches) = read_znippy_index(&path).unwrap();
        let got_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(got_rows, rows, "data rows unaffected by signature sections");
        // The data manifest also hides reserved entries.
        let manifest = read_znippy_manifest(&path).unwrap();
        assert!(
            manifest
                .iter()
                .all(|e| !crate::index::is_reserved_module(&e.module_name))
        );

        // Whole-archive provenance verifies, and every artifact is signed.
        let report = verify_archive(&path, &roots).unwrap();
        assert_eq!(report.signer.common_name, "archive-signer");
        assert_eq!(report.artifacts_verified, 3);

        // Per-artifact entry point (what holger calls).
        let cms = artifact_signature_for(&path, "pkg/b-2.0.0.jar")
            .unwrap()
            .unwrap();
        let file = FileMeta {
            relative_path: "pkg/b-2.0.0.jar".into(),
            compressed: false,
            uncompressed_size: 100,
            chunks: vec![chunk(0, 0x21)],
        };
        let id = verify_artifact(&file, &cms, &roots).unwrap();
        assert_eq!(id.common_name, "archive-signer");
    }

    #[test]
    fn unsigned_seal_writes_no_signature_sections() {
        // Even with the `sign` feature compiled in, sealing WITHOUT a signer is a
        // no-op for the signature layer: no reserved sign sections are written, so
        // the archive is byte-for-byte the v0.7 format (additive guarantee).
        let files = vec![("pkg/a.jar", vec![[0x11u8; 32]])];
        let (schema, batch) = base_batch(&files);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.znippy");
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all_at(&[0u8; 16], 0).unwrap();
        let mut sink = ArrowIpcSink::new(Arc::new(f), 16); // no .with_signer(..)
        sink.push_subindex(
            &schema,
            &[batch],
            GroupKey {
                pkg_type: 0,
                repo: "repo".into(),
                module_name: "data".into(),
            },
        )
        .unwrap();
        Box::new(sink).finish().unwrap();

        assert!(read_archive_signatures(&path).unwrap().is_none());
        let manifest = read_znippy_full_manifest(&path).unwrap().0;
        assert!(
            manifest
                .iter()
                .all(|e| e.module_name != crate::index::SIGN_ARCHIVE_MODULE
                    && e.module_name != crate::index::SIGN_ARTIFACTS_MODULE),
            "no signature sections in an unsigned seal"
        );
    }

    #[test]
    fn tampering_a_signed_archive_is_detected() {
        let (ca_key, ca_der) = mint_ca("Znippy Test CA");
        let signer = p256_signer(&ca_key, &ca_der, "archive-signer");
        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.znippy");
        seal_signed(&path, Box::new(signer));
        assert!(verify_archive(&path, &roots).is_ok());

        // Tamper the served artifact CMS: verifying it against the (untouched)
        // recomputed digest must fail.
        let cms = artifact_signature_for(&path, "pkg/a-1.0.0.jar")
            .unwrap()
            .unwrap();
        let mut bad = cms.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let file = FileMeta {
            relative_path: "pkg/a-1.0.0.jar".into(),
            compressed: false,
            uncompressed_size: 200,
            chunks: vec![chunk(0, 0x11), chunk(1, 0x12)],
        };
        assert!(verify_artifact(&file, &bad, &roots).is_err());

        // Tamper the artifact's content (a chunk hash) → recomputed digest no
        // longer matches the genuine signature.
        let mut tampered = file;
        tampered.chunks[0].checksum[0] ^= 0x01;
        assert!(verify_artifact(&tampered, &cms, &roots).is_err());
    }

    // ── Phase C: holger-interop. Mint the CA+leaf with cert-helper (OpenSSL),
    //    exactly as holger/mannequin/src/pki does, and verify a single served
    //    artifact's signature through the pure-Rust sign path. ──
    #[cfg(feature = "sign-holger-test")]
    #[test]
    fn holger_verifies_a_served_artifact() {
        use cert_helper::certificate::{
            CertBuilder, HashAlg, KeyType, Usage, UseesBuilderFields, X509Parts,
        };
        use p256::pkcs8::DecodePrivateKey;
        use x509_cert::der::DecodePem;

        // 1. Mannequin-style P-256 CA.
        let ca = CertBuilder::new()
            .common_name("Holger Mannequin CA")
            .country_name("SE")
            .organization("Holger Test")
            .is_ca(true)
            .key_type(KeyType::P256)
            .signature_alg(HashAlg::SHA256)
            .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect())
            .build_and_self_sign()
            .unwrap();

        // 2. CA issues a signer leaf cert (P-256), like issue_server_cert.
        let leaf = CertBuilder::new()
            .common_name("znippy-artifact-signer")
            .key_type(KeyType::P256)
            .signature_alg(HashAlg::SHA256)
            .key_usage([Usage::clientauth].into_iter().collect())
            .build_and_sign(&ca)
            .unwrap();

        let ca_pem = ca.get_pem().unwrap();
        let leaf_cert_pem = leaf.get_pem().unwrap();
        let leaf_key_pem = leaf.get_private_key().unwrap();

        // 3. Convert to the shapes the pure-Rust API consumes.
        let ca_der = x509_cert::Certificate::from_pem(&ca_pem)
            .unwrap()
            .to_der()
            .unwrap();
        let leaf_der = x509_cert::Certificate::from_pem(&leaf_cert_pem)
            .unwrap()
            .to_der()
            .unwrap();
        let key_pem_str = String::from_utf8(leaf_key_pem).unwrap();
        let secret = p256::SecretKey::from_pkcs8_pem(&key_pem_str)
            .or_else(|_| p256::SecretKey::from_sec1_pem(&key_pem_str))
            .expect("load leaf P-256 key");
        let signer = EcdsaP256Signer::new(p256::ecdsa::SigningKey::from(secret), leaf_der);

        // 4. holger's storage layer would seal a signed archive; here we sign one
        //    served artifact's digest directly, then verify it as holger would.
        let file = sample_file();
        let cms = signer.sign_digest(&file_digest(&file)).unwrap();

        let roots = CertStore::from_der_certs(&[ca_der]).unwrap();
        // verify_artifact is the exact call holger makes when serving a file.
        let id = verify_artifact(&file, &cms, &roots).unwrap();
        assert_eq!(id.common_name, "znippy-artifact-signer");

        // An untrusted CA is rejected (negative control).
        let other = CertBuilder::new()
            .common_name("Rogue CA")
            .is_ca(true)
            .key_type(KeyType::P256)
            .signature_alg(HashAlg::SHA256)
            .key_usage([Usage::certsign].into_iter().collect())
            .build_and_self_sign()
            .unwrap();
        let other_der = x509_cert::Certificate::from_pem(&other.get_pem().unwrap())
            .unwrap()
            .to_der()
            .unwrap();
        let bad_roots = CertStore::from_der_certs(&[other_der]).unwrap();
        assert!(verify_artifact(&file, &cms, &bad_roots).is_err());
    }
}
