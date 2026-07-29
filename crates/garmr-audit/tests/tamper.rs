// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end integrity tests, including the mandatory tamper-detection cases
//! (brief §TESTING 1–6): mutation, deletion, reordering, truncation, invalid
//! signatures, and fail-closed on durable-write failure.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use garmr_audit::{
    action, ActorType, AuditLedger, AuditRecord, ContentMode, FindingKind, LedgerConfig, Outcome,
    SoftwareSigner, TrustRoot,
};

fn small_cfg(per_record_sign: bool) -> LedgerConfig {
    LedgerConfig {
        node_id: "test".into(),
        content_mode: ContentMode::DigestOnly,
        per_record_sign,
        segment_max_records: 5,
        checkpoint_every: 3,
        fsync: true,
    }
}

fn signer() -> Arc<SoftwareSigner> {
    Arc::new(SoftwareSigner::from_seed([7u8; 32]))
}

fn a_record() -> AuditRecord {
    AuditRecord::new(action::QUERY, "obj")
        .actor(ActorType::Human, "operator", Some("admin"))
        .outcome(Outcome::Success)
        .reason("AAAA")
}

fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join("segments").join(format!("{id:016x}.jsonl"))
}

fn read_lines(p: &Path) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

fn write_lines(p: &Path, lines: &[String]) {
    let mut s = lines.join("\n");
    s.push('\n');
    fs::write(p, s).unwrap();
}

#[test]
fn roundtrip_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    for _ in 0..7 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    let report = verify(dir.path(), pk);
    assert!(
        report.ok,
        "clean ledger should verify: {:?}",
        report.findings
    );
    assert_eq!(report.records_checked, 7);
    assert_eq!(report.last_sequence, 7);
}

#[test]
fn mutating_a_record_breaks_verification() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    for _ in 0..4 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    // Flip a payload byte in the second record (same length keeps JSON valid).
    let p = seg_path(dir.path(), 1);
    let mut lines = read_lines(&p);
    lines[1] = lines[1].replacen("AAAA", "BBBB", 1);
    write_lines(&p, &lines);

    let report = verify(dir.path(), pk);
    assert!(!report.ok);
    assert!(
        has(&report, FindingKind::HashMismatch),
        "{:?}",
        report.findings
    );
}

#[test]
fn deleting_a_record_breaks_verification() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    for _ in 0..4 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    let p = seg_path(dir.path(), 1);
    let mut lines = read_lines(&p);
    lines.remove(1); // drop the second record
    write_lines(&p, &lines);

    let report = verify(dir.path(), pk);
    assert!(!report.ok);
    assert!(
        has(&report, FindingKind::SequenceGap) || has(&report, FindingKind::ChainBreak),
        "{:?}",
        report.findings
    );
}

#[test]
fn reordering_records_breaks_verification() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    for _ in 0..4 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    let p = seg_path(dir.path(), 1);
    let mut lines = read_lines(&p);
    lines.swap(1, 2);
    write_lines(&p, &lines);

    let report = verify(dir.path(), pk);
    assert!(!report.ok);
    assert!(
        has(&report, FindingKind::SequenceGap),
        "{:?}",
        report.findings
    );
}

#[test]
fn truncating_a_sealed_segment_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    // 6 records: seg 1 fills to 5 and is sealed (signed checkpoint, count=5); the
    // 6th lands in seg 2.
    for _ in 0..6 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    // Drop the last record of the sealed segment 1.
    let p = seg_path(dir.path(), 1);
    let mut lines = read_lines(&p);
    lines.pop();
    write_lines(&p, &lines);

    let report = verify(dir.path(), pk);
    assert!(!report.ok);
    assert!(
        has(&report, FindingKind::Truncated),
        "{:?}",
        report.findings
    );
}

#[test]
fn invalid_signature_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(true), signer()).unwrap();
    for _ in 0..3 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    // Flip one hex nibble of a record's signature.
    let p = seg_path(dir.path(), 1);
    let mut lines = read_lines(&p);
    lines[1] = flip_signature(&lines[1]);
    write_lines(&p, &lines);

    let report = verify(dir.path(), pk);
    assert!(!report.ok);
    assert!(
        has(&report, FindingKind::BadSignature),
        "{:?}",
        report.findings
    );
}

#[cfg(unix)]
#[test]
fn append_fails_closed_when_write_fails() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = small_cfg(false);
    cfg.segment_max_records = 2;
    let ledger = AuditLedger::open(dir.path(), cfg, signer()).unwrap();
    ledger.append(a_record()).unwrap();
    ledger.append(a_record()).unwrap();
    assert_eq!(ledger.head_sequence(), 2);

    // Make the segments directory read-only, so the next append (which must roll
    // to a new segment) cannot create the file.
    let seg_dir = dir.path().join("segments");
    fs::set_permissions(&seg_dir, fs::Permissions::from_mode(0o500)).unwrap();

    let mut protected_change_applied = false;
    match ledger.append(a_record()) {
        Ok(_) => protected_change_applied = true,
        Err(_) => { /* abort the protected change */ }
    }
    assert!(
        !protected_change_applied,
        "a protected change must not proceed when the audit write fails"
    );
    // The chain did not advance.
    assert_eq!(ledger.head_sequence(), 2);

    // Restore perms so the tempdir can be cleaned up, and confirm recovery works.
    fs::set_permissions(&seg_dir, fs::Permissions::from_mode(0o700)).unwrap();
    ledger.append(a_record()).unwrap();
    assert_eq!(ledger.head_sequence(), 3);
}

#[test]
fn reopen_continues_the_chain_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    {
        let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
        for _ in 0..3 {
            ledger.append(a_record()).unwrap();
        }
    } // dropped
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    for _ in 0..3 {
        ledger.append(a_record()).unwrap();
    }
    let pk = ledger.public_key();
    let report = verify(dir.path(), pk);
    assert!(report.ok, "{:?}", report.findings);
    assert_eq!(report.records_checked, 6);
    assert_eq!(report.last_sequence, 6);
}

#[test]
fn torn_trailing_write_is_healed_on_open() {
    let dir = tempfile::tempdir().unwrap();
    {
        let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
        for _ in 0..3 {
            ledger.append(a_record()).unwrap();
        }
    }
    // Simulate a crash mid-append: a partial trailing line with no newline.
    let p = seg_path(dir.path(), 1);
    let mut content = fs::read(&p).unwrap();
    content.extend_from_slice(b"{\"broken\":");
    fs::write(&p, &content).unwrap();

    // Reopen heals the torn tail; further appends chain cleanly.
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    ledger.append(a_record()).unwrap();
    let pk = ledger.public_key();
    let report = verify(dir.path(), pk);
    assert!(report.ok, "torn tail should heal: {:?}", report.findings);
    assert_eq!(report.records_checked, 4);
}

#[test]
fn digest_only_mode_drops_raw_content() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = AuditLedger::open(dir.path(), small_cfg(false), signer()).unwrap();
    ledger
        .append(a_record().content("super secret prompt text"))
        .unwrap();
    let line = &read_lines(&seg_path(dir.path(), 1))[0];
    assert!(
        !line.contains("super secret"),
        "raw content must not be persisted in digest-only mode"
    );
    assert!(!line.contains("\"content\""), "no content field: {line}");
    assert!(line.contains("\"input_digest\""), "digest retained: {line}");
}

// --- helpers ---------------------------------------------------------------

fn verify(dir: &Path, pk: [u8; 32]) -> garmr_audit::VerifyReport {
    garmr_audit::verify_dir(dir, &TrustRoot::from_public_key(pk)).unwrap()
}

fn has(report: &garmr_audit::VerifyReport, kind: FindingKind) -> bool {
    report.findings.iter().any(|f| f.kind == kind)
}

/// Flip one nibble of the `"signature":"…"` hex value in a JSON line.
fn flip_signature(line: &str) -> String {
    let marker = "\"signature\":\"";
    let at = line.find(marker).expect("signature field") + marker.len();
    let mut bytes = line.as_bytes().to_vec();
    bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}