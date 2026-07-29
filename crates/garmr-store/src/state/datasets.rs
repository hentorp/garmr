// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 8 — the append-only, content-keyed `datasets` table: immutable
//! [`DatasetSnapshot`]s, keyed by their own content digest.
//!
//! Because the key IS the content digest, a re-put of identical content is an
//! idempotent no-op and a differing-content collision at the same digest is a
//! blake3 break (refused, mirroring the `register_record` guard). `put_dataset`
//! additionally REFUSES any manifest that fails its own `verify_digest`, so a
//! tampered or mis-stamped snapshot can never land. Readers tolerantly skip an
//! undecodable row (the Phase 3/4/5 idiom).

use garmr_core::{DatasetSnapshot, Error, Result};
use redb::ReadableTable;

use super::{StateStore, DATASETS};

/// The result of storing a dataset snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatasetPutOutcome {
    /// A new snapshot was stored.
    Inserted,
    /// The exact same content was already stored (idempotent no-op).
    AlreadyIdentical,
    /// The digest key exists with DIFFERENT content — refused (a blake3 break or
    /// corruption; a snapshot digest is never rewritten).
    Conflict,
}

impl StateStore {
    /// Store an immutable dataset snapshot, keyed by its content digest.
    /// Idempotent by content; refuses a manifest that fails digest verification.
    pub fn put_dataset(&self, s: &DatasetSnapshot) -> Result<DatasetPutOutcome> {
        if !s.verify_digest() {
            return Err(Error::store(
                "refusing to store a dataset snapshot that fails digest verification",
            ));
        }
        let key = s.digest.clone();
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let outcome;
        {
            let mut t = wtx.open_table(DATASETS).map_err(Error::store)?;
            let existing: Option<DatasetSnapshot> = t
                .get(key.as_str())
                .map_err(Error::store)?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()
                .map_err(Error::store)?;
            match existing {
                Some(cur) if cur == *s => outcome = DatasetPutOutcome::AlreadyIdentical,
                Some(_) => outcome = DatasetPutOutcome::Conflict,
                None => {
                    let bytes = serde_json::to_vec(s).map_err(Error::store)?;
                    t.insert(key.as_str(), bytes.as_slice())
                        .map_err(Error::store)?;
                    outcome = DatasetPutOutcome::Inserted;
                }
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(outcome)
    }

    /// Fetch one snapshot by its content digest.
    pub fn get_dataset(&self, digest: &str) -> Result<Option<DatasetSnapshot>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(DATASETS).map_err(Error::store)?;
        match t.get(digest).map_err(Error::store)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            )),
            None => Ok(None),
        }
    }

    /// All stored snapshots (tolerantly skipping any undecodable row).
    pub fn list_datasets(&self) -> Result<Vec<DatasetSnapshot>> {
        self.scan_tolerant(DATASETS, "dataset_snapshot")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::{Disposition, LabelRow, SplitBucket, TrustSource};

    fn tmp_state() -> (StateStore, std::path::PathBuf) {
        let dir = std::env::temp_dir();
        let unique = format!(
            "garmr-ds-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = dir.join(unique);
        (StateStore::open(&path).unwrap(), path)
    }

    fn snapshot(name: &str, disp: Disposition) -> DatasetSnapshot {
        let mut s = DatasetSnapshot {
            name: name.into(),
            rows: vec![LabelRow {
                case_id: "c1".into(),
                rule_level: "high".into(),
                criticality: 1.0,
                trusted_disposition: disp,
                trusted_severity: 8,
                trusted_source: TrustSource::AnalystDecision,
                opened_at_us: 100,
                split: SplitBucket::Test,
            }],
            ..Default::default()
        };
        s.stamp_digest();
        s
    }

    #[test]
    fn put_get_roundtrip_and_idempotent() {
        let (st, path) = tmp_state();
        let s = snapshot("d", Disposition::Malicious);
        assert_eq!(st.put_dataset(&s).unwrap(), DatasetPutOutcome::Inserted);
        assert_eq!(
            st.put_dataset(&s).unwrap(),
            DatasetPutOutcome::AlreadyIdentical
        );
        let got = st.get_dataset(&s.digest).unwrap().unwrap();
        assert_eq!(got, s);
        assert_eq!(st.list_datasets().unwrap().len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn refuses_a_tampered_snapshot() {
        let (st, path) = tmp_state();
        let mut s = snapshot("d", Disposition::Malicious);
        s.rows[0].trusted_disposition = Disposition::Benign; // mutate AFTER stamping
        assert!(!s.verify_digest());
        assert!(
            st.put_dataset(&s).is_err(),
            "a mis-stamped manifest is refused"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn distinct_content_lands_under_distinct_digests() {
        let (st, path) = tmp_state();
        let a = snapshot("d", Disposition::Malicious);
        let b = snapshot("d", Disposition::Benign); // different label ⇒ different digest
        assert_ne!(a.digest, b.digest);
        assert_eq!(st.put_dataset(&a).unwrap(), DatasetPutOutcome::Inserted);
        assert_eq!(st.put_dataset(&b).unwrap(), DatasetPutOutcome::Inserted);
        assert_eq!(st.list_datasets().unwrap().len(), 2);
        let _ = std::fs::remove_file(path);
    }
}