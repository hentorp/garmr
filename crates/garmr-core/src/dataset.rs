// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 8 — the immutable, content-addressed **dataset snapshot**: the data
//! spine of the safe learning plane (see `docs/architecture/learning-plane.md`).
//!
//! Pure, no I/O. A snapshot pins EXACTLY which cases/events were in and out, the
//! label sources and their trust, the parser/detector/feature versions, a
//! temporal train/val/test split (the newest slice is a never-touched Test
//! holdout), and a BLAKE3 content digest computed by hand (map-order- and
//! input-order-independent, the same reason the audit ledger and registry frame
//! by hand — [`crate::frame`]). Two builds with identical content produce the
//! identical digest; any change to a pinned id/version/label mints a new digest,
//! never a silent rewrite.
//!
//! The manifest lives in `garmr-core` (like [`crate::decision`],
//! [`crate::registry`], [`crate::environment`]) so `garmr-store` can type its
//! append-only `datasets` table and return the [`ExclusionReason`] enum, while
//! all the build/replay logic lives in the `garmr-learning` crate.

use serde::{Deserialize, Serialize};

use crate::{frame, Disposition, TrustSource};

/// Which temporal split a labeled row belongs to. The newest slice is `Test`,
/// the held-out set a challenger is judged on and never fit against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitBucket {
    #[default]
    Train,
    Val,
    Test,
}

/// Why a case was excluded from the labeled set (pinned for auditability).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    /// The case shares an entity with a non-closed (open) case.
    OpenCase,
    /// The case shares an entity with a compromised/adverse case.
    Compromised,
    /// No trusted label (only a prediction / shadow / unresolved).
    UntrustedLabel,
    /// Outside the requested build window.
    OutOfWindow,
    #[default]
    #[serde(other)]
    Unknown,
}

/// The build window, in unix microseconds. A distinct type from
/// `garmr_query::TimeRange` (which core cannot depend on) so the two never
/// collide at a call site that imports both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnapshotWindow {
    #[serde(default)]
    pub from_us: i64,
    #[serde(default)]
    pub to_us: i64,
}

/// The parser/detector/feature versions the labels were produced under (pinned
/// so a later parser/detector change is a visible dataset difference).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetVersions {
    #[serde(default)]
    pub parser_versions: Vec<String>,
    #[serde(default)]
    pub detector_versions: Vec<String>,
    #[serde(default)]
    pub feature_version: String,
}

/// A pinned label source and the trust weight it carried.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct LabelSourcePin {
    #[serde(default)]
    pub kind: TrustSource,
    #[serde(default)]
    pub trust: f32,
}

/// The temporal boundaries (unix micros): `Train` ≤ `train_end_us` < `Val` ≤
/// `val_end_us` < `Test`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TemporalSplit {
    #[serde(default)]
    pub train_end_us: i64,
    #[serde(default)]
    pub val_end_us: i64,
}

/// A case pinned into the dataset (the reproducibility anchor).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedCase {
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub opened_at_us: i64,
}

/// A case excluded from the labeled set, with the reason (pinned).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub reason: ExclusionReason,
}

/// One labeled row: a case's coarse features + its TRUSTED (human/incident)
/// label. Predictions are never a label (invariant #3); membership is built by
/// the pure `garmr-learning` builder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabelRow {
    #[serde(default)]
    pub case_id: String,
    /// The trigger detection's declared level (informational..critical).
    #[serde(default)]
    pub rule_level: String,
    /// Asset-criticality `[0,1]` from the Trusted environment model at build
    /// time (so a criticality-sensitive knob is actually measurable on replay).
    #[serde(default)]
    pub criticality: f32,
    /// The trusted disposition (the ground-truth label).
    #[serde(default)]
    pub trusted_disposition: Disposition,
    /// The trusted severity 0–10.
    #[serde(default)]
    pub trusted_severity: u8,
    /// Where the trusted label came from (`Outcome` | `AnalystDecision`).
    #[serde(default)]
    pub trusted_source: TrustSource,
    #[serde(default)]
    pub opened_at_us: i64,
    #[serde(default)]
    pub split: SplitBucket,
}

/// The immutable, content-addressed dataset snapshot.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DatasetSnapshot {
    #[serde(default)]
    pub name: String,
    /// Build timestamp (unix micros) — METADATA, deliberately EXCLUDED from the
    /// digest so identical content is idempotent.
    #[serde(default)]
    pub built_at_us: i64,
    #[serde(default)]
    pub window: SnapshotWindow,
    #[serde(default)]
    pub versions: DatasetVersions,
    #[serde(default)]
    pub label_sources: Vec<LabelSourcePin>,
    #[serde(default)]
    pub split: TemporalSplit,
    #[serde(default)]
    pub included: Vec<PinnedCase>,
    #[serde(default)]
    pub excluded: Vec<Exclusion>,
    #[serde(default)]
    pub rows: Vec<LabelRow>,
    /// The BLAKE3-hex content identity (`compute_digest`).
    #[serde(default)]
    pub digest: String,
}

/// Is a disposition a dangerous positive (the class the dangerous-FN guard
/// protects)?
pub fn is_dangerous(d: Disposition) -> bool {
    matches!(d, Disposition::Malicious | Disposition::Suspicious)
}

/// Map a case's `opened_at` (unix micros) to its temporal bucket. The newest
/// slice (after `val_end_us`) is the Test holdout.
pub fn assign_split(opened_at_us: i64, split: TemporalSplit) -> SplitBucket {
    if opened_at_us <= split.train_end_us {
        SplitBucket::Train
    } else if opened_at_us <= split.val_end_us {
        SplitBucket::Val
    } else {
        SplitBucket::Test
    }
}

/// Per-bucket sizes: total rows and dangerous-positive rows. Exposes an empty /
/// undersized Test holdout (or one with zero positives) so a vacuous guard is
/// detectable rather than silently passing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketCount {
    pub total: usize,
    pub dangerous: usize,
}

/// Counts across the three temporal buckets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketCounts {
    pub train: BucketCount,
    pub val: BucketCount,
    pub test: BucketCount,
}

impl DatasetSnapshot {
    /// The stable tag for a trust source (for the digest and for provenance).
    fn trust_tag(s: TrustSource) -> &'static str {
        match s {
            TrustSource::Outcome => "outcome",
            TrustSource::AnalystDecision => "analyst_decision",
            TrustSource::DiscountedPrediction => "discounted_prediction",
            TrustSource::Unresolved => "unresolved",
            TrustSource::UnresolvedSelfGenerated => "unresolved_self_generated",
        }
    }

    fn disposition_tag(d: Disposition) -> &'static str {
        match d {
            Disposition::Benign => "benign",
            Disposition::Suspicious => "suspicious",
            Disposition::Malicious => "malicious",
            Disposition::NeedsHuman => "needs_human",
        }
    }

    fn split_tag(s: SplitBucket) -> &'static str {
        match s {
            SplitBucket::Train => "train",
            SplitBucket::Val => "val",
            SplitBucket::Test => "test",
        }
    }

    fn reason_tag(r: ExclusionReason) -> &'static str {
        match r {
            ExclusionReason::OpenCase => "open_case",
            ExclusionReason::Compromised => "compromised",
            ExclusionReason::UntrustedLabel => "untrusted_label",
            ExclusionReason::OutOfWindow => "out_of_window",
            ExclusionReason::Unknown => "unknown",
        }
    }

    /// The content digest over every identity-bearing field (all but `digest`
    /// and the metadata `built_at_us`), framed over CANONICALLY-SORTED parts so
    /// it is independent of serde map order and of input (row/case) order.
    pub fn compute_digest(&self) -> String {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        parts.push(self.name.as_bytes().to_vec());
        parts.push(format!("w:{}:{}", self.window.from_us, self.window.to_us).into_bytes());

        let mut pv = self.versions.parser_versions.clone();
        pv.sort();
        parts.push(format!("pv:{}", pv.join(",")).into_bytes());
        let mut dv = self.versions.detector_versions.clone();
        dv.sort();
        parts.push(format!("dv:{}", dv.join(",")).into_bytes());
        parts.push(format!("fv:{}", self.versions.feature_version).into_bytes());
        parts
            .push(format!("sp:{}:{}", self.split.train_end_us, self.split.val_end_us).into_bytes());

        let mut ls: Vec<String> = self
            .label_sources
            .iter()
            .map(|s| format!("{}:{}", Self::trust_tag(s.kind), s.trust))
            .collect();
        ls.sort();
        parts.push(format!("ls:{}", ls.join(",")).into_bytes());

        let mut inc: Vec<String> = self
            .included
            .iter()
            .map(|c| {
                let mut ev = c.event_ids.clone();
                ev.sort();
                format!("{}|{}|{}", c.case_id, c.opened_at_us, ev.join("+"))
            })
            .collect();
        inc.sort();
        for s in inc {
            parts.push(format!("inc:{s}").into_bytes());
        }

        let mut exc: Vec<String> = self
            .excluded
            .iter()
            .map(|e| format!("{}|{}", e.case_id, Self::reason_tag(e.reason)))
            .collect();
        exc.sort();
        for s in exc {
            parts.push(format!("exc:{s}").into_bytes());
        }

        let mut rows: Vec<String> = self
            .rows
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}",
                    r.case_id,
                    r.rule_level,
                    r.criticality,
                    Self::disposition_tag(r.trusted_disposition),
                    r.trusted_severity,
                    Self::trust_tag(r.trusted_source),
                    r.opened_at_us,
                    Self::split_tag(r.split),
                )
            })
            .collect();
        rows.sort();
        for s in rows {
            parts.push(format!("row:{s}").into_bytes());
        }

        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        frame(&refs)
    }

    /// True iff `digest` is present and equals the recomputed content digest.
    pub fn verify_digest(&self) -> bool {
        !self.digest.is_empty() && self.digest == self.compute_digest()
    }

    /// Recompute and stamp the digest (called once at the end of a build).
    pub fn stamp_digest(&mut self) {
        self.digest = self.compute_digest();
    }

    /// Per-bucket row and dangerous-positive counts.
    pub fn bucket_counts(&self) -> BucketCounts {
        let mut c = BucketCounts::default();
        for r in &self.rows {
            let bucket = match r.split {
                SplitBucket::Train => &mut c.train,
                SplitBucket::Val => &mut c.val,
                SplitBucket::Test => &mut c.test,
            };
            bucket.total += 1;
            if is_dangerous(r.trusted_disposition) {
                bucket.dangerous += 1;
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(case_id: &str, disp: Disposition, at_us: i64, split: SplitBucket) -> LabelRow {
        LabelRow {
            case_id: case_id.into(),
            rule_level: "medium".into(),
            criticality: 0.5,
            trusted_disposition: disp,
            trusted_severity: 5,
            trusted_source: TrustSource::AnalystDecision,
            opened_at_us: at_us,
            split,
        }
    }

    #[test]
    fn empty_object_decodes() {
        let s: DatasetSnapshot = serde_json::from_str("{}").unwrap();
        assert!(s.rows.is_empty());
        assert_eq!(s.digest, "");
    }

    #[test]
    fn digest_is_order_independent() {
        let mut a = DatasetSnapshot {
            name: "d".into(),
            rows: vec![
                row("c1", Disposition::Malicious, 10, SplitBucket::Train),
                row("c2", Disposition::Benign, 20, SplitBucket::Test),
            ],
            included: vec![
                PinnedCase {
                    case_id: "c1".into(),
                    event_ids: vec!["e2".into(), "e1".into()],
                    opened_at_us: 10,
                },
                PinnedCase {
                    case_id: "c2".into(),
                    event_ids: vec!["e3".into()],
                    opened_at_us: 20,
                },
            ],
            ..Default::default()
        };
        a.stamp_digest();

        // Same content, rows + included + event_ids all reordered.
        let mut b = DatasetSnapshot {
            name: "d".into(),
            rows: vec![
                row("c2", Disposition::Benign, 20, SplitBucket::Test),
                row("c1", Disposition::Malicious, 10, SplitBucket::Train),
            ],
            included: vec![
                PinnedCase {
                    case_id: "c2".into(),
                    event_ids: vec!["e3".into()],
                    opened_at_us: 20,
                },
                PinnedCase {
                    case_id: "c1".into(),
                    event_ids: vec!["e1".into(), "e2".into()],
                    opened_at_us: 10,
                },
            ],
            // built_at differs — must NOT affect the digest.
            built_at_us: 999_999,
            ..Default::default()
        };
        b.stamp_digest();
        assert_eq!(
            a.digest, b.digest,
            "digest is content-identity, order/metadata independent"
        );
        assert!(a.verify_digest() && b.verify_digest());
    }

    #[test]
    fn digest_changes_when_a_label_changes() {
        let mut a = DatasetSnapshot {
            name: "d".into(),
            rows: vec![row("c1", Disposition::Malicious, 10, SplitBucket::Test)],
            ..Default::default()
        };
        a.stamp_digest();
        let mut b = a.clone();
        b.rows[0].trusted_disposition = Disposition::Benign; // flip the label
        b.stamp_digest();
        assert_ne!(a.digest, b.digest, "a changed label mints a new digest");
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut a = DatasetSnapshot {
            name: "d".into(),
            rows: vec![row("c1", Disposition::Malicious, 10, SplitBucket::Test)],
            ..Default::default()
        };
        a.stamp_digest();
        assert!(a.verify_digest());
        a.rows[0].trusted_severity = 9; // mutate after stamping
        assert!(!a.verify_digest(), "post-stamp mutation fails verification");
    }

    #[test]
    fn split_assignment_at_boundaries() {
        let sp = TemporalSplit {
            train_end_us: 100,
            val_end_us: 200,
        };
        assert_eq!(assign_split(50, sp), SplitBucket::Train);
        assert_eq!(assign_split(100, sp), SplitBucket::Train); // inclusive lower
        assert_eq!(assign_split(101, sp), SplitBucket::Val);
        assert_eq!(assign_split(200, sp), SplitBucket::Val);
        assert_eq!(assign_split(201, sp), SplitBucket::Test); // newest holdout
    }

    #[test]
    fn bucket_counts_track_dangerous_positives() {
        let s = DatasetSnapshot {
            rows: vec![
                row("c1", Disposition::Malicious, 10, SplitBucket::Test),
                row("c2", Disposition::Benign, 20, SplitBucket::Test),
                row("c3", Disposition::Suspicious, 30, SplitBucket::Test),
                row("c4", Disposition::Benign, 5, SplitBucket::Train),
            ],
            ..Default::default()
        };
        let c = s.bucket_counts();
        assert_eq!(c.test.total, 3);
        assert_eq!(c.test.dangerous, 2); // malicious + suspicious
        assert_eq!(c.train.total, 1);
        assert_eq!(c.train.dangerous, 0);
    }
}
