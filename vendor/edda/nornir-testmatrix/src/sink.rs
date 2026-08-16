//! Where a matrix run's rows go. The [`TestSink`] trait is the durable seam:
//! `nornir` implements it over its Iceberg warehouse; a leaf repo with no
//! warehouse uses the built-in [`JsonFileSink`] (append-only JSON history file)
//! or [`NullSink`] (drop, for dry-runs / tests).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model::{TestResultRow, rows_to_json};

/// A destination for matrix rows. One `append` per run (all rows share a run id).
///
/// `nornir` implements this with the Iceberg `test_results` table; leaf repos
/// pick a built-in sink. The trait is object-safe so callers can hold a
/// `Box<dyn TestSink>`.
pub trait TestSink {
    /// Persist `rows` (one matrix run). Implementations should treat an empty
    /// slice as a no-op success.
    fn append(&self, rows: &[TestResultRow]) -> Result<()>;
}

/// Drops everything — for dry-runs and tests. Always `Ok`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl TestSink for NullSink {
    fn append(&self, _rows: &[TestResultRow]) -> Result<()> {
        Ok(())
    }
}

/// Appends each run's rows to a JSON-lines history file (one JSON *array* per
/// run, one line per run) so a leaf repo keeps a portable matrix history without
/// a warehouse. Re-readable with [`JsonFileSink::read_all`].
#[derive(Debug, Clone)]
pub struct JsonFileSink {
    path: PathBuf,
}

impl JsonFileSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read every row ever appended (flattening all run-lines back into one Vec).
    pub fn read_all(&self) -> Result<Vec<TestResultRow>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("read {}", self.path.display())),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let batch: Vec<TestResultRow> = serde_json::from_str(line)
                .with_context(|| format!("parse run line in {}", self.path.display()))?;
            out.extend(batch);
        }
        Ok(out)
    }
}

impl TestSink for JsonFileSink {
    fn append(&self, rows: &[TestResultRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        // One compact JSON array per run, on its own line (JSONL of arrays).
        let compact = serde_json::to_string(rows)?;
        // rows_to_json is the human/stable pretty form; we keep the compact
        // serde form for the history file so read_all round-trips exactly.
        let _ = rows_to_json; // referenced for the pretty CLI path elsewhere.
        let mut existing = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("read {}", self.path.display())),
        };
        if !existing.is_empty() && !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing.push_str(&compact);
        existing.push('\n');
        fs::write(&self.path, existing)
            .with_context(|| format!("write {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::status;

    fn rows(run: &str) -> Vec<TestResultRow> {
        vec![
            TestResultRow::unit(run, "z", "z", "a", status::PASS, 1.0, 100, ""),
            TestResultRow::unit(run, "z", "z", "b", status::FAIL, 2.0, 100, "boom"),
        ]
    }

    #[test]
    fn null_sink_swallows_rows() {
        assert!(NullSink.append(&rows("r")).is_ok());
        assert!(NullSink.append(&[]).is_ok());
    }

    #[test]
    fn json_file_sink_round_trips_two_runs() {
        let dir = std::env::temp_dir().join(format!("ntm-sink-{}", crate::model::new_run_id()));
        let file = dir.join("hist.jsonl");
        let sink = JsonFileSink::new(&file);

        // Empty append is a no-op (file not created).
        sink.append(&[]).unwrap();
        assert!(sink.read_all().unwrap().is_empty(), "no rows yet");

        sink.append(&rows("runA")).unwrap();
        sink.append(&rows("runB")).unwrap();

        let back = sink.read_all().unwrap();
        assert_eq!(back.len(), 4, "two runs × two rows = 4 rows read back");
        // Exact value round-trip on the failing row.
        let fail = back
            .iter()
            .find(|r| r.test_name == "b" && r.run_id == "runA")
            .unwrap();
        assert_eq!(fail.status, status::FAIL);
        assert_eq!(fail.message, "boom");
        assert_eq!(fail.duration_ms, 2.0);
        // run ids both present.
        assert!(back.iter().any(|r| r.run_id == "runA"));
        assert!(back.iter().any(|r| r.run_id == "runB"));

        let _ = fs::remove_dir_all(&dir);
    }
}
