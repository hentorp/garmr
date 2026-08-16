// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! A consistent logical dump of the state store, taken while the writer runs.
//!
//! The existing backup is offline: it stops the writer and copies the redb file.
//! A 24/7 SOC cannot do that, so this captures the same content from a single
//! **read transaction** — redb's MVCC snapshot — which is what makes the result
//! coherent without pausing anything. Writes committed after the transaction
//! opens are simply not in it, which is the definition of a snapshot rather than
//! a defect.
//!
//! # Why a logical dump rather than a file copy
//!
//! Copying the file under a live writer can capture a torn page. A logical dump
//! reads through the same transactional view every query uses, so what comes out
//! was, at one instant, exactly the database.
//!
//! # Why the shape table exists
//!
//! redb type-checks a table at open, and `ReadOnlyUntypedTable` (2.6.3) exposes
//! only stats and len — there is no generic iteration. So every table must be
//! opened with its real value type, and [`SHAPES`] carries that mapping.
//! [`super::ALL_TABLES`] is the completeness authority; a test asserts the two
//! agree, so a table added later cannot be silently skipped by a backup.

use std::io::{Read, Write};

use garmr_core::{Error, Result};
use redb::{ReadableTable, TableDefinition};

use super::StateStore;

/// Dump format version. Bumped only on an incompatible framing change; the
/// reader refuses anything it does not know rather than guessing.
const DUMP_VERSION: u32 = 1;
const MAGIC: &[u8; 8] = b"GARMRDMP";

/// A table's redb value type. Keys are always `&str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Bytes,
    U64,
    I64,
}

/// Every table with the value type it must be opened as.
///
/// Kept beside the dump because that is the only place the distinction matters.
/// The names are checked against [`super::ALL_TABLES`] by a test, so this cannot
/// fall behind the schema.
pub const SHAPES: &[(&str, Shape)] = &[
    ("actions", Shape::Bytes),
    ("app_baselines", Shape::Bytes),
    ("app_shadow", Shape::Bytes),
    ("app_stateful", Shape::Bytes),
    ("auth", Shape::Bytes),
    ("budget", Shape::U64),
    ("cases", Shape::Bytes),
    ("cold_archives", Shape::Bytes),
    // The deletion ledger travels with a backup on purpose: it is the proof of
    // what was removed, and a backup that carried the archives but not the
    // record of their deletion would restore the data with no trace that it had
    // ever been deleted.
    ("cold_deletions", Shape::Bytes),
    ("cold_meta", Shape::I64),
    ("datasets", Shape::Bytes),
    ("decisions", Shape::Bytes),
    ("env_observations", Shape::Bytes),
    ("env_sightings", Shape::Bytes),
    ("env_transitions", Shape::Bytes),
    ("false_negatives", Shape::Bytes),
    ("feedback", Shape::Bytes),
    ("findings", Shape::Bytes),
    ("hunts", Shape::Bytes),
    ("incident_outcomes", Shape::Bytes),
    ("ingest_seq", Shape::Bytes),
    ("mistakes", Shape::Bytes),
    ("predictions", Shape::Bytes),
    ("proposals", Shape::Bytes),
    ("query_plans", Shape::Bytes),
    ("registry", Shape::Bytes),
    ("registry_promotions", Shape::Bytes),
    ("silences", Shape::Bytes),
    ("suppression", Shape::U64),
    ("templates", Shape::I64),
    // Erasure predicates travel with a backup for the same reason the deletion
    // ledger does: a restore must restore the OBLIGATION to keep erasing late
    // arrivals, not just the data.
    ("tombstones", Shape::Bytes),
];

/// What a dump captured, for the manifest and for an operator to sanity-check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DumpStats {
    pub tables: usize,
    pub rows: u64,
    pub bytes: u64,
}

fn put_u32(w: &mut impl Write, v: u32) -> Result<()> {
    w.write_all(&v.to_le_bytes()).map_err(Error::store)
}
fn put_u64(w: &mut impl Write, v: u64) -> Result<()> {
    w.write_all(&v.to_le_bytes()).map_err(Error::store)
}
fn put_bytes(w: &mut impl Write, b: &[u8]) -> Result<()> {
    put_u64(w, b.len() as u64)?;
    w.write_all(b).map_err(Error::store)
}
fn get_u32(r: &mut impl Read) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(Error::store)?;
    Ok(u32::from_le_bytes(b))
}
fn get_u64(r: &mut impl Read) -> Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(Error::store)?;
    Ok(u64::from_le_bytes(b))
}
fn get_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let n = get_u64(r)? as usize;
    // A corrupt length must not become a multi-gigabyte allocation before the
    // read fails. 64 MiB is far above any real row here.
    if n > 64 * 1024 * 1024 {
        return Err(Error::store(format!("dump: implausible field length {n}")));
    }
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).map_err(Error::store)?;
    Ok(v)
}

impl StateStore {
    /// Write a consistent logical dump.
    ///
    /// Every table is read inside ONE read transaction, so the result is a
    /// single point-in-time view even though the writer keeps committing
    /// throughout. Scalar values are normalised to 8 little-endian bytes, so the
    /// framing is uniform and the reader needs no per-table branching beyond
    /// choosing where to put them back.
    pub fn dump_to(&self, w: &mut impl Write) -> Result<DumpStats> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        w.write_all(MAGIC).map_err(Error::store)?;
        put_u32(w, DUMP_VERSION)?;
        put_u32(w, SHAPES.len() as u32)?;

        let mut stats = DumpStats {
            tables: SHAPES.len(),
            ..Default::default()
        };
        for (name, shape) in SHAPES {
            put_bytes(w, name.as_bytes())?;
            // Rows are buffered per table so the count can be written first —
            // a reader that knows the count up front can reject a truncated
            // dump instead of silently restoring a partial table.
            let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            match shape {
                Shape::Bytes => {
                    let t = TableDefinition::<&str, &[u8]>::new(name);
                    // A table that has never been written does not exist yet;
                    // that is an empty table, not a failure.
                    if let Ok(tbl) = rtx.open_table(t) {
                        for e in tbl.iter().map_err(Error::store)? {
                            let (k, v) = e.map_err(Error::store)?;
                            rows.push((k.value().as_bytes().to_vec(), v.value().to_vec()));
                        }
                    }
                }
                Shape::U64 => {
                    let t = TableDefinition::<&str, u64>::new(name);
                    if let Ok(tbl) = rtx.open_table(t) {
                        for e in tbl.iter().map_err(Error::store)? {
                            let (k, v) = e.map_err(Error::store)?;
                            rows.push((
                                k.value().as_bytes().to_vec(),
                                v.value().to_le_bytes().to_vec(),
                            ));
                        }
                    }
                }
                Shape::I64 => {
                    let t = TableDefinition::<&str, i64>::new(name);
                    if let Ok(tbl) = rtx.open_table(t) {
                        for e in tbl.iter().map_err(Error::store)? {
                            let (k, v) = e.map_err(Error::store)?;
                            rows.push((
                                k.value().as_bytes().to_vec(),
                                v.value().to_le_bytes().to_vec(),
                            ));
                        }
                    }
                }
            }
            put_u64(w, rows.len() as u64)?;
            for (k, v) in &rows {
                put_bytes(w, k)?;
                put_bytes(w, v)?;
                stats.bytes += (k.len() + v.len()) as u64;
            }
            stats.rows += rows.len() as u64;
        }
        w.flush().map_err(Error::store)?;
        Ok(stats)
    }

    /// Load a dump into this (expected empty) store.
    ///
    /// Restores into the same tables the dump names. A table the dump does not
    /// know is left untouched rather than cleared: this is a restore, not a
    /// synchronisation, and silently emptying something the operator still has
    /// would be the worse mistake.
    pub fn restore_dump(&self, r: &mut impl Read) -> Result<DumpStats> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).map_err(Error::store)?;
        if &magic != MAGIC {
            return Err(Error::store("not a garmr state dump"));
        }
        let version = get_u32(r)?;
        if version != DUMP_VERSION {
            // Refuse rather than guess: a framing change that is read with the
            // wrong rules restores plausible-looking garbage.
            return Err(Error::store(format!(
                "dump format version {version} is not supported (this build reads {DUMP_VERSION})"
            )));
        }
        let table_count = get_u32(r)? as usize;
        let mut stats = DumpStats {
            tables: table_count,
            ..Default::default()
        };
        for _ in 0..table_count {
            let name = String::from_utf8(get_bytes(r)?)
                .map_err(|_| Error::store("dump: table name is not utf-8"))?;
            let shape = SHAPES
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, s)| *s)
                .ok_or_else(|| {
                    // A dump naming a table this build does not have means the
                    // image is from a different schema. Restoring the rest would
                    // produce a store that looks complete and is not.
                    Error::store(format!("dump names unknown table {name:?}"))
                })?;
            let rows = get_u64(r)?;
            let wtx = self.db.begin_write().map_err(Error::store)?;
            {
                match shape {
                    Shape::Bytes => {
                        let mut t = wtx
                            .open_table(TableDefinition::<&str, &[u8]>::new(name.as_str()))
                            .map_err(Error::store)?;
                        for _ in 0..rows {
                            let k = get_bytes(r)?;
                            let v = get_bytes(r)?;
                            let ks = std::str::from_utf8(&k)
                                .map_err(|_| Error::store("dump: key is not utf-8"))?;
                            t.insert(ks, v.as_slice()).map_err(Error::store)?;
                        }
                    }
                    Shape::U64 | Shape::I64 => {
                        let scalar = |v: &[u8]| -> Result<[u8; 8]> {
                            v.try_into()
                                .map_err(|_| Error::store("dump: scalar value is not 8 bytes"))
                        };
                        if shape == Shape::U64 {
                            let mut t = wtx
                                .open_table(TableDefinition::<&str, u64>::new(name.as_str()))
                                .map_err(Error::store)?;
                            for _ in 0..rows {
                                let k = get_bytes(r)?;
                                let v = get_bytes(r)?;
                                let ks = std::str::from_utf8(&k)
                                    .map_err(|_| Error::store("dump: key is not utf-8"))?;
                                t.insert(ks, u64::from_le_bytes(scalar(&v)?))
                                    .map_err(Error::store)?;
                            }
                        } else {
                            let mut t = wtx
                                .open_table(TableDefinition::<&str, i64>::new(name.as_str()))
                                .map_err(Error::store)?;
                            for _ in 0..rows {
                                let k = get_bytes(r)?;
                                let v = get_bytes(r)?;
                                let ks = std::str::from_utf8(&k)
                                    .map_err(|_| Error::store("dump: key is not utf-8"))?;
                                t.insert(ks, i64::from_le_bytes(scalar(&v)?))
                                    .map_err(Error::store)?;
                            }
                        }
                    }
                }
            }
            wtx.commit().map_err(Error::store)?;
            stats.rows += rows;
        }
        Ok(stats)
    }
}
