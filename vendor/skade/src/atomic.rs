// Apache-2.0 licensed.

//! Multi-table atomic commits.
//!
//! Iceberg's per-table `Transaction::commit` only guarantees atomicity for
//! one table. For warehouses where several tables represent one logical unit
//! (e.g. `bench_runs` + `dep_graph` + `components` published together as one
//! release), partial visibility of half-committed data is undesirable.
//!
//! redb gives every write transaction global atomicity across all tables in
//! the database. This module exposes that as
//! [`RedbCatalog::atomic_release`]: prepare N `TableCommit`s, write their
//! new metadata files to object storage, then flip every catalog pointer in
//! a single redb transaction. Either *all* table heads advance or *none* do.

use iceberg::table::Table;
use iceberg::{Catalog, Error, ErrorKind, MetadataLocation, Result, TableCommit};
use redb::ReadableTable;
use std::str::FromStr;

use crate::catalog::RedbCatalog;
use crate::error::map_redb;
use crate::keys::table_key;
use crate::store::TABLES;

impl RedbCatalog {
    /// Atomically commit a batch of [`TableCommit`]s.
    ///
    /// Behaviour:
    ///
    /// 1. For each commit: load the current table, apply requirements +
    ///    updates, and stage the new `TableMetadata`. If any apply fails the
    ///    whole batch fails before any I/O is performed.
    /// 2. Each staged metadata JSON is written to the table's storage via
    ///    `FileIO`. **These writes are not transactional** — on failure here,
    ///    earlier staged files are left as orphan blobs (Iceberg orphan-file
    ///    cleanup, if you run it, will collect them).
    /// 3. A single redb write transaction reads every current
    ///    metadata-pointer, compares it against the base used at stage time,
    ///    and on full agreement flips them all to the staged locations. If
    ///    any one pointer has moved since stage (concurrent writer), the
    ///    entire transaction aborts with `CatalogCommitConflicts` and no
    ///    pointers move.
    ///
    /// Returns the new `Table` handles in the same order as the input.
    pub async fn atomic_release(
        &self,
        commits: impl IntoIterator<Item = TableCommit>,
    ) -> Result<Vec<Table>> {
        // Stage phase: load tables, apply commits in memory, capture old/new
        // metadata locations.
        struct Staged {
            ident: iceberg::TableIdent,
            base_metadata_location: String,
            staged_metadata_location: String,
            staged_table: Table,
        }

        let mut staged: Vec<Staged> = Vec::new();
        for commit in commits {
            let ident = commit.identifier().clone();
            let current = self.load_table(&ident).await?;
            let base = current.metadata_location_result()?.to_string();
            let table = commit.apply(current)?;
            let new_loc = table.metadata_location_result()?.to_string();
            staged.push(Staged {
                ident,
                base_metadata_location: base,
                staged_metadata_location: new_loc,
                staged_table: table,
            });
        }

        // Write phase: persist staged metadata blobs. Done outside the redb
        // transaction so we don't hold the write lock during network I/O.
        for s in &staged {
            s.staged_table
                .metadata()
                .write_to(s.staged_table.file_io(), &s.staged_metadata_location)
                .await?;
            crate::heal::fsync_local_metadata(&s.staged_metadata_location);
        }

        // Commit phase: swap all pointers atomically with optimistic checks.
        {
            let db = self.store.db.lock().await;
            let mut write = db.begin_write().map_err(map_redb)?;
            write.set_durability(self.store.durability);
            {
                let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
                for s in &staged {
                    let key = table_key(&self.name, &s.ident);
                    let current = tables_tbl
                        .get(key.as_str())
                        .map_err(map_redb)?
                        .map(|v| v.value().to_string());
                    match current {
                        Some(loc) if loc == s.base_metadata_location => {}
                        Some(_) => {
                            crate::testmatrix::functional_status(
                                "skade.commit",
                                "atomic_release",
                                false,
                                &format!("conflict on {} ({} tables)", s.ident, staged.len()),
                            );
                            return Err(Error::new(
                                ErrorKind::CatalogCommitConflicts,
                                format!("Commit conflicted for table {} in atomic batch", s.ident),
                            )
                            .with_retryable(true));
                        }
                        None => {
                            crate::testmatrix::functional_status(
                                "skade.commit",
                                "atomic_release",
                                false,
                                &format!("table {} disappeared", s.ident),
                            );
                            return Err(Error::new(
                                ErrorKind::TableNotFound,
                                format!("Table {} disappeared during atomic batch", s.ident),
                            ));
                        }
                    }
                }
                for s in &staged {
                    let key = table_key(&self.name, &s.ident);
                    tables_tbl
                        .insert(key.as_str(), s.staged_metadata_location.as_str())
                        .map_err(map_redb)?;
                }
            }
            // Append every advanced table to the immutable commit log (same txn).
            let mut events = Vec::with_capacity(staged.len());
            for s in &staged {
                let rec = crate::store::record_commit(
                    &write,
                    &table_key(&self.name, &s.ident),
                    s.staged_table.metadata().current_snapshot_id(),
                    &s.staged_metadata_location,
                )
                .map_err(map_redb)?;
                events.push(rec.event);
            }
            write.commit().map_err(map_redb)?;
            // L1 write-through: publish all advanced pointers (under the redb
            // write lock, so the batch is visible to readers all-or-nothing
            // relative to other writers).
            for s in &staged {
                self.store.pointers.insert(
                    &table_key(&self.name, &s.ident),
                    &s.staged_metadata_location,
                );
            }
            // Streaming spine: one CommitEvent per advanced table in the batch.
            for ev in events {
                self.store.publish(ev);
            }
            crate::testmatrix::functional_status(
                "skade.commit",
                "atomic_release",
                true,
                &format!("{} tables flipped in one redb txn", staged.len()),
            );
        }
        self.store.maybe_trigger_compaction();

        Ok(staged.into_iter().map(|s| s.staged_table).collect())
    }

    /// Atomically commit a batch of raw `(ident, requirements, updates)` triples.
    ///
    /// This is the public workaround for iceberg-rust 0.9.1's `pub(crate)` builder
    /// on `TableCommit`: callers that hold requirements and updates as plain vecs
    /// (e.g. received over a REST wire) can drive the same all-or-nothing redb
    /// pointer swap as [`Self::atomic_release`] without constructing a `TableCommit`.
    ///
    /// Semantics are identical to `atomic_release`: every requirement is checked,
    /// updates are folded into a new metadata blob written to storage, and all
    /// catalog pointers are flipped in a single redb transaction. Any conflict or
    /// requirement failure aborts the whole batch.
    pub async fn atomic_release_raw(
        &self,
        commits: impl IntoIterator<
            Item = (
                iceberg::TableIdent,
                Vec<iceberg::TableRequirement>,
                Vec<iceberg::TableUpdate>,
            ),
        >,
    ) -> Result<Vec<Table>> {
        struct Staged {
            ident: iceberg::TableIdent,
            base_metadata_location: String,
            staged_metadata_location: String,
            staged_table: Table,
        }

        let mut staged: Vec<Staged> = Vec::new();
        for (ident, requirements, updates) in commits {
            let current = self.load_table(&ident).await?;
            let base = current.metadata_location_result()?.to_string();

            for req in &requirements {
                req.check(Some(current.metadata()))?;
            }

            let mut meta_builder = current.metadata().clone().into_builder(Some(base.clone()));
            for upd in updates {
                meta_builder = upd.apply(meta_builder)?;
            }
            let new_metadata = meta_builder.build()?.metadata;

            let staged_loc = MetadataLocation::from_str(&base)?
                .with_next_version()
                .to_string();

            let staged_table = Table::builder()
                .file_io(current.file_io().clone())
                .identifier(ident.clone())
                .metadata(new_metadata)
                .metadata_location(staged_loc.clone())
                .build()?;

            staged.push(Staged {
                ident,
                base_metadata_location: base,
                staged_metadata_location: staged_loc,
                staged_table,
            });
        }

        // Write phase: persist metadata blobs outside the redb lock.
        for s in &staged {
            s.staged_table
                .metadata()
                .write_to(s.staged_table.file_io(), &s.staged_metadata_location)
                .await?;
            crate::heal::fsync_local_metadata(&s.staged_metadata_location);
        }

        // Commit phase: optimistic all-or-nothing pointer swap.
        {
            let db = self.store.db.lock().await;
            let mut write = db.begin_write().map_err(map_redb)?;
            write.set_durability(self.store.durability);
            {
                let mut tables_tbl = write.open_table(TABLES).map_err(map_redb)?;
                for s in &staged {
                    let key = table_key(&self.name, &s.ident);
                    let current = tables_tbl
                        .get(key.as_str())
                        .map_err(map_redb)?
                        .map(|v| v.value().to_string());
                    match current {
                        Some(loc) if loc == s.base_metadata_location => {}
                        Some(_) => {
                            crate::testmatrix::functional_status(
                                "skade.commit",
                                "atomic_release_raw",
                                false,
                                &format!("conflict on {} ({} tables)", s.ident, staged.len()),
                            );
                            return Err(Error::new(
                                ErrorKind::CatalogCommitConflicts,
                                format!("Commit conflicted for table {} in atomic batch", s.ident),
                            )
                            .with_retryable(true));
                        }
                        None => {
                            crate::testmatrix::functional_status(
                                "skade.commit",
                                "atomic_release_raw",
                                false,
                                &format!("table {} disappeared", s.ident),
                            );
                            return Err(Error::new(
                                ErrorKind::TableNotFound,
                                format!("Table {} disappeared during atomic batch", s.ident),
                            ));
                        }
                    }
                }
                for s in &staged {
                    let key = table_key(&self.name, &s.ident);
                    tables_tbl
                        .insert(key.as_str(), s.staged_metadata_location.as_str())
                        .map_err(map_redb)?;
                }
            }
            let mut events = Vec::with_capacity(staged.len());
            for s in &staged {
                let rec = crate::store::record_commit(
                    &write,
                    &table_key(&self.name, &s.ident),
                    s.staged_table.metadata().current_snapshot_id(),
                    &s.staged_metadata_location,
                )
                .map_err(map_redb)?;
                events.push(rec.event);
            }
            write.commit().map_err(map_redb)?;
            for s in &staged {
                self.store.pointers.insert(
                    &table_key(&self.name, &s.ident),
                    &s.staged_metadata_location,
                );
            }
            // Streaming spine: one CommitEvent per advanced table in the batch.
            for ev in events {
                self.store.publish(ev);
            }
            crate::testmatrix::functional_status(
                "skade.commit",
                "atomic_release_raw",
                true,
                &format!("{} tables flipped in one redb txn", staged.len()),
            );
        }
        self.store.maybe_trigger_compaction();

        Ok(staged.into_iter().map(|s| s.staged_table).collect())
    }
}
