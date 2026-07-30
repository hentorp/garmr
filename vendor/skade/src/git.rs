// Apache-2.0 licensed.

//! Git-like refs over Iceberg: **branches, tags, WAP publish, rollback**.
//!
//! Every Iceberg table's metadata carries a `refs` map — movable **branches**
//! and immutable **tags**, each pointing at a snapshot with a retention policy.
//! iceberg-rust models this natively ([`SnapshotReference`] /
//! [`SnapshotRetention`]) but exposes none of the git surface at the catalog
//! level. This module surfaces it, **100% within the Iceberg spec** and fully
//! additive: every mutation is expressed as a standard
//! [`TableUpdate::SetSnapshotRef`] / [`TableUpdate::RemoveSnapshotRef`] applied
//! through the existing [`RedbCatalog::commit_table`] pointer-advance path
//! (one redb txn / fsync, commit-log append, L0/L1 write-through). Tables stay
//! pure Iceberg — any reader works at a given ref.
//!
//! What lands here (table-level git, the "Tier 1" surface):
//!
//! * [`RedbCatalog::create_branch`] / [`RedbCatalog::create_tag`] — mint a
//!   movable branch or immutable tag on a snapshot (defaults to the current
//!   one), rejecting a name that already exists.
//! * [`RedbCatalog::drop_ref`] — delete a branch or tag.
//! * [`RedbCatalog::list_refs`] / [`RedbCatalog::ref_snapshot_id`] — enumerate
//!   refs / resolve one to its snapshot id.
//! * [`RedbCatalog::fast_forward`] — advance a branch to a descendant snapshot
//!   (rejects a non-fast-forward move with a retryable conflict).
//! * [`RedbCatalog::publish_branch`] — the **WAP** publish step: fast-forward a
//!   target branch (e.g. `main`) to the head of an audit branch once its
//!   quality gate has passed.
//! * [`RedbCatalog::rollback_to`] — move `main` back to an ancestor snapshot
//!   (git `reset --hard` to a point in history).
//! * [`RedbCatalog::load_table_for_ref`] / [`RedbCatalog::resolve_metadata_for_ref`]
//!   — read a table **as of** a branch or tag (time-travel by ref name).
//!
//! Every move is guarded by a [`TableRequirement::RefSnapshotIdMatch`]
//! optimistic precondition, so a concurrent writer that moved the ref out from
//! under us aborts the commit (retryable `CatalogCommitConflicts`) rather than
//! clobbering it — the same all-or-nothing discipline the rest of the catalog
//! uses.

use std::sync::Arc;

use iceberg::spec::{MAIN_BRANCH, SnapshotReference, SnapshotRetention, TableMetadata};
use iceberg::table::Table;
use iceberg::{Error, ErrorKind, Result, TableIdent, TableRequirement, TableUpdate};

use crate::catalog::RedbCatalog;

/// Whether a ref is a movable **branch** or an immutable **tag**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// A movable named pointer (git branch). Advanced by commits / fast-forward.
    Branch,
    /// An immutable label on one snapshot (git tag).
    Tag,
}

/// One entry of a table's `refs` map: a branch or tag and the snapshot it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    /// The ref name (e.g. `main`, `audit`, `v1.0`).
    pub name: String,
    /// Branch or tag.
    pub kind: RefKind,
    /// The snapshot the ref currently points at.
    pub snapshot_id: i64,
}

/// Retention policy for a **branch** (git branches never garbage-collect their
/// own head, but Iceberg can expire older snapshots on them). All `None` uses
/// the table-property defaults. Mirrors the fields of
/// [`SnapshotRetention::Branch`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BranchRetention {
    /// Minimum number of snapshots to keep on the branch while expiring.
    pub min_snapshots_to_keep: Option<i32>,
    /// Max age (ms) of snapshots to keep when expiring.
    pub max_snapshot_age_ms: Option<i64>,
    /// Max age (ms) of the ref itself to keep while expiring (never for `main`).
    pub max_ref_age_ms: Option<i64>,
}

impl From<BranchRetention> for SnapshotRetention {
    fn from(b: BranchRetention) -> Self {
        SnapshotRetention::Branch {
            min_snapshots_to_keep: b.min_snapshots_to_keep,
            max_snapshot_age_ms: b.max_snapshot_age_ms,
            max_ref_age_ms: b.max_ref_age_ms,
        }
    }
}

fn no_such_ref(ident: &TableIdent, ref_name: &str) -> Error {
    Error::new(
        ErrorKind::TableNotFound,
        format!("No branch or tag `{ref_name}` on table {ident}"),
    )
}

fn no_snapshot(ident: &TableIdent) -> Error {
    Error::new(
        ErrorKind::DataInvalid,
        format!("Table {ident} has no snapshots to reference"),
    )
}

fn unknown_snapshot(ident: &TableIdent, snapshot_id: i64) -> Error {
    Error::new(
        ErrorKind::DataInvalid,
        format!("Snapshot {snapshot_id} does not exist in table {ident}"),
    )
}

/// True iff `descendant` is reachable from `ancestor` by walking
/// `parent_snapshot_id` links — i.e. `ancestor` is on the linear history of
/// `descendant` (or they are the same snapshot). This is the fast-forward test:
/// moving a ref from `ancestor` to `descendant` only fast-forwards when the
/// current head is an ancestor of the target.
fn is_ancestor(metadata: &TableMetadata, ancestor: i64, descendant: i64) -> bool {
    let mut cur = Some(descendant);
    while let Some(id) = cur {
        if id == ancestor {
            return true;
        }
        cur = metadata
            .snapshot_by_id(id)
            .and_then(|s| s.parent_snapshot_id());
    }
    false
}

impl RedbCatalog {
    /// Resolve `snapshot_id` (or the table's current snapshot when `None`),
    /// verifying it exists, against the table's current metadata.
    fn resolve_snapshot(
        metadata: &TableMetadata,
        ident: &TableIdent,
        snapshot_id: Option<i64>,
    ) -> Result<i64> {
        match snapshot_id {
            Some(id) => {
                if metadata.snapshot_by_id(id).is_none() {
                    return Err(unknown_snapshot(ident, id));
                }
                Ok(id)
            }
            None => metadata
                .current_snapshot_id()
                .ok_or_else(|| no_snapshot(ident)),
        }
    }

    /// Create a **branch** `branch` pointing at `snapshot_id` (or the current
    /// snapshot when `None`), with the given retention. Fails
    /// `CatalogCommitConflicts` if the branch already exists (use
    /// [`Self::fast_forward`] to move an existing one). Returns the updated table.
    pub async fn create_branch(
        &self,
        ident: &TableIdent,
        branch: &str,
        snapshot_id: Option<i64>,
        retention: BranchRetention,
    ) -> Result<Table> {
        let metadata = self.resolve_metadata(ident).await?;
        let sid = Self::resolve_snapshot(&metadata, ident, snapshot_id)?;
        let updates = vec![TableUpdate::SetSnapshotRef {
            ref_name: branch.to_string(),
            reference: SnapshotReference::new(sid, retention.into()),
        }];
        let requirements = vec![TableRequirement::RefSnapshotIdMatch {
            r#ref: branch.to_string(),
            snapshot_id: None, // must not already exist
        }];
        self.commit_table(ident.clone(), requirements, updates)
            .await
    }

    /// Create an immutable **tag** `tag` on `snapshot_id` (or the current
    /// snapshot when `None`). `max_ref_age_ms` bounds how long the tag survives
    /// snapshot expiry (`None` = table default). Fails `CatalogCommitConflicts`
    /// if the tag already exists. Returns the updated table.
    pub async fn create_tag(
        &self,
        ident: &TableIdent,
        tag: &str,
        snapshot_id: Option<i64>,
        max_ref_age_ms: Option<i64>,
    ) -> Result<Table> {
        let metadata = self.resolve_metadata(ident).await?;
        let sid = Self::resolve_snapshot(&metadata, ident, snapshot_id)?;
        let updates = vec![TableUpdate::SetSnapshotRef {
            ref_name: tag.to_string(),
            reference: SnapshotReference::new(sid, SnapshotRetention::Tag { max_ref_age_ms }),
        }];
        let requirements = vec![TableRequirement::RefSnapshotIdMatch {
            r#ref: tag.to_string(),
            snapshot_id: None, // must not already exist
        }];
        self.commit_table(ident.clone(), requirements, updates)
            .await
    }

    /// Drop a branch or tag by name. Fails `TableNotFound` if no such ref
    /// exists. Guarded by an optimistic `RefSnapshotIdMatch` so a concurrent
    /// move aborts rather than silently deleting a moved ref. Returns the
    /// updated table.
    pub async fn drop_ref(&self, ident: &TableIdent, ref_name: &str) -> Result<Table> {
        let metadata = self.resolve_metadata(ident).await?;
        let current = metadata
            .snapshot_for_ref(ref_name)
            .map(|s| s.snapshot_id())
            .ok_or_else(|| no_such_ref(ident, ref_name))?;
        let updates = vec![TableUpdate::RemoveSnapshotRef {
            ref_name: ref_name.to_string(),
        }];
        let requirements = vec![TableRequirement::RefSnapshotIdMatch {
            r#ref: ref_name.to_string(),
            snapshot_id: Some(current),
        }];
        self.commit_table(ident.clone(), requirements, updates)
            .await
    }

    /// Enumerate every branch and tag on the table, sorted by name. Reads the
    /// lock-free current metadata (no build).
    pub async fn list_refs(&self, ident: &TableIdent) -> Result<Vec<RefEntry>> {
        let metadata = self.resolve_metadata(ident).await?;
        let mut out: Vec<RefEntry> = metadata
            .refs()
            .iter()
            .map(|(name, r)| RefEntry {
                name: name.clone(),
                kind: if r.is_branch() {
                    RefKind::Branch
                } else {
                    RefKind::Tag
                },
                snapshot_id: r.snapshot_id,
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The snapshot id a branch or tag currently points at, or `None` if the
    /// ref does not exist.
    pub async fn ref_snapshot_id(&self, ident: &TableIdent, ref_name: &str) -> Result<Option<i64>> {
        let metadata = self.resolve_metadata(ident).await?;
        Ok(metadata.snapshot_for_ref(ref_name).map(|s| s.snapshot_id()))
    }

    /// Fast-forward `branch` to `to_snapshot_id`, keeping its retention policy.
    ///
    /// The move is a **true fast-forward**: the branch's current head must be an
    /// ancestor of `to_snapshot_id` (or equal to it, a no-op). A move that would
    /// diverge history is rejected with a retryable `CatalogCommitConflicts`,
    /// exactly as `git push` refuses a non-fast-forward. Fails `TableNotFound`
    /// if the branch does not exist, `DataInvalid` if the target snapshot is
    /// unknown.
    pub async fn fast_forward(
        &self,
        ident: &TableIdent,
        branch: &str,
        to_snapshot_id: i64,
    ) -> Result<Table> {
        let metadata = self.resolve_metadata(ident).await?;
        self.fast_forward_ref(ident, &metadata, branch, to_snapshot_id)
            .await
    }

    /// WAP publish: fast-forward `to_branch` (e.g. `main`) to the head of
    /// `from_branch` (e.g. an `audit` branch that passed its quality gate).
    ///
    /// This is the "publish" half of write-audit-publish: writers land data on
    /// `from_branch`, a validator inspects it, and once it passes the audited
    /// head is fast-forwarded onto the production branch atomically. The move is
    /// a true fast-forward (the production head must be an ancestor of the
    /// audited head), so a `main` that advanced under an audit run refuses to
    /// publish rather than silently rewind. Both branches must exist.
    pub async fn publish_branch(
        &self,
        ident: &TableIdent,
        from_branch: &str,
        to_branch: &str,
    ) -> Result<Table> {
        let metadata = self.resolve_metadata(ident).await?;
        let from_head = metadata
            .snapshot_for_ref(from_branch)
            .map(|s| s.snapshot_id())
            .ok_or_else(|| no_such_ref(ident, from_branch))?;
        self.fast_forward_ref(ident, &metadata, to_branch, from_head)
            .await
    }

    /// Shared fast-forward core: move an **existing** branch `branch` to
    /// `to_snapshot_id`, requiring the current head to be an ancestor of the
    /// target. Preserves the branch's retention. Guarded by `RefSnapshotIdMatch`
    /// on the head we validated.
    async fn fast_forward_ref(
        &self,
        ident: &TableIdent,
        metadata: &TableMetadata,
        branch: &str,
        to_snapshot_id: i64,
    ) -> Result<Table> {
        let reference = metadata
            .refs()
            .get(branch)
            .cloned()
            .ok_or_else(|| no_such_ref(ident, branch))?;
        if !reference.is_branch() {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!("Ref `{branch}` on table {ident} is a tag, not a branch"),
            ));
        }
        if metadata.snapshot_by_id(to_snapshot_id).is_none() {
            return Err(unknown_snapshot(ident, to_snapshot_id));
        }
        let head = reference.snapshot_id;
        if !is_ancestor(metadata, head, to_snapshot_id) {
            return Err(Error::new(
                ErrorKind::CatalogCommitConflicts,
                format!(
                    "Not a fast-forward: branch `{branch}` head {head} is not an ancestor of {to_snapshot_id} on table {ident}"
                ),
            )
            .with_retryable(true));
        }
        let updates = vec![TableUpdate::SetSnapshotRef {
            ref_name: branch.to_string(),
            reference: SnapshotReference::new(to_snapshot_id, reference.retention.clone()),
        }];
        let requirements = vec![TableRequirement::RefSnapshotIdMatch {
            r#ref: branch.to_string(),
            snapshot_id: Some(head),
        }];
        self.commit_table(ident.clone(), requirements, updates)
            .await
    }

    /// Roll `main` back to an **ancestor** snapshot (git `reset --hard`).
    ///
    /// `to_snapshot_id` must be an ancestor of the current `main` head — you can
    /// only rewind along existing history, never to an unrelated snapshot. The
    /// old snapshots are retained in the table (nothing is deleted), so the move
    /// is reversible via [`Self::fast_forward`] back to the newer head. Preserves
    /// `main`'s retention. Fails `DataInvalid` if the target is not an ancestor
    /// of the current head, `TableNotFound` if the table has no `main` branch.
    pub async fn rollback_to(&self, ident: &TableIdent, to_snapshot_id: i64) -> Result<Table> {
        let metadata = self.resolve_metadata(ident).await?;
        let reference = metadata
            .refs()
            .get(MAIN_BRANCH)
            .cloned()
            .ok_or_else(|| no_such_ref(ident, MAIN_BRANCH))?;
        if metadata.snapshot_by_id(to_snapshot_id).is_none() {
            return Err(unknown_snapshot(ident, to_snapshot_id));
        }
        let head = reference.snapshot_id;
        // Rewind only: the target must be an ancestor of the current head.
        if !is_ancestor(&metadata, to_snapshot_id, head) {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "Cannot roll back main to {to_snapshot_id}: it is not an ancestor of the current head {head} on table {ident}"
                ),
            ));
        }
        let updates = vec![TableUpdate::SetSnapshotRef {
            ref_name: MAIN_BRANCH.to_string(),
            reference: SnapshotReference::new(to_snapshot_id, reference.retention.clone()),
        }];
        let requirements = vec![TableRequirement::RefSnapshotIdMatch {
            r#ref: MAIN_BRANCH.to_string(),
            snapshot_id: Some(head),
        }];
        self.commit_table(ident.clone(), requirements, updates)
            .await
    }

    /// Read a table **as of** a branch or tag: resolve the ref to its snapshot
    /// id, then route through the historical time-travel path
    /// ([`Self::load_table_at`]). The snapshot the ref names must be present in
    /// the durable commit log (it is, for any snapshot that was ever a table
    /// head — the common tag-a-release / branch-off-history case). Fails
    /// `TableNotFound` if the ref does not exist.
    pub async fn load_table_for_ref(&self, ident: &TableIdent, ref_name: &str) -> Result<Table> {
        let sid = self
            .ref_snapshot_id(ident, ref_name)
            .await?
            .ok_or_else(|| no_such_ref(ident, ref_name))?;
        self.load_table_at(ident, sid).await
    }

    /// Resolve a table's parsed metadata **as of** a branch or tag, without
    /// building a [`Table`] — the metadata-only ref read (mirrors
    /// [`Self::resolve_metadata_at`] but keyed by ref name).
    pub async fn resolve_metadata_for_ref(
        &self,
        ident: &TableIdent,
        ref_name: &str,
    ) -> Result<Arc<TableMetadata>> {
        let sid = self
            .ref_snapshot_id(ident, ref_name)
            .await?
            .ok_or_else(|| no_such_ref(ident, ref_name))?;
        self.resolve_metadata_at(ident, sid).await
    }
}
