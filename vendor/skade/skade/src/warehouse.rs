//! [`Warehouse`] — an Iceberg warehouse in one directory: `catalog.redb`
//! (the embedded [`RedbCatalog`]) beside a `warehouse/` data tree, opened with
//! one call. The catalog-from-path constructor znippy asked for.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::Schema as ArrowSchema;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{FormatVersion, PartitionSpec, Transform};
use parquet::basic::Compression;

/// Iceberg table format version skade writes for new tables. **V3** is the
/// newest the spec (and iceberg-rust 0.9.1) supports — it unlocks the v3
/// formats (binary deletion vectors, variant, native geometry/geography,
/// nanosecond timestamps, row lineage, default column values) and is the
/// on-ramp to v4 (Parquet metadata). Our stack (iceberg-rust + iceberg-datafusion)
/// reads V3; manifests are still Avro until v4 lands. See ROADMAP.md.
const NEW_TABLE_FORMAT: FormatVersion = FormatVersion::V3;
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use skade_katalog::{HealOutcome, RedbCatalog, RedbCatalogBuilder};

use crate::bridge::arrow_to_iceberg;
use crate::error::{Result, SkadeError};
use crate::object_store::{ObjectStore, ObjectStoreConfig, ObjectStoreFactory};
use crate::table::Table;

/// Namespace used for table names given without an explicit `ns.` prefix.
pub const DEFAULT_NAMESPACE: &str = "main";

/// An embedded Iceberg warehouse rooted at one local directory:
///
/// ```text
/// <root>/catalog.redb   — the RedbCatalog (namespaces + table pointers, ACID)
/// <root>/warehouse/     — table metadata JSON, Avro manifests, Parquet data
/// ```
///
/// Single-process (redb file lock); drop the `Warehouse` before reopening the
/// same directory. Table names are `"table"` (→ namespace [`DEFAULT_NAMESPACE`])
/// or `"ns.table"` / `"a.b.table"`.
pub struct Warehouse {
    catalog: Arc<RedbCatalog>,
    root: PathBuf,
}

impl Warehouse {
    /// Open (creating if absent) the warehouse at `dir`.
    pub async fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let root = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("warehouse"))?;
        // file:// URIs must be absolute.
        let root = root.canonicalize()?;

        let catalog = RedbCatalogBuilder::default()
            .db_path(root.join("catalog.redb"))
            .warehouse_location(format!("file://{}", root.join("warehouse").display()))
            .with_storage_factory(Arc::new(LocalFsStorageFactory))
            .load("skade", HashMap::new())
            .await?;
        let wh = Warehouse {
            catalog: Arc::new(catalog),
            root,
        };
        wh.ensure_namespace(&NamespaceIdent::new(DEFAULT_NAMESPACE.to_string()))
            .await?;
        Ok(wh)
    }

    /// Open a warehouse whose Iceberg data/metadata blobs live in a pluggable
    /// [`ObjectStore`] (e.g. a shared MinIO), while the redb catalog file stays
    /// on a local disk at `db_path`.
    ///
    /// `warehouse_uri` is the location iceberg stamps into table metadata and
    /// passes back to the store on every read/write (e.g.
    /// `s3://mybucket/warehouse` for an S3 store, or `file:///…` for a local
    /// store). The supplied `store` handles the bytes-IO behind that URI.
    ///
    /// This is the constructor a consumer (Njord) uses to run skade → Iceberg on
    /// a shared MinIO with the S3 SDK of its choice — see
    /// [`crate::object_store`]. [`Warehouse::open`] is unchanged and keeps using
    /// the local filesystem; nothing here affects existing callers.
    pub async fn open_with_store(
        db_path: impl AsRef<Path>,
        warehouse_uri: impl Into<String>,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self> {
        Self::open_with_factory(
            db_path,
            warehouse_uri,
            Arc::new(ObjectStoreFactory::from_store(store)),
        )
        .await
    }

    /// Like [`open_with_store`](Self::open_with_store) but from a serializable
    /// [`ObjectStoreConfig`] (the backend is built lazily, and the config
    /// survives an iceberg metadata round-trip). Use this for S3/MinIO backends
    /// configured from a settings file or env.
    pub async fn open_with_object_store_config(
        db_path: impl AsRef<Path>,
        warehouse_uri: impl Into<String>,
        config: ObjectStoreConfig,
    ) -> Result<Self> {
        Self::open_with_factory(
            db_path,
            warehouse_uri,
            Arc::new(ObjectStoreFactory::from_config(config)),
        )
        .await
    }

    async fn open_with_factory(
        db_path: impl AsRef<Path>,
        warehouse_uri: impl Into<String>,
        factory: Arc<dyn iceberg::io::StorageFactory>,
    ) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let warehouse_uri = warehouse_uri.into();
        let catalog = RedbCatalogBuilder::default()
            .db_path(&db_path)
            .warehouse_location(warehouse_uri)
            .with_storage_factory(factory)
            .load("skade", HashMap::new())
            .await?;
        // The "root" for an object-store warehouse is the catalog file's dir
        // (the only thing on local disk); the data tree lives in the store.
        let root = db_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let wh = Warehouse {
            catalog: Arc::new(catalog),
            root,
        };
        wh.ensure_namespace(&NamespaceIdent::new(DEFAULT_NAMESPACE.to_string()))
            .await?;
        Ok(wh)
    }

    /// The warehouse root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The underlying embedded catalog (an [`iceberg::Catalog`]).
    pub fn catalog(&self) -> Arc<RedbCatalog> {
        self.catalog.clone()
    }

    /// Crash-recovery for a local warehouse: if `name`'s metadata pointer
    /// resolves to a missing/empty/unparseable file (an unclean shutdown left it
    /// un-fsync'd while the durable pointer advanced), roll the pointer back to
    /// the newest fully-loadable metadata in the table's directory. A safe,
    /// pointer-only no-op when the table is healthy, unknown, or object-store
    /// backed — call it at startup before opening the table. See
    /// [`HealOutcome`] for what happened.
    pub async fn heal_table(&self, name: &str) -> Result<HealOutcome> {
        let ident = self.table_ident(name)?;
        Ok(self.catalog.heal_table(&ident).await?)
    }

    /// Parse `"table"` / `"ns.table"` / `"a.b.table"` into a [`TableIdent`].
    pub fn table_ident(&self, name: &str) -> Result<TableIdent> {
        let parts: Vec<&str> = name.split('.').filter(|s| !s.is_empty()).collect();
        match parts.as_slice() {
            [] => Err(SkadeError::Other(format!("invalid table name '{name}'"))),
            [t] => Ok(TableIdent::new(
                NamespaceIdent::new(DEFAULT_NAMESPACE.to_string()),
                (*t).to_string(),
            )),
            [ns @ .., t] => {
                let ns = NamespaceIdent::from_strs(ns.iter().copied())?;
                Ok(TableIdent::new(ns, (*t).to_string()))
            }
        }
    }

    async fn ensure_namespace(&self, ns: &NamespaceIdent) -> Result<()> {
        if !self.catalog.namespace_exists(ns).await? {
            self.catalog.create_namespace(ns, HashMap::new()).await?;
        }
        Ok(())
    }

    /// Create `name` with an Iceberg schema derived from `schema`
    /// (field ids `1..N`, see [`arrow_to_iceberg`]). The namespace is created
    /// if missing.
    pub async fn create_table(&self, name: &str, schema: &ArrowSchema) -> Result<Table> {
        let ident = self.table_ident(name)?;
        self.ensure_namespace(ident.namespace()).await?;
        let creation = TableCreation::builder()
            .name(ident.name().to_string())
            .schema(arrow_to_iceberg(schema)?)
            .format_version(NEW_TABLE_FORMAT)
            .build();
        let inner = self
            .catalog
            .create_table(ident.namespace(), creation)
            .await?;
        Ok(Table::new(self.catalog.clone(), inner))
    }

    /// Like [`create_table`](Self::create_table) but partitioned by
    /// `partition_cols` with **identity** transforms (each must be a string
    /// column present in `schema`). This is what lets [`append`](crate::append)
    /// tag data files with a partition value and what enables partition pruning
    /// on filtered reads. Empty `partition_cols` is equivalent to
    /// [`create_table`](Self::create_table).
    pub async fn create_partitioned_table(
        &self,
        name: &str,
        schema: &ArrowSchema,
        partition_cols: &[&str],
    ) -> Result<Table> {
        let ident = self.table_ident(name)?;
        self.ensure_namespace(ident.namespace()).await?;
        let ice_schema = arrow_to_iceberg(schema)?;
        let creation = if partition_cols.is_empty() {
            TableCreation::builder()
                .name(ident.name().to_string())
                .schema(ice_schema)
                .format_version(NEW_TABLE_FORMAT)
                .build()
        } else {
            let mut b = PartitionSpec::builder(Arc::new(ice_schema.clone()));
            for c in partition_cols {
                b = b.add_partition_field(c, (*c).to_string(), Transform::Identity)?;
            }
            let spec = b.build()?.into_unbound();
            TableCreation::builder()
                .name(ident.name().to_string())
                .schema(ice_schema)
                .partition_spec(spec)
                .format_version(NEW_TABLE_FORMAT)
                .build()
        };
        let inner = self
            .catalog
            .create_table(ident.namespace(), creation)
            .await?;
        // Partition-path marker: identity-partitioned table created (or plain if
        // `partition_cols` was empty).
        crate::functional_status(
            "skade/create_partitioned_table",
            "identity_partition_spec",
            true,
            &format!("{} on [{}]", ident.name(), partition_cols.join(",")),
        );
        Ok(Table::new(self.catalog.clone(), inner))
    }

    /// Load the existing table `name`.
    pub async fn table(&self, name: &str) -> Result<Table> {
        let ident = self.table_ident(name)?;
        let inner = self.catalog.load_table(&ident).await?;
        Ok(Table::new(self.catalog.clone(), inner))
    }

    /// Load `name`, creating it (schema derived from `schema`) if absent.
    pub async fn table_or_create(&self, name: &str, schema: &ArrowSchema) -> Result<Table> {
        let ident = self.table_ident(name)?;
        if self.catalog.table_exists(&ident).await? {
            self.table(name).await
        } else {
            self.create_table(name, schema).await
        }
    }

    /// All table idents in the warehouse (every namespace).
    pub async fn table_idents(&self) -> Result<Vec<TableIdent>> {
        let mut out = Vec::new();
        for ns in self.catalog.list_namespaces(None).await? {
            out.extend(self.catalog.list_tables(&ns).await?);
        }
        Ok(out)
    }

    /// Compact `name` by rebuilding it: stream its current rows into a fresh
    /// table written as a handful of large files, then **atomically swap** that
    /// table into `name` in one redb transaction ([`RedbCatalog::swap_table`]).
    ///
    /// This is the fix for the metadata-growth pathology: iceberg-rust 0.9.1's
    /// only writer is `fast_append`, which appends one manifest per commit and
    /// carries the whole manifest list forward, so under continuous ingest the
    /// snapshot log, manifest list, and tiny-file count grow without bound
    /// (observed: thousands of snapshots, GBs of metadata, OOM). Rebuilding
    /// writes a few large zstd files in **exactly one** commit — the compacted
    /// table has one snapshot regardless of size, so the trigger arithmetic
    /// converges and no separate `expire_snapshots` is needed. Peak memory is
    /// one Parquet row group (rows stream through [`append_stream_props`]); a
    /// large table is never materialised whole. Failure at any point drops the
    /// scratch table and its partial data dir before returning — nothing leaks
    /// to the next restart, and the live table is untouched.
    ///
    /// `prune` (when given) transforms each batch during the rebuild — e.g.
    /// dropping rows already sealed to cold storage, which is the one safe
    /// moment to shrink the hot table (single writer, full rewrite anyway).
    ///
    /// **Concurrency contract:** there must be no concurrent *writer* to `name`
    /// (garmr calls this on its single append actor). The rebuild copies the
    /// snapshot current at entry; an append racing it would be silently lost.
    /// Concurrent *readers* are fine — they hold their own snapshot, and the
    /// swap is gap-free (a reader never sees `name` absent). Unpartitioned
    /// tables only (errors otherwise).
    ///
    /// **Caller obligations after return:** (1) reload any held [`Table`] handle
    /// for `name` — the old handle points at the retired metadata/dir and its
    /// next append would write into the directory you're about to GC; (2) delete
    /// [`CompactReport::old_data_dir`] after a grace window longer than the
    /// longest in-flight query (readers resolved just before the swap keep
    /// streaming the old files).
    pub async fn compact_table(
        &self,
        name: &str,
        prune: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
    ) -> Result<CompactReport> {
        let live_ident = self.table_ident(name)?;

        let old = self.table(name).await?;
        if !old
            .inner()
            .metadata()
            .default_partition_spec()
            .fields()
            .is_empty()
        {
            return Err(SkadeError::other(
                "compact_table: partitioned tables are not supported",
            ));
        }
        let snapshots_before = old.inner().metadata().snapshots().len();
        let old_data_dir = local_path_of(old.inner().metadata().location());
        let schema = old.arrow_schema()?;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stamp = if stamp == 0 {
            static FALLBACK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            u128::from(FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        } else {
            stamp
        };
        let temp_name = match name.rsplit_once('.') {
            Some((ns, t)) => format!("{ns}.{t}__c{stamp}"),
            None => format!("{name}__c{stamp}"),
        };
        let temp_ident = self.table_ident(&temp_name)?;
        let temp = self.create_table(&temp_name, schema.as_ref()).await?;
        let temp_dir = local_path_of(temp.inner().metadata().location());

        let rebuilt = self.rebuild_into(&old, &temp, prune).await;
        let (new_snapshot, rows_in, rows_out) = match rebuilt {
            Ok(v) => v,
            Err(e) => {
                let _ = self.catalog.drop_table(&temp_ident).await;
                if let Some(dir) = temp_dir {
                    let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)).await;
                }
                return Err(e);
            }
        };

        self.catalog
            .swap_table(&live_ident, &temp_ident, new_snapshot)
            .await?;

        Ok(CompactReport {
            snapshots_before,
            rows: rows_out,
            rows_pruned: rows_in - rows_out,
            old_data_dir,
        })
    }

    /// The fallible body of [`compact_table`](Self::compact_table): stream the
    /// old table's current snapshot through `prune` into `temp` as a few large
    /// zstd files with **one** commit (one snapshot), bounding peak memory at a
    /// Parquet row group.
    async fn rebuild_into(
        &self,
        old: &Table,
        temp: &Table,
        prune: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
    ) -> Result<(Option<i64>, u64, u64)> {
        use futures::TryStreamExt;
        let stream = old
            .inner()
            .scan()
            .select_all()
            .build()?
            .to_arrow()
            .await?
            .map_err(SkadeError::from);
        let props = crate::write::WriteProps::new(Compression::ZSTD(Default::default()))
            .row_group_size(128 * 1024);
        let (ice, rows_in, rows_out) = crate::write::append_stream_props(
            &*self.catalog,
            temp.inner(),
            std::pin::pin!(stream),
            prune,
            &props,
        )
        .await?;
        Ok((ice.metadata().current_snapshot_id(), rows_in, rows_out))
    }

    /// Like [`compact_table`](Self::compact_table), but the rebuild writes the
    /// surviving rows **clustered ascending by `index_col`** (via
    /// [`append_sorted_props`](crate::write::append_sorted_props)), so per-file /
    /// per-row-group min/max on that column becomes selective and a range
    /// predicate on it prunes files/row-groups instead of decompressing them.
    /// Additive: the unsorted [`compact_table`](Self::compact_table) is unchanged.
    ///
    /// Same concurrency contract and caller obligations as `compact_table` (no
    /// concurrent writer; reload held handles; GC `old_data_dir` after a grace
    /// window). Unpartitioned tables only. **Memory:** the rebuild materialises
    /// the whole (pruned) table to sort it — see `append_sorted_props`.
    pub async fn compact_table_sorted(
        &self,
        name: &str,
        index_col: &str,
        prune: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
    ) -> Result<CompactReport> {
        let live_ident = self.table_ident(name)?;
        let old = self.table(name).await?;
        if !old
            .inner()
            .metadata()
            .default_partition_spec()
            .fields()
            .is_empty()
        {
            return Err(SkadeError::other(
                "compact_table_sorted: partitioned tables are not supported",
            ));
        }
        let snapshots_before = old.inner().metadata().snapshots().len();
        let old_data_dir = local_path_of(old.inner().metadata().location());
        let schema = old.arrow_schema()?;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stamp = if stamp == 0 {
            static FALLBACK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            u128::from(FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        } else {
            stamp
        };
        let temp_name = match name.rsplit_once('.') {
            Some((ns, t)) => format!("{ns}.{t}__cs{stamp}"),
            None => format!("{name}__cs{stamp}"),
        };
        let temp_ident = self.table_ident(&temp_name)?;
        let temp = self.create_table(&temp_name, schema.as_ref()).await?;
        let temp_dir = local_path_of(temp.inner().metadata().location());

        let rebuilt = self
            .rebuild_into_sorted(&old, &temp, index_col, prune)
            .await;
        let (new_snapshot, rows_in, rows_out) = match rebuilt {
            Ok(v) => v,
            Err(e) => {
                let _ = self.catalog.drop_table(&temp_ident).await;
                if let Some(dir) = temp_dir {
                    let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)).await;
                }
                return Err(e);
            }
        };

        self.catalog
            .swap_table(&live_ident, &temp_ident, new_snapshot)
            .await?;

        Ok(CompactReport {
            snapshots_before,
            rows: rows_out,
            rows_pruned: rows_in - rows_out,
            old_data_dir,
        })
    }

    /// Fallible body of [`compact_table_sorted`](Self::compact_table_sorted):
    /// collect the old snapshot (applying `prune`), then write it clustered by
    /// `index_col` in one commit. `rows_in` counts pre-prune rows so
    /// `CompactReport::rows_pruned` stays correct.
    async fn rebuild_into_sorted(
        &self,
        old: &Table,
        temp: &Table,
        index_col: &str,
        prune: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
    ) -> Result<(Option<i64>, u64, u64)> {
        use futures::TryStreamExt;
        let stream = old
            .inner()
            .scan()
            .select_all()
            .build()?
            .to_arrow()
            .await?
            .map_err(SkadeError::from);
        futures::pin_mut!(stream);
        let mut input: Vec<RecordBatch> = Vec::new();
        let mut rows_in = 0u64;
        while let Some(batch) = stream.try_next().await? {
            rows_in += batch.num_rows() as u64;
            let batch = match prune {
                Some(f) => f(batch)?,
                None => batch,
            };
            if batch.num_rows() > 0 {
                input.push(batch);
            }
        }
        let props = crate::write::WriteProps::new(Compression::ZSTD(Default::default()))
            .row_group_size(128 * 1024);
        let (ice, _rin, rows_out) = crate::write::append_sorted_props(
            &*self.catalog,
            temp.inner(),
            input,
            index_col,
            128 * 1024,
            &props,
        )
        .await?;
        Ok((ice.metadata().current_snapshot_id(), rows_in, rows_out))
    }

    /// Like [`compact_table`](Self::compact_table) but the rebuild is written with
    /// caller-supplied [`WriteProps`](crate::WriteProps) instead of skade's fixed
    /// zstd/128k defaults. Additive: the whole compaction contract (single
    /// snapshot, atomic swap, prune hook, caller reload + GC obligations) is
    /// identical — only the Parquet knobs of the rebuilt files change.
    ///
    /// The lever this exposes is **carrying per-column bloom filters across a
    /// compaction**: a plain [`compact_table`](Self::compact_table) rebuild drops
    /// any bloom the live files had, so a caller that appends with a bloom (via
    /// [`Table::write_props`](crate::Table::write_props)) must compact through this
    /// to keep it. Pass a `props` that keeps the compaction's own compression /
    /// row-group sizing and adds the bloom columns you want preserved.
    pub async fn compact_table_props(
        &self,
        name: &str,
        prune: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
        props: &crate::write::WriteProps,
    ) -> Result<CompactReport> {
        let live_ident = self.table_ident(name)?;

        let old = self.table(name).await?;
        if !old
            .inner()
            .metadata()
            .default_partition_spec()
            .fields()
            .is_empty()
        {
            return Err(SkadeError::other(
                "compact_table_props: partitioned tables are not supported",
            ));
        }
        let snapshots_before = old.inner().metadata().snapshots().len();
        let old_data_dir = local_path_of(old.inner().metadata().location());
        let schema = old.arrow_schema()?;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stamp = if stamp == 0 {
            static FALLBACK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            u128::from(FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        } else {
            stamp
        };
        let temp_name = match name.rsplit_once('.') {
            Some((ns, t)) => format!("{ns}.{t}__c{stamp}"),
            None => format!("{name}__c{stamp}"),
        };
        let temp_ident = self.table_ident(&temp_name)?;
        let temp = self.create_table(&temp_name, schema.as_ref()).await?;
        let temp_dir = local_path_of(temp.inner().metadata().location());

        let rebuilt = self.rebuild_into_props(&old, &temp, prune, props).await;
        let (new_snapshot, rows_in, rows_out) = match rebuilt {
            Ok(v) => v,
            Err(e) => {
                let _ = self.catalog.drop_table(&temp_ident).await;
                if let Some(dir) = temp_dir {
                    let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)).await;
                }
                return Err(e);
            }
        };

        self.catalog
            .swap_table(&live_ident, &temp_ident, new_snapshot)
            .await?;

        Ok(CompactReport {
            snapshots_before,
            rows: rows_out,
            rows_pruned: rows_in - rows_out,
            old_data_dir,
        })
    }

    /// The fallible body of [`compact_table_props`](Self::compact_table_props):
    /// like [`rebuild_into`](Self::rebuild_into) but with caller-supplied
    /// [`WriteProps`](crate::WriteProps).
    async fn rebuild_into_props(
        &self,
        old: &Table,
        temp: &Table,
        prune: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
        props: &crate::write::WriteProps,
    ) -> Result<(Option<i64>, u64, u64)> {
        use futures::TryStreamExt;
        let stream = old
            .inner()
            .scan()
            .select_all()
            .build()?
            .to_arrow()
            .await?
            .map_err(SkadeError::from);
        let (ice, rows_in, rows_out) = crate::write::append_stream_props(
            &*self.catalog,
            temp.inner(),
            std::pin::pin!(stream),
            prune,
            props,
        )
        .await?;
        Ok((ice.metadata().current_snapshot_id(), rows_in, rows_out))
    }

    /// A [`WarehouseLineageSink`](crate::lineage::WarehouseLineageSink) bound to
    /// this warehouse's reserved `lineage_events` table, creating that table with
    /// the reserved schema if it does not exist yet. Attach the returned sink to
    /// a [`Table`] via [`Table::with_lineage_sink`] (feature `lineage`) to
    /// historize every write as a `lineage_events` row.
    pub async fn lineage_sink(&self) -> Result<Arc<crate::lineage::WarehouseLineageSink>> {
        let ident = self.table_ident(crate::lineage::LINEAGE_EVENTS_TABLE)?;
        if !self.catalog.table_exists(&ident).await? {
            self.create_table(
                crate::lineage::LINEAGE_EVENTS_TABLE,
                &crate::lineage::lineage_events_schema(),
            )
            .await?;
        }
        Ok(Arc::new(crate::lineage::WarehouseLineageSink::new(
            self.catalog.clone(),
            ident,
        )))
    }

    /// Atomically commit a batch of raw `(ident, requirements, updates)` triples
    /// (all-or-nothing, one redb txn — see
    /// [`RedbCatalog::atomic_release_raw`](skade_katalog::RedbCatalog)) **and**
    /// emit ONE `Release` lineage event naming every advanced table to `sink`
    /// (the atomic batch is one logical job). Lineage is best-effort: a sink
    /// error never fails the release. Returns the advanced table handles.
    pub async fn atomic_release_with_lineage(
        &self,
        commits: Vec<(
            TableIdent,
            Vec<iceberg::TableRequirement>,
            Vec<iceberg::TableUpdate>,
        )>,
        actor: impl Into<String>,
        sink: &Arc<dyn crate::lineage::LineageSink>,
    ) -> Result<Vec<iceberg::table::Table>> {
        let tables = self.catalog.atomic_release_raw(commits).await?;
        let commit_seq = self.catalog.commit_seq().await.ok();
        let labels: Vec<(String, Option<i64>)> = tables
            .iter()
            .map(|t| {
                let id = t.identifier();
                (
                    format!("{}.{}", id.namespace().to_url_string(), id.name()),
                    t.metadata().current_snapshot().map(|s| s.snapshot_id()),
                )
            })
            .collect();
        crate::lineage::emit_release(sink.as_ref(), actor, &labels, commit_seq).await;
        Ok(tables)
    }
}

/// Report from [`Warehouse::compact_table`].
#[derive(Debug, Clone)]
pub struct CompactReport {
    /// Snapshots `name` had before compaction — the pathology metric.
    pub snapshots_before: usize,
    /// Rows carried into the compacted table.
    pub rows: u64,
    /// Rows the `prune` hook dropped during the rebuild (0 without a hook).
    pub rows_pruned: u64,
    /// Local path of the RETIRED table's data directory, orphaned by the swap.
    /// Safe to delete only after a grace window (in-flight readers may still be
    /// streaming its files). `None` if the location wasn't a local `file://` path.
    pub old_data_dir: Option<PathBuf>,
}

/// Strip a `file://` (or bare-absolute) storage location to a local path.
fn local_path_of(location: &str) -> Option<PathBuf> {
    if let Some(p) = location.strip_prefix("file://") {
        Some(PathBuf::from(p))
    } else if location.starts_with('/') {
        Some(PathBuf::from(location))
    } else {
        None
    }
}

#[cfg(feature = "sql")]
mod sql {
    use super::*;
    use arrow_array::RecordBatch;
    use datafusion::prelude::{SessionConfig, SessionContext};
    use iceberg_datafusion::{IcebergCatalogProvider, IcebergStaticTableProvider};

    impl Warehouse {
        /// A fresh DataFusion session over the warehouse's *current* state.
        ///
        /// Every table is reachable as `skade.<ns>.<table>`; tables in
        /// [`DEFAULT_NAMESPACE`] are additionally registered under their bare
        /// name, so `SELECT … FROM t JOIN u …` works unqualified. The session
        /// snapshots the catalog at creation — build a new one (or call
        /// [`Warehouse::sql`], which does) to see later commits.
        pub async fn session(&self) -> Result<SessionContext> {
            self.session_with(SessionConfig::new()).await
        }

        /// Like [`session`](Self::session) but with a caller-supplied
        /// [`SessionConfig`]. The main use is `with_target_partitions(1)` for a
        /// query that must stream in bounded memory: with the default parallelism
        /// DataFusion inserts a round-robin `RepartitionExec` that reads the scan
        /// ahead of a slow consumer and buffers it unboundedly (an OOM on a large
        /// table); a single partition streams the scan row-group by row-group
        /// under the consumer's backpressure instead.
        pub async fn session_with(&self, config: SessionConfig) -> Result<SessionContext> {
            let ctx = SessionContext::new_with_config(config);
            let provider =
                IcebergCatalogProvider::try_new(self.catalog.clone() as Arc<dyn Catalog>).await?;
            ctx.register_catalog("skade", Arc::new(provider));

            // Register every table (all namespaces) under its bare name so
            // unqualified `SELECT … FROM <table>` resolves. Cross-namespace name
            // collisions are last-wins (rare in an embedded warehouse); use the
            // `skade.<ns>.<table>` catalog path to disambiguate.
            for ns in self.catalog.list_namespaces(None).await? {
                for ident in self.catalog.list_tables(&ns).await? {
                    // A table listed a moment ago can be removed by a concurrent
                    // compaction swap (or a drop) before we load it — skip it
                    // rather than failing the whole session. The query only needs
                    // the tables it actually references; a transiently-absent
                    // scratch table must not 404 an unrelated `SELECT … FROM events`.
                    let table = match self.catalog.load_table(&ident).await {
                        Ok(t) => t,
                        Err(e) if e.kind() == iceberg::ErrorKind::TableNotFound => continue,
                        Err(e) => return Err(e.into()),
                    };
                    let provider = IcebergStaticTableProvider::try_new_from_table(table).await?;
                    ctx.register_table(ident.name(), Arc::new(provider))?;
                }
            }
            Ok(ctx)
        }

        /// Run one SQL statement over the warehouse (any number of tables) and
        /// collect the result batches. Convenience for
        /// `self.session().await?.sql(query).await?.collect()`.
        pub async fn sql(&self, query: &str) -> Result<Vec<RecordBatch>> {
            let ctx = self.session().await?;
            Ok(ctx.sql(query).await?.collect().await?)
        }
    }
}
