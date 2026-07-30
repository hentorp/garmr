// Apache-2.0 licensed.

//! Builder for [`RedbCatalog`].

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use iceberg::io::{FileIOBuilder, StorageFactory};
use iceberg::{CatalogBuilder, Error, ErrorKind, Result};

use crate::catalog::RedbCatalog;
use crate::error::map_redb;
use crate::store::Store;

/// Property key for the redb database file path. May be set either via
/// [`RedbCatalogBuilder::db_path`] or in the `props` map passed to
/// [`iceberg::CatalogBuilder::load`].
pub const REDB_CATALOG_PROP_DB_PATH: &str = "redb.db-path";

/// Property key for the warehouse root URI. May be set either via
/// [`RedbCatalogBuilder::warehouse_location`] or in the `props` map passed to
/// [`iceberg::CatalogBuilder::load`].
pub const REDB_CATALOG_PROP_WAREHOUSE: &str = "warehouse";

/// Property key for the L0 parsed-metadata cache budget, in bytes. May be set
/// via [`RedbCatalogBuilder::metadata_cache_bytes`] or in the `props` map. A
/// value of `0` disables the cache. Defaults to
/// [`crate::DEFAULT_METADATA_CACHE_BYTES`] (128 MiB) when unset.
pub const REDB_CATALOG_PROP_METADATA_CACHE_BYTES: &str = "redb.metadata-cache-bytes";

/// Property key for the built-`Table` handle cache capacity (number of resident
/// handles). May be set via [`RedbCatalogBuilder::table_handle_cache_capacity`]
/// or in the `props` map. A value of `0` disables the cache. Defaults to
/// [`crate::DEFAULT_TABLE_HANDLE_CACHE_CAPACITY`] when unset.
pub const REDB_CATALOG_PROP_TABLE_HANDLE_CACHE_CAPACITY: &str = "redb.table-handle-cache-capacity";

/// Property key for write durability. Values: `immediate` (default, fsync per
/// commit), `eventual`, `none`. May be set via
/// [`RedbCatalogBuilder::durability`] or in the `props` map.
pub const REDB_CATALOG_PROP_DURABILITY: &str = "redb.durability";

/// Durability applied to every catalog-mutation commit. Maps onto redb's
/// durability levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WriteDurability {
    /// fsync on every commit — crash-safe. The default.
    #[default]
    Immediate,
    /// Queued for persistence; persists shortly after `commit` returns. Higher
    /// write throughput, may lose the last few commits on a hard crash (the
    /// database stays internally consistent).
    Eventual,
    /// No fsync — fastest writes, durability is best-effort. Intended for bulk
    /// import / benchmarking. Note: redb only frees pages at higher durability
    /// levels, so exclusive `None` use grows the file.
    None,
}

impl WriteDurability {
    pub(crate) fn to_redb(self) -> redb::Durability {
        match self {
            WriteDurability::Immediate => redb::Durability::Immediate,
            WriteDurability::Eventual => redb::Durability::Eventual,
            WriteDurability::None => redb::Durability::None,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "immediate" => Some(Self::Immediate),
            "eventual" => Some(Self::Eventual),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Builder for [`RedbCatalog`].
#[derive(Debug, Default)]
pub struct RedbCatalogBuilder {
    db_path: Option<PathBuf>,
    warehouse_location: Option<String>,
    storage_factory: Option<Arc<dyn StorageFactory>>,
    metadata_cache_bytes: Option<u64>,
    table_handle_cache_capacity: Option<u64>,
    durability: Option<WriteDurability>,
    props: HashMap<String, String>,
}

impl RedbCatalogBuilder {
    /// Set the redb database file path.
    pub fn db_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.db_path = Some(path.into());
        self
    }

    /// Set the warehouse root URI (e.g. `file:///var/.../warehouse`).
    pub fn warehouse_location(mut self, loc: impl Into<String>) -> Self {
        self.warehouse_location = Some(loc.into());
        self
    }

    /// Set the L0 parsed-metadata cache budget in bytes (e.g. `64 * 1024 * 1024`
    /// for 64 MiB). `0` disables the cache. Defaults to
    /// [`crate::DEFAULT_METADATA_CACHE_BYTES`] (128 MiB) when unset.
    pub fn metadata_cache_bytes(mut self, bytes: u64) -> Self {
        self.metadata_cache_bytes = Some(bytes);
        self
    }

    /// Set the built-`Table` handle cache capacity (number of resident handles).
    /// `0` disables it. Defaults to
    /// [`crate::DEFAULT_TABLE_HANDLE_CACHE_CAPACITY`] when unset. A warm
    /// `load_table` hit then costs an `Arc`-sharing `Table` clone (~100 ns)
    /// instead of rebuilding iceberg's per-`Table` `ObjectCache` (~14 µs).
    pub fn table_handle_cache_capacity(mut self, capacity: u64) -> Self {
        self.table_handle_cache_capacity = Some(capacity);
        self
    }

    /// Set write durability for catalog mutations. Defaults to
    /// [`WriteDurability::Immediate`] (fsync per commit).
    pub fn durability(mut self, durability: WriteDurability) -> Self {
        self.durability = Some(durability);
        self
    }

    /// Bulk-set arbitrary properties. Equivalent to repeated `prop` calls.
    pub fn props(mut self, props: HashMap<String, String>) -> Self {
        for (k, v) in props {
            self.props.insert(k, v);
        }
        self
    }

    /// Set a single property.
    pub fn prop(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.props.insert(key.into(), value.into());
        self
    }
}

impl CatalogBuilder for RedbCatalogBuilder {
    type C = RedbCatalog;

    fn with_storage_factory(mut self, storage_factory: Arc<dyn StorageFactory>) -> Self {
        self.storage_factory = Some(storage_factory);
        self
    }

    fn load(
        mut self,
        name: impl Into<String>,
        props: HashMap<String, String>,
    ) -> impl Future<Output = Result<Self::C>> + Send {
        for (k, v) in props {
            self.props.insert(k, v);
        }
        if let Some(p) = self.props.remove(REDB_CATALOG_PROP_DB_PATH) {
            self.db_path = Some(PathBuf::from(p));
        }
        if let Some(w) = self.props.remove(REDB_CATALOG_PROP_WAREHOUSE) {
            self.warehouse_location = Some(w);
        }
        let cache_bytes_prop = self.props.remove(REDB_CATALOG_PROP_METADATA_CACHE_BYTES);
        let table_cache_prop = self
            .props
            .remove(REDB_CATALOG_PROP_TABLE_HANDLE_CACHE_CAPACITY);
        let durability_prop = self.props.remove(REDB_CATALOG_PROP_DURABILITY);

        let name = name.into();
        let db_path = self.db_path.clone();
        let warehouse_location = self.warehouse_location.clone();
        let storage_factory = self.storage_factory.clone();
        let metadata_cache_bytes = self.metadata_cache_bytes;
        let table_handle_cache_capacity = self.table_handle_cache_capacity;
        let durability = self.durability;

        async move {
            if name.trim().is_empty() {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    "Catalog name cannot be empty",
                ));
            }
            let db_path = db_path.ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    format!(
                        "redb catalog requires `{REDB_CATALOG_PROP_DB_PATH}` to be set, \
                         either via RedbCatalogBuilder::db_path or props"
                    ),
                )
            })?;
            let warehouse_location = warehouse_location.ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    format!(
                        "redb catalog requires `{REDB_CATALOG_PROP_WAREHOUSE}` to be set, \
                         either via RedbCatalogBuilder::warehouse_location or props"
                    ),
                )
            })?;
            let factory = storage_factory.ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "StorageFactory must be provided for RedbCatalog. \
                     Use `with_storage_factory` to configure it.",
                )
            })?;
            // A `props` entry overrides the typed builder field (consistent with
            // db-path / warehouse handling above); otherwise fall back to the
            // field, then the crate default.
            let metadata_cache_bytes = match cache_bytes_prop {
                Some(s) => s.trim().parse::<u64>().map_err(|_| {
                    Error::new(
                        ErrorKind::DataInvalid,
                        format!(
                            "`{REDB_CATALOG_PROP_METADATA_CACHE_BYTES}` must be a non-negative \
                             integer number of bytes, got `{s}`"
                        ),
                    )
                })?,
                None => metadata_cache_bytes.unwrap_or(crate::DEFAULT_METADATA_CACHE_BYTES),
            };

            let table_handle_cache_capacity = match table_cache_prop {
                Some(s) => s.trim().parse::<u64>().map_err(|_| {
                    Error::new(
                        ErrorKind::DataInvalid,
                        format!(
                            "`{REDB_CATALOG_PROP_TABLE_HANDLE_CACHE_CAPACITY}` must be a \
                             non-negative integer, got `{s}`"
                        ),
                    )
                })?,
                None => table_handle_cache_capacity
                    .unwrap_or(crate::DEFAULT_TABLE_HANDLE_CACHE_CAPACITY),
            };

            let durability = match durability_prop {
                Some(s) => WriteDurability::parse(&s).ok_or_else(|| {
                    Error::new(
                        ErrorKind::DataInvalid,
                        format!(
                            "`{REDB_CATALOG_PROP_DURABILITY}` must be one of \
                             immediate|eventual|none, got `{s}`"
                        ),
                    )
                })?,
                None => durability.unwrap_or_default(),
            };

            let fileio = FileIOBuilder::new(factory).build();

            if let Some(parent) = db_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        Error::new(
                            ErrorKind::Unexpected,
                            format!("failed to create catalog dir {}: {e}", parent.display()),
                        )
                    })?;
                }
            }

            let store = Store::open(db_path, durability.to_redb()).map_err(map_redb)?;

            Ok(RedbCatalog {
                name,
                warehouse_location,
                fileio,
                store,
                meta_cache: crate::meta_cache::MetadataCache::new(metadata_cache_bytes),
                table_cache: crate::table_cache::TableHandleCache::new(table_handle_cache_capacity),
            })
        }
    }
}
