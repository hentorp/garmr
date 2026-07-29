// Apache-2.0 licensed.

//! Error conversions between `redb` and `iceberg`.

use iceberg::{Error, ErrorKind};

/// Errors that may arise from the redb catalog backend itself.
///
/// Most call sites convert these into [`iceberg::Error`] before returning to
/// trait callers; this type is exposed for users who want richer matching.
#[derive(Debug, thiserror::Error)]
pub enum RedbCatalogError {
    #[error("redb storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("redb transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("redb table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("redb commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("redb database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("json (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<RedbCatalogError> for Error {
    fn from(err: RedbCatalogError) -> Self {
        Error::new(ErrorKind::Unexpected, err.to_string())
    }
}

pub(crate) fn map_redb<E: Into<RedbCatalogError>>(e: E) -> Error {
    let err: RedbCatalogError = e.into();
    Error::from(err)
}
