//! One error type over the whole stack (iceberg, arrow, parquet, datafusion, io).

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, SkadeError>;

/// Everything that can go wrong writing/reading an Iceberg table.
#[derive(Debug, thiserror::Error)]
pub enum SkadeError {
    #[error("iceberg: {0}")]
    Iceberg(#[from] iceberg::Error),

    #[error("arrow: {0}")]
    Arrow(#[from] arrow_schema::ArrowError),

    #[error("parquet: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),

    #[cfg(feature = "sql")]
    #[error("datafusion: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl SkadeError {
    /// Build an [`SkadeError::Other`] from anything displayable.
    pub fn other(msg: impl std::fmt::Display) -> Self {
        SkadeError::Other(msg.to_string())
    }
}
