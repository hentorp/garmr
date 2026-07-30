use arrow::record_batch::RecordBatch;

pub trait MapDataSource: Send {
    fn ways(&self) -> anyhow::Result<Vec<RecordBatch>>;

    fn nodes(&self) -> anyhow::Result<Vec<RecordBatch>> {
        Ok(vec![])
    }
}
