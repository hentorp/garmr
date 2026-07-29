// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// LOCAL PATCH (nornir-catalog bench): parallel, per-file partitioned scan.
// Upstream 0.9.1 exposes the whole table as `UnknownPartitioning(1)` and reads
// every file into one flattened stream (`to_arrow()`), so the Parquet decode is
// single-threaded — on a 32-core box ~1 core works and ~31 idle. Here we plan
// the file scan tasks once (async, at construction), expose ONE DataFusion
// partition per file, and `execute(partition)` reads just that file via
// `ArrowReaderBuilder`. DataFusion then decodes the files concurrently across all
// cores. (Drop-in once iceberg-datafusion ships output partitioning upstream.)

use std::pin::Pin;
use std::sync::Arc;
use std::vec;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::SchemaRef as ArrowSchemaRef;
use datafusion::error::Result as DFResult;
use datafusion::execution::{SendableRecordBatchStream, TaskContext};
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{DisplayAs, ExecutionPlan, Partitioning, PlanProperties};
use datafusion::prelude::Expr;
use futures::{Stream, TryStreamExt};
use iceberg::arrow::ArrowReaderBuilder;
use iceberg::expr::Predicate;
use iceberg::io::FileIO;
use iceberg::scan::{FileScanTask, FileScanTaskStream};
use iceberg::table::Table;

use super::expr_to_predicate::convert_filters_to_predicate;
use crate::to_datafusion_error;

/// Manages the scanning process of an Iceberg [`Table`], encapsulating the
/// necessary details and computed properties required for execution planning.
#[derive(Debug)]
pub struct IcebergTableScan {
    /// A table in the catalog.
    table: Table,
    /// Snapshot of the table to scan.
    snapshot_id: Option<i64>,
    /// `FileIO` to read the data files (one per partition).
    file_io: FileIO,
    /// The planned file scan tasks — one DataFusion partition reads each.
    tasks: Vec<FileScanTask>,
    /// Stores certain, often expensive to compute,
    /// plan properties used in query optimization.
    plan_properties: Arc<PlanProperties>,
    /// Projection column names, None means all columns
    projection: Option<Vec<String>>,
    /// Filters to apply to the table scan
    predicates: Option<Predicate>,
    /// Optional limit on the number of rows to return
    limit: Option<usize>,
}

impl IcebergTableScan {
    /// Creates a new [`IcebergTableScan`] object. Plans the file scan tasks up
    /// front (async) so the scan can expose one partition per file.
    pub(crate) async fn new(
        table: Table,
        snapshot_id: Option<i64>,
        schema: ArrowSchemaRef,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DFResult<Self> {
        let output_schema = match projection {
            None => schema.clone(),
            Some(projection) => Arc::new(schema.project(projection).unwrap()),
        };
        let projection = get_column_names(schema.clone(), projection);
        let predicates = convert_filters_to_predicate(filters);
        let file_io = table.file_io().clone();

        // Plan the file scan tasks once (same build steps as the upstream
        // single-stream path, just collected so we can split them per partition).
        let scan_builder = match snapshot_id {
            Some(snapshot_id) => table.scan().snapshot_id(snapshot_id),
            None => table.scan(),
        };
        let mut scan_builder = match &projection {
            Some(column_names) => scan_builder.select(column_names.clone()),
            None => scan_builder.select_all(),
        };
        if let Some(pred) = &predicates {
            scan_builder = scan_builder.with_filter(pred.clone());
        }
        let table_scan = scan_builder.build().map_err(to_datafusion_error)?;
        let tasks: Vec<FileScanTask> = table_scan
            .plan_files()
            .await
            .map_err(to_datafusion_error)?
            .try_collect()
            .await
            .map_err(to_datafusion_error)?;

        let partitions = tasks.len().max(1);
        let plan_properties = Arc::new(Self::compute_properties(output_schema, partitions));

        Ok(Self {
            table,
            snapshot_id,
            file_io,
            tasks,
            plan_properties,
            projection,
            predicates,
            limit,
        })
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    pub fn snapshot_id(&self) -> Option<i64> {
        self.snapshot_id
    }

    pub fn projection(&self) -> Option<&[String]> {
        self.projection.as_deref()
    }

    pub fn predicates(&self) -> Option<&Predicate> {
        self.predicates.as_ref()
    }

    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Computes [`PlanProperties`]. `partitions` = number of file scan tasks, so
    /// DataFusion runs one decode track per file across all cores.
    fn compute_properties(schema: ArrowSchemaRef, partitions: usize) -> PlanProperties {
        PlanProperties::new(
            EquivalenceProperties::new(schema),
            Partitioning::UnknownPartitioning(partitions),
            EmissionType::Incremental,
            Boundedness::Bounded,
        )
    }
}

impl ExecutionPlan for IcebergTableScan {
    fn name(&self) -> &str {
        "IcebergTableScan"
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan + 'static>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DFResult<Arc<dyn ExecutionPlan>> {
        Ok(self)
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.plan_properties
    }

    fn execute(
        &self,
        partition: usize,
        _context: Arc<TaskContext>,
    ) -> DFResult<SendableRecordBatchStream> {
        // Each partition decodes exactly one file scan task (independent work,
        // so DataFusion fans these out across cores). A partition with no task
        // (only when the table is empty and we reported 1) yields nothing.
        let stream: Pin<Box<dyn Stream<Item = DFResult<RecordBatch>> + Send>> =
            match self.tasks.get(partition).cloned() {
                Some(task) => {
                    let tasks: FileScanTaskStream = Box::pin(futures::stream::iter(vec![Ok(task)]));
                    let batches = ArrowReaderBuilder::new(self.file_io.clone())
                        .build()
                        .read(tasks)
                        .map_err(to_datafusion_error)?
                        .map_err(to_datafusion_error);
                    Box::pin(batches)
                }
                None => Box::pin(futures::stream::empty()),
            };

        // Per-partition limit: a soft cap (a GlobalLimitExec above enforces the
        // exact total), kept as the upstream optimization.
        let limited_stream: Pin<Box<dyn Stream<Item = DFResult<RecordBatch>> + Send>> =
            if let Some(limit) = self.limit {
                let mut remaining = limit;
                Box::pin(stream.try_filter_map(move |batch| {
                    futures::future::ready(if remaining == 0 {
                        Ok(None)
                    } else if batch.num_rows() <= remaining {
                        remaining -= batch.num_rows();
                        Ok(Some(batch))
                    } else {
                        let limited_batch = batch.slice(0, remaining);
                        remaining = 0;
                        Ok(Some(limited_batch))
                    })
                }))
            } else {
                stream
            };

        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            limited_stream,
        )))
    }
}

impl DisplayAs for IcebergTableScan {
    fn fmt_as(
        &self,
        _t: datafusion::physical_plan::DisplayFormatType,
        f: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
        write!(
            f,
            "IcebergTableScan projection:[{}] predicate:[{}] partitions:[{}]",
            self.projection
                .clone()
                .map_or(String::new(), |v| v.join(",")),
            self.predicates
                .clone()
                .map_or(String::from(""), |p| format!("{p}")),
            self.tasks.len()
        )
    }
}

fn get_column_names(
    schema: ArrowSchemaRef,
    projection: Option<&Vec<usize>>,
) -> Option<Vec<String>> {
    projection.map(|v| {
        v.iter()
            .map(|p| schema.field(*p).name().clone())
            .collect::<Vec<String>>()
    })
}
