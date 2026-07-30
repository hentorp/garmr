// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The async Executor (only under the `store` feature): runs a [`HybridQuery`]
//! against the lakehouse (structured), the Tantivy index (full-text), and an
//! injected [`SemanticSearch`] backend, then fuses them.
//!
//! Every SQL path is triply safe: the compiled string is generated-SELECT-only
//! by construction ([`crate::compile`]), re-checked with
//! `garmr_store::reject_non_readonly` (defense in depth), and run under a query
//! timeout — the same envelope as the agent's `ask`/query tools.

use std::time::Duration;

use garmr_core::{Error, Result};
use garmr_store::Store;

use crate::fuse::{fuse, Row, SemanticSearch};
use crate::ir::HybridQuery;
use crate::result::{HybridResult, SemanticStatus};

const QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs the hybrid Query IR. Stateless — a namespace for [`Executor::run`].
pub struct Executor;

impl Executor {
    /// Validate + clamp the query, then run each requested signal and fuse them.
    /// `sem` is the (optional) semantic backend — `None` means the semantic
    /// clause is honestly reported as unavailable, never silently dropped.
    pub async fn run(
        store: &Store,
        query: &HybridQuery,
        sem: Option<&dyn SemanticSearch>,
    ) -> Result<HybridResult> {
        let mut q = query.clone();
        q.validate().map_err(Error::store)?;
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        // 1. Structured — the gate. Compiled-SELECT-only, re-guarded, time-bounded.
        let (structured, has_structured) =
            match q.filter.compile_sql(q.fusion.candidate_cap, now_micros) {
                Some(sql) => {
                    garmr_store::reject_non_readonly(&sql).map_err(Error::store)?;
                    let batches = tokio::time::timeout(QUERY_TIMEOUT, store.events.sql(sql))
                        .await
                        .map_err(|_| Error::store("structured query timed out"))??;
                    (rows_from_batches(&batches), true)
                }
                None => (Vec::new(), false),
            };

        // 2. Full-text — label filters pushed down for precision (typed terms).
        let fulltext: Vec<(Row, f32)> = match &q.text {
            Some(t) => store
                .search
                .search_filtered(
                    &t.query,
                    &q.filter.host,
                    &q.filter.service,
                    &q.filter.source,
                    &q.filter.severity,
                    &q.filter.log_type,
                    q.fusion.per_signal_k,
                )?
                .into_iter()
                .map(|h| {
                    (
                        Row {
                            ts_micros: h.ts_micros,
                            host: h.host,
                            service: h.service,
                            severity: h.severity,
                            message: h.message,
                        },
                        h.score,
                    )
                })
                .collect(),
            None => Vec::new(),
        };

        // 3. Semantic — via the injected backend; honest about a missing model.
        let (semantic, status) = match (&q.semantic, sem) {
            (Some(s), Some(backend)) => (
                backend.search(&s.query, q.fusion.per_signal_k),
                SemanticStatus::Used,
            ),
            (Some(_), None) => (Vec::new(), SemanticStatus::RequestedButUnavailable),
            (None, _) => (Vec::new(), SemanticStatus::NotRequested),
        };

        tracing::debug!(
            structured = structured.len(),
            fulltext = fulltext.len(),
            semantic = semantic.len(),
            gate = has_structured,
            "hybrid query executed"
        );
        Ok(fuse(
            &structured,
            has_structured,
            &fulltext,
            &semantic,
            status,
            &q.fusion,
        ))
    }
}

/// Extract `Row`s from the `event_ts, host, service, severity, message`
/// projection (see [`crate::compile::PROJECTION`]).
fn rows_from_batches(batches: &[skade::arrow_array::RecordBatch]) -> Vec<Row> {
    use skade::arrow_array::{Array, StringArray, TimestampMicrosecondArray};
    let mut out = Vec::new();
    for b in batches {
        let ts = b
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>();
        let host = b.column(1).as_any().downcast_ref::<StringArray>();
        let svc = b.column(2).as_any().downcast_ref::<StringArray>();
        let sev = b.column(3).as_any().downcast_ref::<StringArray>();
        let msg = b.column(4).as_any().downcast_ref::<StringArray>();
        let (Some(ts), Some(host), Some(svc), Some(sev), Some(msg)) = (ts, host, svc, sev, msg)
        else {
            continue;
        };
        for i in 0..b.num_rows() {
            out.push(Row {
                ts_micros: if ts.is_valid(i) { ts.value(i) } else { 0 },
                host: sval(host, i),
                service: sval(svc, i),
                severity: sval(sev, i),
                message: sval(msg, i),
            });
        }
    }
    out
}

fn sval(a: &skade::arrow_array::StringArray, i: usize) -> String {
    use skade::arrow_array::Array;
    if a.is_valid(i) {
        a.value(i).to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn rows_from_batches_maps_the_projection() {
        use skade::arrow_array::{RecordBatch, StringArray, TimestampMicrosecondArray};
        use skade::arrow_schema::{DataType, Field, Schema, TimeUnit};

        let schema = Arc::new(Schema::new(vec![
            Field::new(
                "event_ts",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                true,
            ),
            Field::new("host", DataType::Utf8, true),
            Field::new("service", DataType::Utf8, true),
            Field::new("severity", DataType::Utf8, true),
            Field::new("message", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(TimestampMicrosecondArray::from(vec![100i64])),
                Arc::new(StringArray::from(vec!["web01"])),
                Arc::new(StringArray::from(vec!["sshd"])),
                Arc::new(StringArray::from(vec!["warning"])),
                Arc::new(StringArray::from(vec!["Failed password for root"])),
            ],
        )
        .unwrap();
        let rows = rows_from_batches(std::slice::from_ref(&batch));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts_micros, 100);
        assert_eq!(rows[0].host, "web01");
        assert_eq!(rows[0].severity, "warning");
        assert_eq!(rows[0].message, "Failed password for root");
    }
}
