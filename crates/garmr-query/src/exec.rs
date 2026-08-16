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
//!
//! **Time is a bound, not a signal.** `filter.time` resolves ONCE to a
//! [`Window`] that every leg then applies in its own idiom — a SQL conjunct, a
//! Tantivy range query, a filter over the semantic backend's hits — so the three
//! legs cannot disagree about which events the analyst asked for. It is
//! deliberately NOT a retrieval signal: a time-only filter does not compile to
//! the fusion gate, because gating "text search over the last 24h" on the newest
//! `candidate_cap` events of that window would silently drop every older hit in
//! it. A time-only query with nothing else to retrieve by is the one exception —
//! then the window's feed IS the answer.

use std::time::Duration;

use garmr_core::{Error, Result};
use garmr_store::Store;

use crate::fuse::{fuse, Row, SemanticSearch};
use crate::ir::HybridQuery;
use crate::result::{HybridResult, SemanticStatus};

const QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Does the structured leg run as a retrieval SIGNAL (and therefore as the
/// fusion gate) for this query?
///
/// It does when the filter selects by something other than time, and when the
/// query has nothing else to retrieve with — a time-only query is the window's
/// feed. It does NOT when a time-only filter accompanies a text or semantic
/// clause: there the window is those legs' bound, and gating them on the newest
/// `candidate_cap` events of the window would drop the older matches inside it.
fn structured_runs(q: &HybridQuery) -> bool {
    q.filter.selects() || (q.text.is_none() && q.semantic.is_none())
}

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
        Self::run_scoped(store, query, sem, None).await
    }

    /// [`Self::run`] with a credential's data scope applied to every leg.
    ///
    /// The scope is threaded ALONGSIDE the query, never merged into
    /// `filter.source`, and that is not a stylistic choice. `structured_runs`
    /// decides whether the structured leg acts as the fusion GATE by asking
    /// whether the filter selects anything; folding the scope into
    /// `filter.source` would make a previously non-selecting filter selective,
    /// promote the structured leg to a gate, and change which rows survive
    /// fusion — a different answer for reasons that have nothing to do with
    /// authorization. Scoping must narrow WHAT a caller may see, never alter
    /// HOW their query is interpreted.
    pub async fn run_scoped(
        store: &Store,
        query: &HybridQuery,
        sem: Option<&dyn SemanticSearch>,
        scope_sources: Option<&[String]>,
    ) -> Result<HybridResult> {
        let mut q = query.clone();
        q.validate().map_err(Error::store)?;
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        // The ONE window every leg bounds itself with (see the module docs).
        let window = q.filter.time.resolve(now_micros);

        // 1. Structured — the gate. Compiled-SELECT-only, re-guarded, time-bounded.
        //    It runs when the filter actually SELECTS something, or when it is
        //    the only dimension the query has (a time-only feed). A time-only
        //    filter alongside a text/semantic clause is a bound for those legs,
        //    not a signal of its own — so no gate, and no [S] provenance
        //    claiming a structured match that was really just "recent".
        let (structured, has_structured) = match structured_runs(&q)
            .then(|| q.filter.compile_sql(q.fusion.candidate_cap, now_micros))
            .flatten()
        {
            Some(sql) => {
                garmr_store::reject_non_readonly(&sql).map_err(Error::store)?;
                // The compiled SELECT is constrained here rather than by editing
                // the filter that produced it, for the reason in the doc above.
                let sql = match scope_sources {
                    None => sql,
                    Some(allowed) => garmr_store::sql_guard::constrain_sources(&sql, allowed)
                        .map_err(Error::store)?,
                };
                let batches = tokio::time::timeout(QUERY_TIMEOUT, store.events.sql(sql))
                    .await
                    .map_err(|_| Error::store("structured query timed out"))??;
                (rows_from_batches(&batches), true)
            }
            None => (Vec::new(), false),
        };

        // 2. Full-text — label filters pushed down for precision (typed terms),
        //    and the window pushed down as a range query. An index built before
        //    `ts_micros` was FAST cannot range-filter and says so (naming
        //    `garmr reindex`) rather than returning unbounded hits the caller
        //    would present as windowed.
        let fulltext: Vec<(Row, f32)> = match &q.text {
            Some(t) => store
                .search
                .search_scoped_in_range(
                    &t.query,
                    &q.filter.host,
                    &q.filter.service,
                    &q.filter.source,
                    &q.filter.severity,
                    &q.filter.log_type,
                    q.fusion.per_signal_k,
                    window.from_us,
                    window.to_us,
                    scope_sources,
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
        //    The backend ranks by meaning alone and knows nothing of the window,
        //    so bounding happens here: fetch wider (`semantic_fetch_k`), drop the
        //    groups the window provably excludes, and keep `per_signal_k` of what
        //    survives — otherwise a windowed query could spend its whole semantic
        //    budget on hits the fuser then discards.
        let (semantic, status) = match (&q.semantic, sem) {
            (Some(s), Some(backend)) => {
                let mut hits = backend.search(&s.query, q.semantic_fetch_k());
                // The data scope is applied BEFORE the window truncation, and
                // before `per_signal_k` is taken, so a confined credential still
                // gets a full budget of hits it may actually read. Filtering
                // after the truncation would let out-of-scope hits consume the
                // budget and silently shrink the answer — the caller would see
                // fewer results and read that as "little matched", when in fact
                // most of what matched was simply not theirs.
                if let Some(allowed) = scope_sources {
                    hits.retain(|h| !h.source.is_empty() && allowed.contains(&h.source));
                }
                if window.is_bounded() {
                    hits.retain(|h| window.may_contain_group(h.ts_micros));
                }
                // Unconditional now that a scope can also thin the list. For an
                // UNBOUNDED query this is a no-op — `semantic_fetch_k` returns
                // exactly `per_signal_k` when there is no window to over-fetch
                // for — so no existing behaviour changes.
                hits.truncate(q.fusion.per_signal_k);
                (hits, SemanticStatus::Used)
            }
            (Some(_), None) => (Vec::new(), SemanticStatus::RequestedButUnavailable),
            (None, _) => (Vec::new(), SemanticStatus::NotRequested),
        };

        tracing::debug!(
            structured = structured.len(),
            fulltext = fulltext.len(),
            semantic = semantic.len(),
            gate = has_structured,
            from_us = window.from_us,
            to_us = window.to_us,
            "hybrid query executed"
        );
        Ok(fuse(
            &structured,
            has_structured,
            &fulltext,
            &semantic,
            status,
            window,
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
    use crate::ir::{SemanticClause, TextClause};
    use std::sync::Arc;

    fn q_with(time_hours: Option<f64>, text: bool, host: Option<&str>) -> HybridQuery {
        let mut q = HybridQuery {
            text: text.then(|| TextClause {
                query: "failed password".into(),
            }),
            ..Default::default()
        };
        q.filter.time.last_hours = time_hours;
        if let Some(h) = host {
            q.filter.host = vec![h.into()];
        }
        q
    }

    #[test]
    fn a_time_only_filter_bounds_the_text_leg_instead_of_gating_it() {
        // The console's Advanced mode with only the global range set: the text
        // leg must search the whole window, not be gated on its newest rows.
        assert!(!structured_runs(&q_with(Some(24.0), true, None)));
        // A real selector gates as before — that is what a filter is for.
        assert!(structured_runs(&q_with(Some(24.0), true, Some("web01"))));
        // Nothing but a window: the feed IS the answer, so the leg runs.
        assert!(structured_runs(&q_with(Some(24.0), false, None)));
        // A semantic-only clause is also a retrieval dimension of its own.
        let mut sem_only = q_with(Some(24.0), false, None);
        sem_only.semantic = Some(SemanticClause {
            query: "brute force".into(),
        });
        assert!(!structured_runs(&sem_only));
    }

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

    #[test]
    fn a_data_scope_never_changes_which_leg_acts_as_the_fusion_gate() {
        // The regression this guards is subtle and would be easy to introduce by
        // "just adding the scope to filter.source": `structured_runs` decides
        // whether the structured leg is the GATE by asking whether the filter
        // selects anything. A scope folded into the filter would make a
        // text-only query suddenly selective, promote structured to a gate, and
        // change which rows survive fusion — a different answer for reasons
        // that have nothing to do with authorization.
        //
        // So: gate behaviour is a function of the QUERY alone. Threading a scope
        // must leave it untouched.
        let text_only = q_with(None, true, None);
        assert!(
            !structured_runs(&text_only),
            "a text-only query must not run the structured leg as a gate"
        );

        // The same query with a source filter the CALLER chose does promote it —
        // that is the caller's own query semantics, and stays intact.
        let mut caller_filtered = q_with(None, true, None);
        caller_filtered.filter.source = vec!["hr".to_string()];
        assert!(
            structured_runs(&caller_filtered),
            "a caller-supplied source filter is a real structured dimension"
        );

        // And the scope is not reachable from the query at all: `run_scoped`
        // takes it as a separate argument, so there is no path by which it could
        // reach `structured_runs`. If someone later adds a `scope` field to
        // HybridQuery, this assertion is where the design decision gets
        // revisited rather than silently reversed.
        assert!(
            text_only.filter.source.is_empty(),
            "threading a scope must never populate filter.source"
        );
    }
}
