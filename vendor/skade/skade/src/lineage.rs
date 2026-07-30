//! Lineage emission — the event model + sink trait for "who did what, to which
//! tables, between which systems, when".
//!
//! A skade write is a lineage fact: an [`actor`](LineageEvent::actor) ran an
//! [`Operation`] that consumed zero or more [`inputs`](LineageEvent::inputs)
//! (upstream datasets) and produced one [`output`](LineageEvent::output) (a
//! table at its new snapshot), at a [`timestamp`](LineageEvent::ts_micros),
//! optionally crossing from a source [`SystemRef`] to a target one. This module
//! defines that model plus a [`LineageSink`] so an emitter can land events
//! anywhere — an in-memory [`CapturingSink`], a historized `lineage_events`
//! Iceberg table, or an OpenLineage HTTP endpoint.
//!
//! The TYPES here are always compiled (they only use `serde` + `async-trait`,
//! both already deps). The *automatic* emit hook inside [`crate::Table::append`]
//! is gated behind the crate's **`lineage`** feature (default off) — see
//! [`crate::Table::with_lineage_sink`]. Emitting is decoupled from the write:
//! events ride a sink, never the commit path, so lineage can never fail a write.
//!
//! Shapes deliberately echo what already exists in the ecosystem so a viewer can
//! fuse them: the [`Operation`] set mirrors skade snapshot operations and knut
//! `_change_type`; [`DatasetRef`]/[`SystemRef`] mirror knut-pipelines'
//! `Dataset`/external-read edges (`reads -> target`) so the same lineage DAG
//! renders Spark flows and skade commits side by side.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arrow_array::{Array, ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema as ArrowSchema};
use iceberg::Catalog as _;
use serde::{Deserialize, Serialize};
use skade_katalog::RedbCatalog;

use crate::error::{Result, SkadeError};

/// What a write did, in lineage terms. Mirrors skade's Iceberg snapshot
/// operations (`Append`/`Delete`/`Overwrite`) plus table birth (`Create`) and
/// the higher-level atomic multi-table `Release` (one logical job, many
/// outputs). The string form matches knut-bifrost's `_change_type` vocabulary
/// where it overlaps, so a CDC consumer and a lineage consumer agree on verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// `fast_append` — rows added (the common ingest case).
    Append,
    /// Equality/position delete — rows removed by identity.
    Delete,
    /// Overwrite/replace — rows rewritten in place.
    Overwrite,
    /// Table created (schema registered, no rows yet).
    Create,
    /// Atomic multi-table release — one logical job, several `outputs`.
    Release,
}

/// A reference to an external system on either end of a dataflow edge — the
/// "BETWEEN which systems" axis. `None` on a [`DatasetRef`] means "within this
/// skade warehouse" (no cross-system hop). Examples: a Spark pipeline run, a
/// Kafka topic, a Postgres source, knut's FalkorDB graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRef {
    /// Stable system kind: `"spark"`, `"skade"`, `"kafka"`, `"postgres"`,
    /// `"falkordb"`, … (free-form, conventionally lower-snake).
    pub kind: String,
    /// Instance/namespace within that kind: a Spark app id, a warehouse URI, a
    /// broker cluster, a database name.
    pub instance: String,
}

impl SystemRef {
    /// A `(kind, instance)` system reference.
    pub fn new(kind: impl Into<String>, instance: impl Into<String>) -> Self {
        SystemRef {
            kind: kind.into(),
            instance: instance.into(),
        }
    }
}

/// A dataset reference: a table identity at a specific snapshot (when known),
/// optionally in a foreign system. The viewer renders one node per distinct
/// `(system, table)`; the `snapshot_id` versions the edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetRef {
    /// `"namespace.table"` within the warehouse (or the foreign dataset name).
    pub table: String,
    /// The snapshot id read (input) or produced (output), if any.
    pub snapshot_id: Option<i64>,
    /// The system this dataset lives in. `None` = this skade warehouse.
    pub system: Option<SystemRef>,
}

impl DatasetRef {
    /// A dataset in this skade warehouse (no foreign system).
    pub fn skade(table: impl Into<String>, snapshot_id: Option<i64>) -> Self {
        DatasetRef {
            table: table.into(),
            snapshot_id,
            system: None,
        }
    }

    /// A dataset living in a foreign `system` (a cross-system lineage endpoint).
    pub fn in_system(
        table: impl Into<String>,
        snapshot_id: Option<i64>,
        system: SystemRef,
    ) -> Self {
        DatasetRef {
            table: table.into(),
            snapshot_id,
            system: Some(system),
        }
    }
}

/// One lineage fact: who did what, to which tables, between which systems, when.
///
/// A plain ingest `append` has empty `inputs` and a single skade `output`. A
/// transform hop names its upstream skade/foreign datasets in `inputs`. An
/// atomic multi-table release is one event with `operation = Release` (the
/// viewer fans `output` out per released table, or emits one event per table —
/// the spike keeps one `output`; multi-output is a follow-up).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEvent {
    /// Stable per-event id (process-unique, time-ordered). Lets the
    /// `lineage_events` table dedupe and lets a viewer key edges.
    pub event_id: String,
    /// Identity that performed the write: a user, a service account, a pipeline
    /// run id. `"skade"` when unattributed.
    pub actor: String,
    /// What the write did.
    pub operation: Operation,
    /// Upstream datasets consumed (empty for a plain external ingest/append).
    pub inputs: Vec<DatasetRef>,
    /// The dataset produced (the table + its new snapshot).
    pub output: DatasetRef,
    /// Event time, microseconds since the Unix epoch (post-commit).
    pub ts_micros: i64,
    /// Durable monotonic commit cursor from skade-katalog (`commit_seq`), when
    /// available — ties the lineage edge to the exact catalog commit so the
    /// viewer can order edges and a consumer can replay from a cursor.
    pub commit_seq: Option<u64>,
}

/// Process-local monotonic tiebreaker so two events minted in the same
/// microsecond still get distinct, time-ordered ids.
static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

impl LineageEvent {
    /// Microseconds since the Unix epoch, now. Saturates at 0 before the epoch.
    pub fn now_micros() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0)
    }

    /// Mint a fresh, process-unique, time-ordered event id.
    fn mint_id(ts_micros: i64) -> String {
        let n = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{ts_micros:016x}-{n:08x}")
    }

    /// A plain single-table append: no declared upstreams, no system hop — the
    /// minimal event a write emits when nothing richer is supplied. Actor
    /// defaults to `"skade"`; refine with [`with_actor`](Self::with_actor).
    pub fn append(table: impl Into<String>, snapshot_id: Option<i64>) -> Self {
        let ts = Self::now_micros();
        LineageEvent {
            event_id: Self::mint_id(ts),
            actor: "skade".to_string(),
            operation: Operation::Append,
            inputs: Vec::new(),
            output: DatasetRef::skade(table, snapshot_id),
            ts_micros: ts,
            commit_seq: None,
        }
    }

    /// Build an event with an explicit operation + output (the general form).
    pub fn new(operation: Operation, output: DatasetRef) -> Self {
        let ts = Self::now_micros();
        LineageEvent {
            event_id: Self::mint_id(ts),
            actor: "skade".to_string(),
            operation,
            inputs: Vec::new(),
            output,
            ts_micros: ts,
            commit_seq: None,
        }
    }

    /// Set the actor (who performed the write).
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    /// Add one upstream input dataset (chainable).
    pub fn with_input(mut self, input: DatasetRef) -> Self {
        self.inputs.push(input);
        self
    }

    /// Tie this event to a catalog commit cursor (`commit_seq`).
    pub fn with_commit_seq(mut self, commit_seq: u64) -> Self {
        self.commit_seq = Some(commit_seq);
        self
    }

    /// Mark the output as living in a foreign target system (a cross-system
    /// edge: skade → Spark/Kafka/graph/…).
    pub fn with_target_system(mut self, system: SystemRef) -> Self {
        self.output.system = Some(system);
        self
    }
}

/// A sink that lands lineage events somewhere durable/observable. Implementors:
/// an in-memory [`CapturingSink`] (tests + a viewer's live tail), a
/// `lineage_events` Iceberg-table appender (historized like the rest of the
/// warehouse), an OpenLineage `RunEvent` HTTP poster.
///
/// `emit` is `async` and returns a [`Result`](crate::error::Result); a caller on
/// the write path should *ignore* a sink error (lineage is best-effort and must
/// never fail a commit) — the emit hook does exactly that.
#[async_trait::async_trait]
pub trait LineageSink: Send + Sync {
    /// Land one lineage event.
    async fn emit(&self, event: &LineageEvent) -> crate::error::Result<()>;
}

/// An in-memory [`LineageSink`] that captures events into a shared `Vec` — for
/// tests and for a viewer that polls the live tail. Cheap to clone (the buffer
/// is a shared `Arc<Mutex<…>>`), so a writer and a reader can hold their own
/// handles to the same buffer.
#[derive(Debug, Default, Clone)]
pub struct CapturingSink {
    events: Arc<std::sync::Mutex<Vec<LineageEvent>>>,
}

impl CapturingSink {
    /// A fresh, empty capturing sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot copy of the events captured so far (oldest-first).
    pub fn events(&self) -> Vec<LineageEvent> {
        self.events.lock().unwrap().clone()
    }

    /// How many events have been captured.
    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Whether no events have been captured yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl LineageSink for CapturingSink {
    async fn emit(&self, event: &LineageEvent) -> crate::error::Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

impl Operation {
    /// The stable lowercase string form (matches the serde `snake_case`
    /// representation and the `lineage_events.operation` column).
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Append => "append",
            Operation::Delete => "delete",
            Operation::Overwrite => "overwrite",
            Operation::Create => "create",
            Operation::Release => "release",
        }
    }

    /// Parse the string form back into an [`Operation`].
    pub fn parse(s: &str) -> Option<Operation> {
        match s {
            "append" => Some(Operation::Append),
            "delete" => Some(Operation::Delete),
            "overwrite" => Some(Operation::Overwrite),
            "create" => Some(Operation::Create),
            "release" => Some(Operation::Release),
            _ => None,
        }
    }
}

/// The reserved lineage table's name (in the default namespace). skade writes
/// its own lineage into this table, and a Spark/SDP run can write the same
/// table — the fusion point the viewer reads.
pub const LINEAGE_EVENTS_TABLE: &str = "lineage_events";

/// The reserved `lineage_events` Iceberg/Arrow schema (design §4.3): one row per
/// [`LineageEvent`]. The repeated-`inputs` list is flattened to a single
/// first-input pair (`input_table`/`input_snapshot`) in this row form; the full
/// event is still recoverable from a `CapturingSink`/JSON for multi-input hops.
pub fn lineage_events_schema() -> ArrowSchema {
    ArrowSchema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("actor", DataType::Utf8, false),
        Field::new("operation", DataType::Utf8, false),
        Field::new("input_table", DataType::Utf8, true),
        Field::new("input_snapshot", DataType::Int64, true),
        Field::new("output_table", DataType::Utf8, false),
        Field::new("output_snapshot", DataType::Int64, true),
        Field::new("source_system", DataType::Utf8, true),
        Field::new("source_instance", DataType::Utf8, true),
        Field::new("target_system", DataType::Utf8, true),
        Field::new("target_instance", DataType::Utf8, true),
        Field::new("ts_micros", DataType::Int64, false),
        Field::new("commit_seq", DataType::Int64, true),
    ])
}

impl LineageEvent {
    /// Encode this event as a single-row [`RecordBatch`] with the reserved
    /// [`lineage_events_schema`] — the on-disk row form a `WarehouseLineageSink`
    /// appends.
    pub fn to_arrow_row(&self) -> Result<RecordBatch> {
        let (in_table, in_snap, src_sys, src_inst) = match self.inputs.first() {
            Some(d) => (
                Some(d.table.clone()),
                d.snapshot_id,
                d.system.as_ref().map(|s| s.kind.clone()),
                d.system.as_ref().map(|s| s.instance.clone()),
            ),
            None => (None, None, None, None),
        };
        let (tgt_sys, tgt_inst) = match &self.output.system {
            Some(s) => (Some(s.kind.clone()), Some(s.instance.clone())),
            None => (None, None),
        };
        let cols: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from_iter_values([self.event_id.clone()])),
            Arc::new(StringArray::from_iter_values([self.actor.clone()])),
            Arc::new(StringArray::from_iter_values([self.operation.as_str()])),
            Arc::new(StringArray::from_iter([in_table])),
            Arc::new(Int64Array::from(vec![in_snap])),
            Arc::new(StringArray::from_iter_values([self.output.table.clone()])),
            Arc::new(Int64Array::from(vec![self.output.snapshot_id])),
            Arc::new(StringArray::from_iter([src_sys])),
            Arc::new(StringArray::from_iter([src_inst])),
            Arc::new(StringArray::from_iter([tgt_sys])),
            Arc::new(StringArray::from_iter([tgt_inst])),
            Arc::new(Int64Array::from(vec![self.ts_micros])),
            Arc::new(Int64Array::from(vec![self.commit_seq.map(|c| c as i64)])),
        ];
        Ok(RecordBatch::try_new(
            Arc::new(lineage_events_schema()),
            cols,
        )?)
    }

    /// Decode row `row` of a [`lineage_events_schema`] batch back into a
    /// [`LineageEvent`] (the inverse of [`to_arrow_row`](Self::to_arrow_row) for a
    /// single-input event).
    pub fn from_arrow_row(batch: &RecordBatch, row: usize) -> Result<LineageEvent> {
        let sget = |name: &str| -> Option<String> {
            batch
                .column_by_name(name)
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .filter(|a| a.is_valid(row))
                .map(|a| a.value(row).to_string())
        };
        let iget = |name: &str| -> Option<i64> {
            batch
                .column_by_name(name)
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .filter(|a| a.is_valid(row))
                .map(|a| a.value(row))
        };
        let req = |v: Option<String>, name: &str| -> Result<String> {
            v.ok_or_else(|| SkadeError::other(format!("lineage_events.{name} is null/missing")))
        };

        let target = match (sget("target_system"), sget("target_instance")) {
            (Some(k), Some(i)) => Some(SystemRef::new(k, i)),
            _ => None,
        };
        let output = DatasetRef {
            table: req(sget("output_table"), "output_table")?,
            snapshot_id: iget("output_snapshot"),
            system: target,
        };
        let mut inputs = Vec::new();
        if let Some(it) = sget("input_table") {
            let system = match (sget("source_system"), sget("source_instance")) {
                (Some(k), Some(i)) => Some(SystemRef::new(k, i)),
                _ => None,
            };
            inputs.push(DatasetRef {
                table: it,
                snapshot_id: iget("input_snapshot"),
                system,
            });
        }
        let op_s = req(sget("operation"), "operation")?;
        Ok(LineageEvent {
            event_id: req(sget("event_id"), "event_id")?,
            actor: req(sget("actor"), "actor")?,
            operation: Operation::parse(&op_s)
                .ok_or_else(|| SkadeError::other(format!("unknown operation `{op_s}`")))?,
            inputs,
            output,
            ts_micros: iget("ts_micros")
                .ok_or_else(|| SkadeError::other("lineage_events.ts_micros is null"))?,
            commit_seq: iget("commit_seq").map(|v| v as u64),
        })
    }
}

/// A [`LineageSink`] that **historizes** each event as a row in a reserved
/// `lineage_events` Iceberg table (skade writing skade). Because it is a normal
/// table it gets time-travel, `read_changelog`, and the CDC stream for free — the
/// viewer reads it like any other table.
///
/// **Self-reference guard:** a write to `lineage_events` itself is skipped
/// (`output.table` matches the sink's table) so appending a lineage row can never
/// recurse into emitting lineage about that append.
pub struct WarehouseLineageSink {
    catalog: Arc<RedbCatalog>,
    ident: iceberg::TableIdent,
    /// `"ns.table"` label of the lineage table (the self-reference guard key).
    label: String,
}

impl WarehouseLineageSink {
    /// Bind a sink to an existing `lineage_events` table (identified by `ident`)
    /// in `catalog`. Prefer [`crate::Warehouse::lineage_sink`], which also
    /// ensures the table exists with the reserved schema.
    pub fn new(catalog: Arc<RedbCatalog>, ident: iceberg::TableIdent) -> Self {
        let label = format!("{}.{}", ident.namespace().to_url_string(), ident.name());
        WarehouseLineageSink {
            catalog,
            ident,
            label,
        }
    }

    /// Whether `event`'s output is the lineage table itself (guarded to avoid
    /// recursion).
    pub fn is_self_reference(&self, event: &LineageEvent) -> bool {
        event.output.table == self.label || event.output.table == self.ident.name()
    }
}

#[async_trait::async_trait]
impl LineageSink for WarehouseLineageSink {
    async fn emit(&self, event: &LineageEvent) -> Result<()> {
        // Never historize lineage about writes to the lineage table itself.
        if self.is_self_reference(event) {
            return Ok(());
        }
        let row = event.to_arrow_row()?;
        let table = self.catalog.load_table(&self.ident).await?;
        crate::write::append(
            self.catalog.as_ref() as &dyn iceberg::Catalog,
            &table,
            &[row],
        )
        .await?;
        Ok(())
    }
}

/// Emit ONE `Release` lineage event naming all `tables` in an atomic batch (the
/// first table is the `output`, the rest are `inputs` — the whole batch is one
/// logical job). Best-effort: a sink error is swallowed. Used by
/// [`crate::Warehouse::atomic_release_with_lineage`].
pub async fn emit_release(
    sink: &dyn LineageSink,
    actor: impl Into<String>,
    tables: &[(String, Option<i64>)],
    commit_seq: Option<u64>,
) {
    let Some((out_table, out_snap)) = tables.first().cloned() else {
        return;
    };
    let mut ev = LineageEvent::new(Operation::Release, DatasetRef::skade(out_table, out_snap))
        .with_actor(actor);
    for (t, s) in &tables[1..] {
        ev = ev.with_input(DatasetRef::skade(t.clone(), *s));
    }
    if let Some(cs) = commit_seq {
        ev = ev.with_commit_seq(cs);
    }
    let _ = sink.emit(&ev).await;
}

/// A [`LineageSink`] that maps each [`LineageEvent`] to an **OpenLineage**
/// `RunEvent` and POSTs it (JSON) to a configured HTTP endpoint — e.g. a Marquez
/// / OpenLineage collector, so skade commits show up in the same lineage graph
/// as Spark/Airflow runs. Behind the opt-in **`lineage-http`** feature (keeps the
/// HTTP client out of every other build).
///
/// The POST is a blocking [`ureq`] call fenced onto
/// [`tokio::task::spawn_blocking`], so it never stalls the async runtime; like
/// every sink it is best-effort on the write path (a transport error is returned
/// but the emit hook swallows it). See [`HttpLineageSink::run_event`] for the
/// exact mapping — it is public so a caller (or a test) can inspect the RunEvent
/// body without a live POST.
#[cfg(feature = "lineage-http")]
pub struct HttpLineageSink {
    /// The OpenLineage collector endpoint (e.g. `http://localhost:5000/api/v1/lineage`).
    endpoint: String,
    /// The OpenLineage `job.namespace` stamped on every event (default `"skade"`).
    job_namespace: String,
    /// The OpenLineage `producer` URI (who emitted the event).
    producer: String,
}

#[cfg(feature = "lineage-http")]
impl HttpLineageSink {
    /// Default OpenLineage `producer` URI for skade-emitted events.
    pub const DEFAULT_PRODUCER: &'static str = "https://codeberg.org/nordisk/skade";

    /// A sink POSTing OpenLineage `RunEvent`s to `endpoint`. Job namespace
    /// defaults to `"skade"`; override with [`with_job_namespace`](Self::with_job_namespace).
    pub fn new(endpoint: impl Into<String>) -> Self {
        HttpLineageSink {
            endpoint: endpoint.into(),
            job_namespace: "skade".to_string(),
            producer: Self::DEFAULT_PRODUCER.to_string(),
        }
    }

    /// Set the OpenLineage `job.namespace` (builder form).
    pub fn with_job_namespace(mut self, ns: impl Into<String>) -> Self {
        self.job_namespace = ns.into();
        self
    }

    /// Set the OpenLineage `producer` URI (builder form).
    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = producer.into();
        self
    }

    /// The configured collector endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Map a [`LineageEvent`] to an OpenLineage **`RunEvent`** JSON value (the
    /// wire body [`emit`](LineageSink::emit) POSTs). A skade commit is a
    /// completed run, so `eventType` is `COMPLETE`; `run.runId` is a stable UUID
    /// derived from the event id; `job.name` is the actor; `inputs`/`outputs` are
    /// the event's datasets (dataset namespace = the foreign system instance, or
    /// the job namespace for in-warehouse datasets). `commit_seq` rides as a run
    /// facet so a consumer can order/replay by the catalog cursor.
    pub fn run_event(&self, event: &LineageEvent) -> serde_json::Value {
        use serde_json::json;

        let dataset = |d: &DatasetRef| -> serde_json::Value {
            let ns = d
                .system
                .as_ref()
                .map(|s| s.instance.clone())
                .unwrap_or_else(|| self.job_namespace.clone());
            let mut facets = serde_json::Map::new();
            if let Some(sid) = d.snapshot_id {
                facets.insert(
                    "version".to_string(),
                    json!({
                        "_producer": self.producer,
                        "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/DatasetVersionDatasetFacet.json",
                        "datasetVersion": sid.to_string(),
                    }),
                );
            }
            json!({ "namespace": ns, "name": d.table, "facets": facets })
        };

        let inputs: Vec<serde_json::Value> = event.inputs.iter().map(dataset).collect();
        let outputs = vec![dataset(&event.output)];

        let mut run_facets = serde_json::Map::new();
        if let Some(cs) = event.commit_seq {
            run_facets.insert(
                "skade_commit".to_string(),
                json!({
                    "_producer": self.producer,
                    "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/RunFacet.json",
                    "commitSeq": cs,
                }),
            );
        }

        json!({
            "eventType": "COMPLETE",
            "eventTime": rfc3339_from_micros(event.ts_micros),
            "producer": self.producer,
            "schemaURL": "https://openlineage.io/spec/2-0-2/OpenLineage.json#/$defs/RunEvent",
            "run": {
                "runId": run_id_uuid(&event.event_id),
                "facets": run_facets,
            },
            "job": {
                "namespace": self.job_namespace,
                "name": event.actor,
                "facets": {
                    "documentation": {
                        "_producer": self.producer,
                        "_schemaURL": "https://openlineage.io/spec/facets/1-0-0/DocumentationJobFacet.json",
                        "description": format!("skade {} on {}", event.operation.as_str(), event.output.table),
                    }
                },
            },
            "inputs": inputs,
            "outputs": outputs,
        })
    }
}

/// Format epoch-microseconds as an RFC-3339 / ISO-8601 UTC timestamp
/// (`YYYY-MM-DDThh:mm:ss.ffffffZ`) — OpenLineage's `eventTime`. Pure date math
/// (Howard Hinnant's civil-from-days), no time-zone crate.
#[cfg(feature = "lineage-http")]
fn rfc3339_from_micros(us: i64) -> String {
    let (secs, micros) = (us.div_euclid(1_000_000), us.rem_euclid(1_000_000));
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    // days since 1970-01-01 → civil (y, m, d).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{micros:06}Z")
}

/// A stable RFC-4122-shaped UUID string derived from an event id (OpenLineage
/// `run.runId` must be UUID-shaped). Deterministic — the same event id always
/// yields the same run id — via two FNV-1a passes over the id, no `uuid` crate.
#[cfg(feature = "lineage-http")]
fn run_id_uuid(event_id: &str) -> String {
    fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
        let mut h = seed;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        h
    }
    let hi = fnv1a(0xcbf2_9ce4_8422_2325, event_id.as_bytes());
    let lo = fnv1a(hi ^ 0x9e37_79b9_7f4a_7c15, event_id.as_bytes());
    let b = [hi.to_be_bytes(), lo.to_be_bytes()].concat();
    // Stamp version 4 + RFC-4122 variant bits so it is a well-formed UUID.
    let v = b[6] & 0x0f | 0x40;
    let var = b[8] & 0x3f | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        v,
        b[7],
        var,
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

#[cfg(feature = "lineage-http")]
#[async_trait::async_trait]
impl LineageSink for HttpLineageSink {
    async fn emit(&self, event: &LineageEvent) -> Result<()> {
        let body = self.run_event(event);
        let endpoint = self.endpoint.clone();
        // ureq is blocking — fence it onto the blocking pool so the async runtime
        // is never stalled by the network round-trip.
        let res = tokio::task::spawn_blocking(move || {
            ureq::post(&endpoint)
                .set("content-type", "application/json")
                .send_string(&body.to_string())
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| SkadeError::other(format!("lineage http join: {e}")))?;
        res.map_err(|e| SkadeError::other(format!("lineage http POST: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn append_event_captures_actor_op_output_and_input() {
        let sink = CapturingSink::new();
        assert!(sink.is_empty());

        // A transform hop: raw_samples -> (skade) bench_telemetry, by a named
        // pipeline run, with a known commit cursor.
        let ev = LineageEvent::append("main.bench_telemetry", Some(42))
            .with_actor("nornir/bench-run-7")
            .with_input(DatasetRef::skade("main.raw_samples", Some(41)))
            .with_commit_seq(1009);

        // Sink round-trip (the async emit path the feature-gated hook uses).
        sink.emit(&ev).await.expect("emit");

        let got = sink.events();
        assert_eq!(got.len(), 1, "exactly one event captured");
        let e = &got[0];

        // Inject-and-assert real values (no smoke test).
        assert_eq!(e.actor, "nornir/bench-run-7");
        assert_eq!(e.operation, Operation::Append);
        assert_eq!(e.output.table, "main.bench_telemetry");
        assert_eq!(e.output.snapshot_id, Some(42));
        assert!(e.output.system.is_none(), "output is in-warehouse");
        assert_eq!(e.inputs.len(), 1);
        assert_eq!(e.inputs[0].table, "main.raw_samples");
        assert_eq!(e.inputs[0].snapshot_id, Some(41));
        assert_eq!(e.commit_seq, Some(1009));
        assert!(e.ts_micros > 0, "timestamp stamped post-commit");

        // Event ids are process-unique and time-ordered.
        let ev2 = LineageEvent::append("main.bench_telemetry", Some(43));
        assert_ne!(ev.event_id, ev2.event_id, "ids are unique");

        // Cross-system target edge: skade -> a Spark sink.
        let crossed =
            LineageEvent::new(Operation::Release, DatasetRef::skade("main.gold", Some(7)))
                .with_target_system(SystemRef::new("spark", "app-20260630"));
        assert_eq!(crossed.operation, Operation::Release);
        assert_eq!(
            crossed.output.system.as_ref().map(|s| s.kind.as_str()),
            Some("spark"),
        );

        // Serde round-trips (the on-the-wire / lineage_events-row form).
        let json = serde_json::to_string(e).expect("serialize");
        let back: LineageEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, e);
    }

    /// A `LineageEvent` survives the reserved `lineage_events` Arrow row form
    /// round-trip (the historized-table encoding), including the input + system
    /// (source/target) axes and the commit cursor.
    #[test]
    fn lineage_events_schema_roundtrips_event() {
        // A cross-system transform hop with one input, both systems, a cursor.
        let ev = LineageEvent::new(
            Operation::Release,
            DatasetRef::in_system(
                "main.gold",
                Some(77),
                SystemRef::new("spark", "app-20260709"),
            ),
        )
        .with_actor("nornir/release-9")
        .with_input(DatasetRef::in_system(
            "main.silver",
            Some(76),
            SystemRef::new("skade", "wh://lake"),
        ))
        .with_commit_seq(4242);

        // The schema is exactly the 13 reserved columns.
        let schema = lineage_events_schema();
        assert_eq!(schema.fields().len(), 13);
        assert_eq!(schema.field(0).name(), "event_id");

        let row = ev.to_arrow_row().expect("encode row");
        assert_eq!(row.num_rows(), 1);
        assert_eq!(row.schema().as_ref(), &lineage_events_schema());

        let back = LineageEvent::from_arrow_row(&row, 0).expect("decode row");
        assert_eq!(back, ev, "the Arrow row round-trips the event exactly");

        // Spot-check a couple of columns landed in the right place.
        assert_eq!(back.operation, Operation::Release);
        assert_eq!(back.output.table, "main.gold");
        assert_eq!(back.output.system.as_ref().unwrap().kind, "spark");
        assert_eq!(back.inputs[0].table, "main.silver");
        assert_eq!(back.inputs[0].system.as_ref().unwrap().kind, "skade");
        assert_eq!(back.commit_seq, Some(4242));
    }
}
