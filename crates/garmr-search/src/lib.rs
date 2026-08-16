// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-search` — a Tantivy full-text index over the event stream.
//!
//! The lakehouse answers SQL (aggregates, trends); this answers the other half
//! of the search experience Splunk/Elastic users expect — Lucene-class
//! free-text search: `failed password`, `host:pve sshd`, phrase and boolean
//! queries over the raw message, ranked by relevance. `message` is tokenised
//! full-text; the labels and extracted fields (`host`, `service`, `src_ip`, …)
//! are exact-match terms you can combine (`host:pve "invalid user"`).
//!
//! Tantivy's `IndexWriter` is a single writer with `&mut commit`, so writes go
//! through a one-owner actor task (index a batch → commit → ack). The
//! `IndexReader` is cheap and shareable; searches reload it so they see the
//! latest commit, including writes made by a separate `garmr serve` process.

use std::collections::HashSet;
use std::path::Path;

use garmr_core::{Error, Event, Result};
use tantivy::collector::TopDocs;
use tantivy::directory::MmapDirectory;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, FAST, STORED, STRING, TEXT};
use tantivy::{doc, DocAddress, Index, IndexReader, IndexSettings, IndexWriter, TantivyDocument};
use tokio::sync::{mpsc, oneshot};

/// One search result, ready to print.
#[derive(Debug, Clone)]
pub struct Hit {
    pub score: f32,
    pub ts_micros: i64,
    pub host: String,
    pub service: String,
    pub severity: String,
    pub message: String,
}

#[derive(Clone)]
struct Fields {
    ts: Field,
    host: Field,
    service: Field,
    source: Field,
    severity: Field,
    log_type: Field,
    src_ip: Field,
    user: Field,
    message: Field,
}

fn build_schema() -> (Schema, Fields) {
    let mut b = Schema::builder();
    // FAST (columnar) so a search can be restricted to an event-time window
    // ([`SearchIndex::search_in_range`]); indexes created before this was FAST
    // still open (see [`SearchIndex::open_index`]) but cannot range-filter
    // until `garmr reindex` rebuilds them.
    let ts = b.add_i64_field("ts_micros", STORED | FAST);
    // Exact-match, retrievable label/field terms (queryable as `host:pve`).
    let host = b.add_text_field("host", STRING | STORED);
    let service = b.add_text_field("service", STRING | STORED);
    let source = b.add_text_field("source", STRING | STORED);
    let severity = b.add_text_field("severity", STRING | STORED);
    let log_type = b.add_text_field("log_type", STRING | STORED);
    let src_ip = b.add_text_field("src_ip", STRING | STORED);
    let user = b.add_text_field("user", STRING | STORED);
    // Tokenised full-text (the default search field), retrievable.
    let message = b.add_text_field("message", TEXT | STORED);
    let schema = b.build();
    let fields = Fields {
        ts,
        host,
        service,
        source,
        severity,
        log_type,
        src_ip,
        user,
        message,
    };
    (schema, fields)
}

enum Cmd {
    /// Index a batch and commit, acking when durable.
    Index(Vec<Event>, oneshot::Sender<Result<()>>),
    /// Delete every document and commit — the first step of a full rebuild from
    /// the warehouse (so re-indexing can't duplicate existing docs).
    Clear(oneshot::Sender<Result<()>>),
    /// Delete every document with `ts_micros < cutoff` and commit — full-text
    /// retention, keeping the index bounded to the hot window.
    PruneBefore(i64, oneshot::Sender<Result<()>>),
    /// Targeted erasure: delete every doc whose `host` label equals the value
    /// (exact term — the labels are untokenized), and commit.
    ///
    /// Deliberately the ONLY predicate the index accepts for erasure. Extracted
    /// fields (src_ip, user) exist here only as message tokens, and a token
    /// query cannot be exact: a phrase over "203.0.113.7" degrades across
    /// tokenization into matching any document sharing a fragment — measured,
    /// not feared: the first draft deleted "10.0.0.5" rows via the shared "0"
    /// token. For those fields the correct operation is a REBUILD from the
    /// already-erased store: the index is derived data, and exact convergence
    /// is `index = f(store)`, not a lossy predicate translation.
    EraseHost(String, oneshot::Sender<Result<()>>),
}

/// A full-text index over events. Always has a read handle; the write handle
/// (`tx`) is present only when opened writable. Tantivy takes an exclusive
/// writer lock, so exactly one process (the `garmr serve` pipeline, or a
/// `garmr replay`) opens it writable; every read-only command (`search`,
/// `cases`, `tail`, `query`) opens reader-only and can run concurrently.
#[derive(Clone)]
pub struct SearchIndex {
    tx: Option<mpsc::Sender<Cmd>>,
    reader: IndexReader,
    index: Index,
    fields: Fields,
    /// Whether the on-disk schema matches [`build_schema`]. False after a
    /// schema evolution until `garmr reindex` rebuilds; see [`open_index`].
    schema_current: bool,
    /// Sources NOT written to the full-text index (see `index`). Empty = all.
    exclude_sources: HashSet<String>,
}

impl SearchIndex {
    fn open_index(dir: &Path) -> Result<(Index, Fields, IndexReader, bool)> {
        std::fs::create_dir_all(dir).map_err(Error::store)?;
        let (schema, _) = build_schema();
        let mmap = MmapDirectory::open(dir).map_err(|e| Error::store(e.to_string()))?;
        // An existing index opens with WHATEVER schema it was created with —
        // never open_or_create's exact-schema check, whose mismatch error would
        // turn a schema evolution into a startup crashloop on every deployment
        // carrying the old index. Instead the handle records `schema_current`,
        // new-schema capabilities degrade with an actionable error (see
        // `search_in_range`), and `garmr reindex` is the migration: it moves an
        // outdated index aside so this create path rebuilds it current.
        // (Neither Index::exists nor Index::open takes the writer lock, so
        // this stays safe for a reader-only open alongside a running writer.)
        let index = if Index::exists(&mmap).map_err(|e| Error::store(e.to_string()))? {
            Index::open(mmap).map_err(|e| Error::store(e.to_string()))?
        } else {
            Index::create(mmap, schema.clone(), IndexSettings::default())
                .map_err(|e| Error::store(e.to_string()))?
        };
        let actual = index.schema();
        let field = |name: &str| {
            actual.get_field(name).map_err(|_| {
                Error::store(format!(
                    "the full-text index has no '{name}' field — run `garmr reindex` (with \
                     `serve` stopped) to rebuild it with the current schema"
                ))
            })
        };
        let fields = Fields {
            ts: field("ts_micros")?,
            host: field("host")?,
            service: field("service")?,
            source: field("source")?,
            severity: field("severity")?,
            log_type: field("log_type")?,
            src_ip: field("src_ip")?,
            user: field("user")?,
            message: field("message")?,
        };
        let schema_current = actual == schema;
        if !schema_current {
            tracing::warn!(
                dir = %dir.display(),
                "full-text index was built with an older schema — time-range filtered search \
                 is unavailable until `garmr reindex` rebuilds it"
            );
        }
        let reader = index.reader().map_err(|e| Error::store(e.to_string()))?;
        Ok((index, fields, reader, schema_current))
    }

    /// Open reader-only (no writer lock). Searches work; `index()` errors.
    pub fn open_reader(dir: &Path) -> Result<Self> {
        let (index, fields, reader, schema_current) = Self::open_index(dir)?;
        Ok(Self {
            tx: None,
            reader,
            index,
            fields,
            schema_current,
            exclude_sources: HashSet::new(),
        })
    }

    /// Open writable: acquires the exclusive writer lock and spawns the writer
    /// actor. Fails if another process already holds the writer.
    pub fn open_writer(dir: &Path) -> Result<Self> {
        let (index, fields, reader, schema_current) = Self::open_index(dir)?;
        let writer: IndexWriter = index
            .writer(50_000_000)
            .map_err(|e| Error::store(e.to_string()))?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(writer_actor(writer, fields.clone(), rx));
        Ok(Self {
            tx: Some(tx),
            reader,
            index,
            fields,
            schema_current,
            exclude_sources: HashSet::new(),
        })
    }

    /// Whether the on-disk index was built with the current schema. False after
    /// a schema evolution (the index still opens and serves unranged searches);
    /// `garmr reindex` rebuilds it current.
    pub fn schema_current(&self) -> bool {
        self.schema_current
    }

    /// Whether this index can restrict a search to an event-time window —
    /// i.e. its `ts_micros` field is FAST (columnar). False only for an index
    /// created before the field became FAST.
    pub fn supports_ts_range(&self) -> bool {
        self.index
            .schema()
            .get_field_entry(self.fields.ts)
            .is_fast()
    }

    /// Builder: set event sources to skip when full-text indexing. Excluded
    /// sources are still persisted and evaluated by detection — they only lose
    /// free-text search. Used to keep a high-volume firehose (kunai) out of the
    /// single-writer indexer so it can't backpressure ingest.
    pub fn with_exclude_sources<I: IntoIterator<Item = String>>(mut self, sources: I) -> Self {
        self.exclude_sources = sources.into_iter().collect();
        self
    }

    /// Index a batch of events and wait until the commit is durable (so a
    /// subsequent search — even in another process — sees them). Errors if the
    /// index was opened reader-only.
    pub async fn index(&self, events: Vec<Event>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        // Drop excluded sources (e.g. the kunai execve firehose) before the
        // single-writer indexer — they are still persisted in the lakehouse and
        // evaluated by detection; this only removes their free-text coverage.
        let events: Vec<Event> = if self.exclude_sources.is_empty() {
            events
        } else {
            events
                .into_iter()
                .filter(|e| !self.exclude_sources.contains(e.source.as_str()))
                .collect()
        };
        if events.is_empty() {
            return Ok(());
        }
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| Error::store("search index opened read-only"))?;
        let (ack, rx) = oneshot::channel();
        tx.send(Cmd::Index(events, ack))
            .await
            .map_err(|_| Error::store("search indexer gone"))?;
        rx.await
            .map_err(|_| Error::store("search indexer dropped ack"))?
    }

    /// Delete every indexed document (durably committed) — the first step of a
    /// full rebuild from the warehouse (`garmr reindex`). Errors if opened
    /// read-only.
    pub async fn clear(&self) -> Result<()> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| Error::store("search index opened read-only"))?;
        let (ack, rx) = oneshot::channel();
        tx.send(Cmd::Clear(ack))
            .await
            .map_err(|_| Error::store("search indexer gone"))?;
        rx.await
            .map_err(|_| Error::store("search indexer dropped ack"))?
    }

    /// Delete every indexed document older than `cutoff_us`, durably committed.
    ///
    /// This is what keeps the full-text index from growing without bound: rows
    /// older than the hot window are sealed into cold archives — reachable via
    /// `cold-query`, deliberately not via free text — so their index entries
    /// are pure growth with no reader. Pruning follows the SEALED boundary
    /// (the retention watermark), never wall-clock age alone, so a document is
    /// only ever dropped once its rows are durably archived.
    ///
    /// Refuses on a pre-upgrade index whose `ts_micros` is not indexed: a range
    /// delete there would silently match nothing, and "pruned" would be a lie
    /// the operator discovers as unbounded disk growth. `garmr reindex` fixes
    /// the schema.
    pub async fn prune_before(&self, cutoff_us: i64) -> Result<()> {
        if !self.supports_ts_range() {
            return Err(Error::store(
                "this full-text index predates ts-range support — run `garmr reindex` \
                 (with `serve` stopped) to rebuild it before pruning can work",
            ));
        }
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| Error::store("search index opened read-only"))?;
        let (ack, rx) = oneshot::channel();
        tx.send(Cmd::PruneBefore(cutoff_us, ack))
            .await
            .map_err(|_| Error::store("search indexer gone"))?;
        rx.await
            .map_err(|_| Error::store("search indexer dropped ack"))?
    }

    /// Erase every document for `host` (exact label term), durably committed.
    /// See [`Cmd::EraseHost`] for why hosts are the only index-side predicate.
    pub async fn erase_host_docs(&self, host: &str) -> Result<()> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| Error::store("search index opened read-only"))?;
        let (ack, rx) = oneshot::channel();
        tx.send(Cmd::EraseHost(host.to_string(), ack))
            .await
            .map_err(|_| Error::store("search indexer gone"))?;
        rx.await
            .map_err(|_| Error::store("search indexer dropped ack"))?
    }

    /// Run a full-text query (Tantivy syntax; bare terms hit `message`) and
    /// return the top `limit` hits by relevance.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        self.search_in_range(query, limit, None, None)
    }

    /// Full-text search restricted to the event-time window `[from_us, to_us)`
    /// (epoch micros; either bound may be open). A bounded search on an index
    /// whose `ts_micros` is not FAST (built before the schema gained it) errors
    /// with the migration instruction rather than silently returning zero or
    /// out-of-window hits — see [`Self::supports_ts_range`].
    pub fn search_in_range(
        &self,
        query: &str,
        limit: usize,
        from_us: Option<i64>,
        to_us: Option<i64>,
    ) -> Result<Vec<Hit>> {
        use tantivy::query::{BooleanQuery, Occur, Query};

        // TopDocs::with_limit(0) panics (asserts limit > 0); clamp so a stray
        // `--limit 0` returns nothing instead of aborting the command.
        let limit = limit.max(1);
        self.reader
            .reload()
            .map_err(|e| Error::store(e.to_string()))?;
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![self.fields.message]);
        let text_q = parser
            .parse_query(query)
            .map_err(|e| Error::store(format!("query: {e}")))?;
        let q: Box<dyn Query> = match self.range_query(from_us, to_us)? {
            None => text_q,
            Some(range) => Box::new(BooleanQuery::new(vec![
                (Occur::Must, text_q),
                (Occur::Must, range),
            ])),
        };
        let top = searcher
            .search(&q, &TopDocs::with_limit(limit).order_by_score())
            .map_err(|e| Error::store(e.to_string()))?;
        self.collect_hits(&searcher, top)
    }

    /// The `[from, to)` event-time clause, or `None` when neither bound is set.
    ///
    /// The ONE place a time bound becomes a query, so every search that takes a
    /// window refuses a pre-upgrade index the same way: a `RangeQuery` on a
    /// non-FAST `ts_micros` would fall back to the (empty) inverted index and
    /// match nothing, so an unservable bound is an error naming the migration —
    /// never zero hits the caller would report as "nothing in that window".
    fn range_query(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
    ) -> Result<Option<Box<dyn tantivy::query::Query>>> {
        use std::ops::Bound;
        use tantivy::query::RangeQuery;
        use tantivy::Term;

        if from_us.is_none() && to_us.is_none() {
            return Ok(None);
        }
        if !self.supports_ts_range() {
            return Err(Error::store(
                "this full-text index predates time-range filtering — run `garmr reindex` \
                 (with `serve` stopped) to rebuild it; searching without a range still works",
            ));
        }
        let term = |v: i64| Term::from_field_i64(self.fields.ts, v);
        Ok(Some(Box::new(RangeQuery::new(
            from_us.map_or(Bound::Unbounded, |v| Bound::Included(term(v))),
            to_us.map_or(Bound::Unbounded, |v| Bound::Excluded(term(v))),
        ))))
    }

    /// Materialize scored doc addresses into [`Hit`]s from the stored fields.
    fn collect_hits(
        &self,
        searcher: &tantivy::Searcher,
        top: Vec<(f32, DocAddress)>,
    ) -> Result<Vec<Hit>> {
        let mut hits = Vec::with_capacity(top.len());
        for (score, addr) in top {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| Error::store(e.to_string()))?;
            let s = |f: Field| {
                doc.get_first(f)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            hits.push(Hit {
                score,
                ts_micros: doc
                    .get_first(self.fields.ts)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                host: s(self.fields.host),
                service: s(self.fields.service),
                severity: s(self.fields.severity),
                message: s(self.fields.message),
            });
        }
        Ok(hits)
    }

    /// Full-text search with typed exact-term LABEL filters pushed down into the
    /// query (Phase 6 hybrid retrieval). The label values are matched as `TermQuery`
    /// on the indexed STRING fields — they are NEVER spliced into the query DSL, so
    /// there is no second injection surface. Each label maps to a fixed internal
    /// field (a compile-time allow-list); OR within a label, AND across labels, AND
    /// the full-text `text`.
    #[allow(clippy::too_many_arguments)]
    pub fn search_filtered(
        &self,
        text: &str,
        host: &[String],
        service: &[String],
        source: &[String],
        severity: &[String],
        log_type: &[String],
        limit: usize,
    ) -> Result<Vec<Hit>> {
        self.search_filtered_in_range(
            text, host, service, source, severity, log_type, limit, None, None,
        )
    }

    /// [`Self::search_filtered`] additionally restricted to the event-time window
    /// `[from_us, to_us)` — the hybrid executor's full-text leg, which bounds
    /// itself with the same window the structured and semantic legs use. Refuses
    /// a bounded search on a pre-upgrade index (see [`Self::range_query`]).
    #[allow(clippy::too_many_arguments)]
    pub fn search_filtered_in_range(
        &self,
        text: &str,
        host: &[String],
        service: &[String],
        source: &[String],
        severity: &[String],
        log_type: &[String],
        limit: usize,
        from_us: Option<i64>,
        to_us: Option<i64>,
    ) -> Result<Vec<Hit>> {
        self.search_scoped_in_range(
            text, host, service, source, severity, log_type, limit, from_us, to_us, None,
        )
    }

    /// [`Self::search_filtered_in_range`] with a credential's data scope applied
    /// as an INDEPENDENT `Must` clause.
    ///
    /// The scope is never merged into the caller's `source` filter, and that
    /// distinction is the whole point. Two separate `Must` clauses mean a
    /// document must satisfy BOTH — the caller's chosen sources AND the ones
    /// their credential may read — so a request cannot widen its own reach.
    /// Merging them would require intersecting in Rust, and an empty
    /// intersection would produce an empty list, which this function reads as
    /// "no filter at all": the most restrictive case would silently become the
    /// most permissive.
    ///
    /// It also closes the query-DSL route. Tantivy's parser accepts `field:value`
    /// syntax, so a caller can write `source:infra` inside the free-text query
    /// itself; that becomes part of the text clause and is ANDed with the scope
    /// clause, yielding nothing rather than another source's rows.
    #[allow(clippy::too_many_arguments)]
    pub fn search_scoped_in_range(
        &self,
        text: &str,
        host: &[String],
        service: &[String],
        source: &[String],
        severity: &[String],
        log_type: &[String],
        limit: usize,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope_sources: Option<&[String]>,
    ) -> Result<Vec<Hit>> {
        use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
        use tantivy::schema::IndexRecordOption;
        use tantivy::Term;

        let limit = limit.max(1);
        self.reader
            .reload()
            .map_err(|e| Error::store(e.to_string()))?;
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![self.fields.message]);
        let text_q = parser
            .parse_query(text)
            .map_err(|e| Error::store(format!("query: {e}")))?;

        let mut clauses: Vec<(Occur, Box<dyn Query>)> = vec![(Occur::Must, text_q)];
        // label -> (fixed field) allow-list; a value can only ever become a
        // TermQuery on ITS column, never an identifier or DSL fragment.
        for (field, vals) in [
            (self.fields.host, host),
            (self.fields.service, service),
            (self.fields.source, source),
            (self.fields.severity, severity),
            (self.fields.log_type, log_type),
        ] {
            if vals.is_empty() {
                continue;
            }
            let ors: Vec<(Occur, Box<dyn Query>)> = vals
                .iter()
                .map(|v| {
                    let tq =
                        TermQuery::new(Term::from_field_text(field, v), IndexRecordOption::Basic);
                    (Occur::Should, Box::new(tq) as Box<dyn Query>)
                })
                .collect();
            clauses.push((Occur::Must, Box::new(BooleanQuery::new(ors))));
        }
        if let Some(range) = self.range_query(from_us, to_us)? {
            clauses.push((Occur::Must, range));
        }
        // The data scope, as its own Must clause. An empty allow-list is NOT
        // "no restriction": it means the credential may read nothing, so it
        // becomes a clause no document can satisfy rather than a skipped filter.
        if let Some(allowed) = scope_sources {
            let ors: Vec<(Occur, Box<dyn Query>)> = allowed
                .iter()
                .map(|v| {
                    let tq = TermQuery::new(
                        Term::from_field_text(self.fields.source, v),
                        IndexRecordOption::Basic,
                    );
                    (Occur::Should, Box::new(tq) as Box<dyn Query>)
                })
                .collect();
            clauses.push((Occur::Must, Box::new(BooleanQuery::new(ors))));
        }

        let q = BooleanQuery::new(clauses);
        let top = searcher
            .search(&q, &TopDocs::with_limit(limit).order_by_score())
            .map_err(|e| Error::store(e.to_string()))?;
        self.collect_hits(&searcher, top)
    }
}

/// Test scaffolding: create `dir` as a full-text index with the LEGACY schema
/// from before `ts_micros` was FAST, holding one sshd document (ts 42_000_000,
/// host "pve", message "Failed password for root"). Upgrade/migration tests —
/// including in crates that don't depend on tantivy directly, via garmr-store's
/// re-export — use this to stage a pre-upgrade index.
#[doc(hidden)]
pub fn create_legacy_index_for_tests(dir: &Path) -> Result<()> {
    let t = |e: tantivy::TantivyError| Error::store(e.to_string());
    std::fs::create_dir_all(dir).map_err(Error::store)?;
    let mut b = Schema::builder();
    let ts = b.add_i64_field("ts_micros", STORED);
    let host = b.add_text_field("host", STRING | STORED);
    let service = b.add_text_field("service", STRING | STORED);
    let source = b.add_text_field("source", STRING | STORED);
    let severity = b.add_text_field("severity", STRING | STORED);
    let log_type = b.add_text_field("log_type", STRING | STORED);
    let _src_ip = b.add_text_field("src_ip", STRING | STORED);
    let _user = b.add_text_field("user", STRING | STORED);
    let message = b.add_text_field("message", TEXT | STORED);
    let index = Index::create_in_dir(dir, b.build()).map_err(t)?;
    let mut w: IndexWriter = index.writer(15_000_000).map_err(t)?;
    w.add_document(doc!(
        ts => 42_000_000i64,
        host => "pve",
        service => "sshd",
        source => "journald",
        severity => "warning",
        log_type => "system",
        message => "Failed password for root",
    ))
    .map_err(t)?;
    w.commit().map_err(t)?;
    Ok(())
}

async fn writer_actor(mut writer: IndexWriter, f: Fields, mut rx: mpsc::Receiver<Cmd>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            Cmd::Index(events, ack) => {
                let r = index_batch(&mut writer, &f, &events);
                let _ = ack.send(r);
            }
            Cmd::Clear(ack) => {
                let r = clear_all(&mut writer);
                let _ = ack.send(r);
            }
            Cmd::PruneBefore(cutoff_us, ack) => {
                let r = prune_before_impl(&mut writer, &f, cutoff_us);
                let _ = ack.send(r);
            }
            Cmd::EraseHost(host, ack) => {
                let r = erase_host_impl(&mut writer, &f, &host);
                let _ = ack.send(r);
            }
        }
    }
}

/// Delete by exact host term + commit, with the same rollback-on-failure
/// discipline as every other write.
fn erase_host_impl(writer: &mut IndexWriter, f: &Fields, host: &str) -> Result<()> {
    let result = (|| {
        writer.delete_term(tantivy::Term::from_field_text(f.host, host));
        writer.commit().map_err(|e| Error::store(e.to_string()))?;
        Ok(())
    })();
    if result.is_err() {
        if let Err(e) = writer.rollback() {
            tracing::error!(error = %e, "search writer rollback failed after erase — full-text indexing degraded");
        }
    }
    result
}

/// Delete every doc with `ts_micros < cutoff_us` + commit, rolling back on
/// failure so a partial delete can't leak into the next commit (the same
/// discipline as `clear_all` / `index_batch`).
fn prune_before_impl(writer: &mut IndexWriter, f: &Fields, cutoff_us: i64) -> Result<()> {
    use tantivy::query::RangeQuery;
    let result = (|| {
        let q = RangeQuery::new(
            std::ops::Bound::Unbounded,
            std::ops::Bound::Excluded(tantivy::Term::from_field_i64(f.ts, cutoff_us)),
        );
        writer
            .delete_query(Box::new(q))
            .map_err(|e| Error::store(e.to_string()))?;
        writer.commit().map_err(|e| Error::store(e.to_string()))?;
        Ok(())
    })();
    if result.is_err() {
        if let Err(e) = writer.rollback() {
            tracing::error!(error = %e, "search writer rollback failed after prune — full-text indexing degraded");
        }
    }
    result
}

/// Delete all documents + commit. On failure, roll back so a partial delete
/// can't leak into the next commit, matching `index_batch`'s discipline.
fn clear_all(writer: &mut IndexWriter) -> Result<()> {
    let result = (|| {
        writer
            .delete_all_documents()
            .map_err(|e| Error::store(e.to_string()))?;
        writer.commit().map_err(|e| Error::store(e.to_string()))?;
        Ok(())
    })();
    if result.is_err() {
        if let Err(e) = writer.rollback() {
            tracing::error!(error = %e, "search writer rollback failed after clear — full-text indexing degraded");
        }
    }
    result
}

fn index_batch(writer: &mut IndexWriter, f: &Fields, events: &[Event]) -> Result<()> {
    let result = index_batch_inner(writer, f, events);
    if result.is_err() {
        // On any add/commit failure, roll back so (a) this batch's queued docs
        // don't silently leak into the NEXT successful commit — the ack said
        // this batch failed — and (b) the writer is rebuilt (tantivy's
        // rollback re-creates it), so a transient error (e.g. disk full) can't
        // permanently poison indexing for the rest of the process. If rollback
        // itself fails the writer is unusable; surface it loudly.
        if let Err(e) = writer.rollback() {
            tracing::error!(error = %e, "search writer rollback failed — full-text indexing degraded");
        }
    }
    result
}

fn index_batch_inner(writer: &mut IndexWriter, f: &Fields, events: &[Event]) -> Result<()> {
    for e in events {
        let mut d = doc!(
            f.ts => e.ts.timestamp_micros(),
            f.host => e.host.as_str(),
            f.service => e.service.as_str(),
            f.source => e.source.as_str(),
            f.severity => e.severity.as_str(),
            f.log_type => e.log_type.as_str(),
            f.message => e.message.as_str(),
        );
        if let Some(ip) = e.field("src_ip") {
            d.add_text(f.src_ip, ip);
        }
        if let Some(u) = e.field("user") {
            d.add_text(f.user, u);
        }
        writer
            .add_document(d)
            .map_err(|e| Error::store(e.to_string()))?;
    }
    writer.commit().map_err(|e| Error::store(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ev(message: &str, host: &str, src_ip: Option<&str>) -> Event {
        let mut fields = BTreeMap::new();
        if let Some(ip) = src_ip {
            fields.insert("src_ip".to_string(), ip.to_string());
        }
        Event {
            ts: chrono::Utc::now(),
            host: host.into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "prod".into(),
            severity: "warning".into(),
            log_type: "system".into(),
            message: message.into(),
            fields,
        }
    }

    #[tokio::test]
    async fn index_then_search_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev(
                "Failed password for root from 203.0.113.7 port 22 ssh2",
                "pve",
                Some("203.0.113.7"),
            ),
            ev(
                "Accepted publickey for henrik from 192.168.1.50 port 40222 ssh2",
                "pve",
                Some("192.168.1.50"),
            ),
        ])
        .await
        .unwrap();

        // Free-text hits the message; a field query targets an exact term.
        let hits = idx.search("failed password", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("Failed password"));

        let field_hits = idx.search("host:pve accepted", 10).unwrap();
        assert!(field_hits
            .iter()
            .any(|h| h.message.contains("Accepted publickey")));

        // A term present in neither message returns nothing.
        assert!(idx.search("kernel panic", 10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn clear_empties_the_index_for_a_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![ev("Failed password for root", "pve", None)])
            .await
            .unwrap();
        assert_eq!(idx.search("failed password", 10).unwrap().len(), 1);
        // Clear → the doc is gone (the first step of a warehouse rebuild).
        idx.clear().await.unwrap();
        assert!(idx.search("failed password", 10).unwrap().is_empty());
        // Re-indexing after a clear does not duplicate.
        idx.index(vec![ev("Failed password for root", "pve", None)])
            .await
            .unwrap();
        assert_eq!(idx.search("failed password", 10).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn search_filtered_pushes_down_label_terms() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev("Failed password for root", "web01", None),
            ev("Failed password for root", "web02", None),
        ])
        .await
        .unwrap();

        // Same text on two hosts; the host filter narrows to one.
        let all = idx
            .search_filtered("failed password", &[], &[], &[], &[], &[], 10)
            .unwrap();
        assert_eq!(all.len(), 2);
        let only = idx
            .search_filtered(
                "failed password",
                &["web01".to_string()],
                &[],
                &[],
                &[],
                &[],
                10,
            )
            .unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].host, "web01");
    }

    #[tokio::test]
    async fn limit_zero_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![ev("failed password", "h", None)])
            .await
            .unwrap();
        // Must clamp, not panic.
        assert!(idx.search("failed", 0).is_ok());
    }

    #[tokio::test]
    async fn read_only_open_rejects_indexing() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_reader(dir.path()).unwrap();
        assert!(idx.index(vec![ev("x", "h", None)]).await.is_err());
    }

    /// An event with a fixed timestamp (epoch micros), for range tests.
    fn ev_at(ts_micros: i64, message: &str) -> Event {
        let mut e = ev(message, "pve", None);
        e.ts = chrono::DateTime::from_timestamp_micros(ts_micros).unwrap();
        e
    }

    #[tokio::test]
    async fn search_in_range_bounds_by_event_time() {
        const S: i64 = 1_000_000; // one second in micros
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev_at(1000 * S, "Failed password for root (early)"),
            ev_at(2000 * S, "Failed password for root (middle)"),
            ev_at(3000 * S, "Failed password for root (late)"),
        ])
        .await
        .unwrap();

        let msgs = |hits: Vec<Hit>| {
            let mut m: Vec<String> = hits.into_iter().map(|h| h.message).collect();
            m.sort();
            m
        };

        // [from, to) is half-open: 2000s is included at its own `from`, 3000s
        // is excluded at its own `to`.
        let mid = idx
            .search_in_range("failed password", 10, Some(2000 * S), Some(3000 * S))
            .unwrap();
        assert_eq!(msgs(mid), ["Failed password for root (middle)"]);

        // An open upper bound reaches the newest event.
        let tail = idx
            .search_in_range("failed password", 10, Some(2000 * S), None)
            .unwrap();
        assert_eq!(tail.len(), 2);

        // An open lower bound reaches the oldest, still excluding `to`.
        let head = idx
            .search_in_range("failed password", 10, None, Some(2000 * S))
            .unwrap();
        assert_eq!(msgs(head), ["Failed password for root (early)"]);

        // No bounds = the plain search.
        assert_eq!(
            idx.search_in_range("failed password", 10, None, None)
                .unwrap()
                .len(),
            3
        );

        // A window with matches for the term but none inside it is empty.
        assert!(idx
            .search_in_range("failed password", 10, Some(4000 * S), None)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn search_filtered_in_range_combines_labels_and_the_window() {
        const S: i64 = 1_000_000;
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        let at = |ts: i64, host: &str| {
            let mut e = ev("Failed password for root", host, None);
            e.ts = chrono::DateTime::from_timestamp_micros(ts).unwrap();
            e
        };
        idx.index(vec![
            at(1000 * S, "web01"),
            at(2000 * S, "web01"),
            at(2000 * S, "web02"),
        ])
        .await
        .unwrap();

        let filtered = |from, to| {
            idx.search_filtered_in_range(
                "failed password",
                &["web01".to_string()],
                &[],
                &[],
                &[],
                &[],
                10,
                from,
                to,
            )
            .unwrap()
        };
        // Host AND window: web02 is out by label, the early row by time.
        let hits = filtered(Some(2000 * S), Some(3000 * S));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].host, "web01");
        assert_eq!(hits[0].ts_micros, 2000 * S);
        // Without the window the host filter alone keeps both web01 rows.
        assert_eq!(filtered(None, None).len(), 2);
    }

    #[tokio::test]
    async fn a_filtered_search_with_a_window_refuses_a_pre_upgrade_index() {
        // Fail-closed exactly like the unfiltered path: an unservable bound
        // must never degrade into an unbounded (or empty) result set.
        let dir = tempfile::tempdir().unwrap();
        create_legacy_index_for_tests(dir.path()).unwrap();
        let idx = SearchIndex::open_reader(dir.path()).unwrap();

        let call = |from, to| {
            idx.search_filtered_in_range("failed password", &[], &[], &[], &[], &[], 10, from, to)
        };
        let err = call(Some(0), None).unwrap_err().to_string();
        assert!(err.contains("garmr reindex"), "unhelpful error: {err}");
        assert!(call(None, Some(1)).is_err(), "an upper bound too");
        // Unranged filtered search still works on the old index.
        assert_eq!(call(None, None).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_fresh_index_reports_a_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        assert!(idx.schema_current());
        assert!(idx.supports_ts_range());
    }

    // A deployment carrying an index from before `ts_micros` was FAST must keep
    // working after the upgrade: open (no startup crashloop), search, and index
    // new events — only the new time-range capability is refused, with the
    // migration instruction, until `garmr reindex` rebuilds the index.
    #[tokio::test]
    async fn an_old_schema_index_opens_degraded_not_broken() {
        let dir = tempfile::tempdir().unwrap();
        create_legacy_index_for_tests(dir.path()).unwrap();

        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        assert!(!idx.schema_current());
        assert!(!idx.supports_ts_range());

        // Unranged search still serves the pre-upgrade documents.
        let hits = idx.search("failed password", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ts_micros, 42_000_000);

        // New events still index through the compat handle.
        idx.index(vec![ev("Accepted publickey for henrik", "pve", None)])
            .await
            .unwrap();
        assert_eq!(idx.search("accepted publickey", 10).unwrap().len(), 1);

        // A bounded search refuses with the migration instruction instead of
        // silently returning zero hits.
        let err = idx
            .search_in_range("failed password", 10, Some(0), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("garmr reindex"), "unhelpful error: {err}");
    }

    fn ev_src(message: &str, source: &str) -> Event {
        let mut e = ev(message, "pve", None);
        e.source = source.into();
        e
    }

    #[tokio::test]
    async fn a_data_scope_filters_full_text_hits_to_its_own_sources() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev_src("Failed password for root hrrow", "hr"),
            ev_src("Failed password for root infrarow", "infra"),
        ])
        .await
        .unwrap();

        let scoped = |allowed: Option<&[String]>| {
            idx.search_scoped_in_range(
                "failed password",
                &[],
                &[],
                &[],
                &[],
                &[],
                10,
                None,
                None,
                allowed,
            )
            .unwrap()
        };

        // Unrestricted sees both; scoped sees only its own source.
        assert_eq!(scoped(None).len(), 2);
        let hr = vec!["hr".to_string()];
        let hits = scoped(Some(&hr));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("hrrow"), "{:?}", hits[0].message);
    }

    #[tokio::test]
    async fn a_source_term_in_the_query_text_cannot_widen_the_scope() {
        // Tantivy's parser accepts `field:value`, so a caller can name another
        // source inside the free-text query itself. The scope is a separate Must
        // clause, so that AND-s to nothing instead of reaching across.
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev_src("Failed password for root hrrow", "hr"),
            ev_src("Failed password for root infrarow", "infra"),
        ])
        .await
        .unwrap();

        let hr = vec!["hr".to_string()];
        let hits = idx
            .search_scoped_in_range(
                "source:infra",
                &[],
                &[],
                &[],
                &[],
                &[],
                10,
                None,
                None,
                Some(&hr),
            )
            .unwrap();
        assert!(
            hits.is_empty(),
            "a query naming another source must yield nothing, got {hits:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_scope_matches_nothing_rather_than_everything() {
        // The dangerous edge: an empty allow-list must not read as "no filter".
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev_src("Failed password for root hrrow", "hr"),
            ev_src("Failed password for root infrarow", "infra"),
        ])
        .await
        .unwrap();

        let none: Vec<String> = Vec::new();
        let hits = idx
            .search_scoped_in_range(
                "failed password",
                &[],
                &[],
                &[],
                &[],
                &[],
                10,
                None,
                None,
                Some(&none),
            )
            .unwrap();
        assert!(
            hits.is_empty(),
            "an empty allow-list must read nothing, got {} hits",
            hits.len()
        );
    }

    #[tokio::test]
    async fn prune_before_drops_old_docs_and_keeps_the_hot_window() {
        const S: i64 = 1_000_000;
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev_at(1000 * S, "sealed-window-only marker line"),
            ev_at(5000 * S, "hot-window marker line"),
        ])
        .await
        .unwrap();

        idx.prune_before(2000 * S).await.unwrap();

        // The acceptance line: a message that existed only in the pruned window
        // returns 0 hits; the hot window still hits.
        assert!(
            idx.search("sealed-window-only", 10).unwrap().is_empty(),
            "pruned document must be gone from full text"
        );
        assert_eq!(idx.search("hot-window", 10).unwrap().len(), 1);

        // Idempotent: pruning again converges to a no-op.
        idx.prune_before(2000 * S).await.unwrap();
        assert_eq!(idx.search("hot-window", 10).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn prune_refuses_a_pre_upgrade_index_rather_than_lying() {
        // On the legacy schema ts is not indexed, so a range delete would match
        // nothing while reporting success — "pruned" would be a lie an operator
        // discovers as unbounded disk growth. Refusing names the fix instead.
        let dir = tempfile::tempdir().unwrap();
        create_legacy_index_for_tests(dir.path()).unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        let err = idx.prune_before(1).await.unwrap_err().to_string();
        assert!(err.contains("garmr reindex"), "unhelpful error: {err}");
    }

    #[tokio::test]
    async fn erase_docs_by_host_term_only_and_no_phrase_primitive() {
        let dir = tempfile::tempdir().unwrap();
        let idx = SearchIndex::open_writer(dir.path()).unwrap();
        idx.index(vec![
            ev("Failed password from 203.0.113.7", "victim-host", None),
            ev("Failed password from 10.0.0.5", "victim-host", None),
            ev("Failed password from 203.0.113.7", "other-host", None),
            ev("routine heartbeat", "other-host", None),
        ])
        .await
        .unwrap();

        // Host erasure: exact term on the untokenized label.
        idx.erase_host_docs("victim-host").await.unwrap();
        assert!(
            idx.search_filtered(
                "failed password",
                &["victim-host".to_string()],
                &[],
                &[],
                &[],
                &[],
                10
            )
            .unwrap()
            .is_empty(),
            "every victim-host doc is gone"
        );
        assert_eq!(
            idx.search("heartbeat", 10).unwrap().len(),
            1,
            "other hosts untouched"
        );

        // There is deliberately no message/phrase erase primitive: a phrase
        // over an IP's tokenization degrades into fragment matching (the first
        // draft deleted 10.0.0.5's doc via the shared "0" token). Field-based
        // erasure goes through a rebuild from the already-erased store instead.
        assert_eq!(
            idx.search("\"203.0.113.7\"", 10).unwrap().len(),
            1,
            "the other host's doc with the erased-elsewhere IP is untouched here"
        );
    }
}
