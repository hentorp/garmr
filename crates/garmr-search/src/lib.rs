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
use tantivy::schema::{Field, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, IndexReader, IndexWriter, TantivyDocument};
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
    let ts = b.add_i64_field("ts_micros", STORED);
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
    /// Sources NOT written to the full-text index (see `index`). Empty = all.
    exclude_sources: HashSet<String>,
}

impl SearchIndex {
    fn open_index(dir: &Path) -> Result<(Index, Fields, IndexReader)> {
        std::fs::create_dir_all(dir).map_err(Error::store)?;
        let (schema, fields) = build_schema();
        let mmap = MmapDirectory::open(dir).map_err(|e| Error::store(e.to_string()))?;
        // open_or_create writes meta.json if absent but takes NO writer lock,
        // so it's safe for a reader-only open alongside a running writer.
        let index = Index::open_or_create(mmap, schema).map_err(|e| Error::store(e.to_string()))?;
        let reader = index.reader().map_err(|e| Error::store(e.to_string()))?;
        Ok((index, fields, reader))
    }

    /// Open reader-only (no writer lock). Searches work; `index()` errors.
    pub fn open_reader(dir: &Path) -> Result<Self> {
        let (index, fields, reader) = Self::open_index(dir)?;
        Ok(Self {
            tx: None,
            reader,
            index,
            fields,
            exclude_sources: HashSet::new(),
        })
    }

    /// Open writable: acquires the exclusive writer lock and spawns the writer
    /// actor. Fails if another process already holds the writer.
    pub fn open_writer(dir: &Path) -> Result<Self> {
        let (index, fields, reader) = Self::open_index(dir)?;
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
            exclude_sources: HashSet::new(),
        })
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

    /// Run a full-text query (Tantivy syntax; bare terms hit `message`) and
    /// return the top `limit` hits by relevance.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        // TopDocs::with_limit(0) panics (asserts limit > 0); clamp so a stray
        // `--limit 0` returns nothing instead of aborting the command.
        let limit = limit.max(1);
        self.reader
            .reload()
            .map_err(|e| Error::store(e.to_string()))?;
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![self.fields.message]);
        let q = parser
            .parse_query(query)
            .map_err(|e| Error::store(format!("query: {e}")))?;
        let top = searcher
            .search(&q, &TopDocs::with_limit(limit).order_by_score())
            .map_err(|e| Error::store(e.to_string()))?;

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

        let q = BooleanQuery::new(clauses);
        let top = searcher
            .search(&q, &TopDocs::with_limit(limit).order_by_score())
            .map_err(|e| Error::store(e.to_string()))?;

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
        }
    }
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
}
