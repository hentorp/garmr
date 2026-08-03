// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `flightbeat` — a tiny Arrow-Flight log shipper for garm.
//!
//! The columnar counterpart to Elastic's Beats: instead of POSTing JSON lines, it
//! reads a source (stdin or a file), batches rows into an Arrow `RecordBatch` of
//! garm's **v1 wire columns**, and ships them via Flight `DoPut` to garm's
//! columnar-swallow ingest — no JSON on the wire, no parse on the receiver. garm
//! computes the provenance (`event_id`, `ingest_time`, trust) server-side.
//!
//! Deliberately minimal: `arrow` + `arrow-flight` + `tonic`, nothing else. It
//! links NO garm/skade code — the wire schema is reproduced here by contract
//! (`wire_schema` must match `garmr_store::schema::wire_schema`; a mismatch is
//! rejected by the receiver, loudly).
//!
//! ```text
//! flightbeat --addr http://127.0.0.1:50051 --host web-01 --source nginx \
//!            --collector edge-01 --batch-rows 4096 --file /var/log/nginx/access.log
//! # or stream stdin:
//! journalctl -f -o cat | flightbeat --addr http://garm:50051 --collector edge-01
//! ```
//!
//! Scope note (minimal first cut): one message per input line, shared label
//! defaults, empty `fields` (`{}` — the receiver derives fields from the message
//! for raw lines). The lazy channel reconnects on a dropped connection and each
//! batch retries with capped backoff (`--max-retries`), and retries are safe
//! (the receiver dedups on `event_id`). Client-side field extraction, file
//! rotation, and journald remain follow-ups; the wire + swallow contract is
//! complete.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arrow_array::{ArrayRef, RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow_flight::encode::FlightDataEncoderBuilder;
use arrow_flight::error::FlightError;
use arrow_flight::FlightClient;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use futures::TryStreamExt;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

/// The v1 payload schema — the 9 columns garm's receiver expects. **Must match
/// `garmr_store::schema::wire_schema` exactly** (name + type + nullability); the
/// receiver validates it and rejects a mismatch.
fn wire_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("event_ts", DataType::Timestamp(TimeUnit::Microsecond, None), false),
        Field::new("host", DataType::Utf8, false),
        Field::new("service", DataType::Utf8, true),
        Field::new("source", DataType::Utf8, true),
        Field::new("environment", DataType::Utf8, true),
        Field::new("severity", DataType::Utf8, true),
        Field::new("log_type", DataType::Utf8, true),
        Field::new("message", DataType::Utf8, false),
        Field::new("fields", DataType::Utf8, true),
    ]))
}

/// The shared label defaults stamped on every row of a batch (one shipper serves
/// one source with a fixed identity — the per-line variety is the `message`).
struct Labels {
    host: String,
    service: String,
    source: String,
    environment: String,
    severity: String,
    log_type: String,
}

/// Build a wire `RecordBatch` from a batch of message lines + the shared labels.
/// All rows share one receive timestamp and the label defaults; `fields` is the
/// empty JSON object (canonical for an event with no extracted fields).
fn build_wire_batch(schema: SchemaRef, msgs: &[String], labels: &Labels) -> Result<RecordBatch> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as i64;
    let n = msgs.len();
    let rep = |s: &str| StringArray::from(vec![s; n]);
    let cols: Vec<ArrayRef> = vec![
        Arc::new(TimestampMicrosecondArray::from(vec![now; n])),
        Arc::new(rep(&labels.host)),
        Arc::new(rep(&labels.service)),
        Arc::new(rep(&labels.source)),
        Arc::new(rep(&labels.environment)),
        Arc::new(rep(&labels.severity)),
        Arc::new(rep(&labels.log_type)),
        Arc::new(StringArray::from(msgs.iter().map(|s| s.as_str()).collect::<Vec<_>>())),
        Arc::new(rep("{}")),
    ];
    RecordBatch::try_new(schema, cols).context("build wire batch")
}

/// Ship one batch via Flight `DoPut`, returning the receiver's stored-row count
/// (from the `PutResult` ack `app_metadata`).
async fn ship(client: &mut FlightClient, schema: SchemaRef, batch: RecordBatch) -> Result<u64> {
    let stream = FlightDataEncoderBuilder::new()
        .with_schema(schema)
        .build(futures::stream::iter(vec![Ok::<_, FlightError>(batch)]));
    let mut resp = client.do_put(stream).await.context("do_put")?;
    let mut acked = 0u64;
    while let Some(r) = resp.try_next().await.context("do_put response")? {
        if let Ok(s) = std::str::from_utf8(&r.app_metadata) {
            acked = s.trim().parse().unwrap_or(acked);
        }
    }
    Ok(acked)
}

/// Capped exponential backoff before retry `attempt` (0-based): 100ms, 200ms,
/// 400ms, … capped at 10s. Bounded so a raw-log firehose can't spin a hot retry
/// loop against a down receiver.
fn backoff_ms(attempt: u32) -> u64 {
    (100u64.saturating_mul(1 << attempt.min(7))).min(10_000)
}

/// Ship a batch, retrying transient failures (the receiver down, a dropped
/// channel) up to `max_retries` with backoff. Retrying is SAFE: the receiver
/// dedups on `event_id`, so a re-shipped batch — even one that partially landed —
/// stores each event at most once. The lazy tonic channel reconnects itself on
/// the next attempt.
async fn ship_with_retry(
    client: &mut FlightClient,
    schema: SchemaRef,
    batch: RecordBatch,
    max_retries: u32,
) -> Result<u64> {
    let mut attempt = 0;
    loop {
        match ship(client, schema.clone(), batch.clone()).await {
            Ok(n) => return Ok(n),
            Err(e) if attempt < max_retries => {
                let wait = backoff_ms(attempt);
                eprintln!(
                    "flightbeat: ship failed (attempt {}/{max_retries}), retrying in {wait}ms: {e:#}",
                    attempt + 1
                );
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                attempt += 1;
            }
            Err(e) => return Err(e.context(format!("giving up after {max_retries} retries"))),
        }
    }
}

struct Args {
    addr: String,
    collector: Option<String>,
    file: Option<String>,
    batch_rows: usize,
    /// Ship a partial (< `batch_rows`) buffer after this many seconds of no
    /// flush, so a low-rate `tail -F`/`journalctl -f` stream doesn't sit unsent
    /// waiting for a full batch. 0 disables the timer (batch-size flush only).
    flush_secs: u64,
    max_retries: u32,
    labels: Labels,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        addr: "http://127.0.0.1:50051".into(),
        collector: None,
        file: None,
        batch_rows: 4096,
        flush_secs: 5,
        max_retries: 5,
        labels: Labels {
            host: "unknown".into(),
            service: String::new(),
            source: "flightbeat".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "app".into(),
        },
    };
    fn val(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
        it.next().with_context(|| format!("missing value for {flag}"))
    }
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--addr" => a.addr = val(&mut it, &flag)?,
            "--collector" => a.collector = Some(val(&mut it, &flag)?),
            "--file" => a.file = Some(val(&mut it, &flag)?),
            "--batch-rows" => a.batch_rows = val(&mut it, &flag)?.parse().context("--batch-rows")?,
            "--flush-secs" => a.flush_secs = val(&mut it, &flag)?.parse().context("--flush-secs")?,
            "--max-retries" => a.max_retries = val(&mut it, &flag)?.parse().context("--max-retries")?,
            "--host" => a.labels.host = val(&mut it, &flag)?,
            "--service" => a.labels.service = val(&mut it, &flag)?,
            "--source" => a.labels.source = val(&mut it, &flag)?,
            "--environment" => a.labels.environment = val(&mut it, &flag)?,
            "--severity" => a.labels.severity = val(&mut it, &flag)?,
            "--log-type" => a.labels.log_type = val(&mut it, &flag)?,
            "-h" | "--help" => {
                eprintln!(
                    "flightbeat — Arrow-Flight log shipper for garm\n\
                     usage: flightbeat [--addr URL] [--collector ID] [--file PATH]\n\
                     \t[--batch-rows N] [--flush-secs N] [--max-retries N]\n\
                     \t[--host H] [--service S] [--source S] [--environment E]\n\
                     \t[--severity S] [--log-type T]\n\
                     reads stdin when --file is omitted; --flush-secs bounds how\n\
                     long a partial batch waits (0 disables the timer)."
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other} (try --help)"),
        }
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let schema = wire_schema();

    // Lazy channel: connects on first use and RECONNECTS itself on a dropped
    // connection, so a transient receiver restart doesn't kill the shipper.
    let channel = tonic::transport::Channel::from_shared(args.addr.clone())
        .context("invalid --addr")?
        .connect_lazy();
    let mut client = FlightClient::new(channel);
    if let Some(c) = &args.collector {
        client.add_header("garmr-collector-id", c).context("collector header")?;
    }

    // One reader interface over stdin or a file.
    let reader: Box<dyn AsyncBufRead + Unpin + Send> = match &args.file {
        Some(path) => {
            let f = tokio::fs::File::open(path).await.with_context(|| format!("open {path}"))?;
            Box::new(BufReader::new(f))
        }
        None => Box::new(BufReader::new(tokio::io::stdin())),
    };
    let mut lines = reader.lines();

    let (mut buf, mut shipped) = (Vec::with_capacity(args.batch_rows), 0u64);

    // A steady stream (`tail -F`, `journalctl -f`) never hits EOF, so without a
    // wall-clock flush a low-rate source would buffer until it reached
    // `batch_rows` — potentially forever. The timer ships whatever is buffered
    // after `flush_secs`; `flush_secs == 0` opts out (batch-size flush only).
    let mut flush = (args.flush_secs > 0).then(|| {
        let mut i = tokio::time::interval(std::time::Duration::from_secs(args.flush_secs));
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    });
    // Consume the immediate first tick so the timer only fires after a real wait.
    if let Some(i) = flush.as_mut() {
        i.tick().await;
    }

    loop {
        // When the timer is disabled, park that select branch forever.
        let tick = async {
            match flush.as_mut() {
                Some(i) => {
                    i.tick().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            line = lines.next_line() => {
                match line.context("read line")? {
                    Some(line) => {
                        if line.is_empty() {
                            continue;
                        }
                        buf.push(line);
                        if buf.len() >= args.batch_rows {
                            shipped += flush_buf(
                                &mut client, &schema, &mut buf, &args.labels, args.max_retries,
                            )
                            .await?;
                        }
                    }
                    None => break, // EOF (a piped one-shot or a closed file)
                }
            }
            _ = tick => {
                shipped += flush_buf(
                    &mut client, &schema, &mut buf, &args.labels, args.max_retries,
                )
                .await?;
            }
        }
    }
    // Final flush of anything the EOF left buffered.
    shipped +=
        flush_buf(&mut client, &schema, &mut buf, &args.labels, args.max_retries).await?;

    eprintln!("flightbeat: shipped {shipped} events to {}", args.addr);
    Ok(())
}

/// Build one Arrow batch from the buffered lines and ship it, clearing the
/// buffer. A no-op (and no wire traffic) when the buffer is empty, so the flush
/// timer firing on an idle stream costs nothing.
async fn flush_buf(
    client: &mut FlightClient,
    schema: &SchemaRef,
    buf: &mut Vec<String>,
    labels: &Labels,
    max_retries: u32,
) -> Result<u64> {
    if buf.is_empty() {
        return Ok(0);
    }
    let batch = build_wire_batch(schema.clone(), buf, labels)?;
    let shipped = ship_with_retry(client, schema.clone(), batch, max_retries).await?;
    buf.clear();
    Ok(shipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels() -> Labels {
        Labels {
            host: "web-01".into(),
            service: "nginx".into(),
            source: "flightbeat".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "app".into(),
        }
    }

    #[test]
    fn wire_batch_shape_matches_the_contract() {
        let schema = wire_schema();
        let msgs = vec!["GET / 200".to_string(), "GET /x 404".to_string()];
        let batch = build_wire_batch(schema.clone(), &msgs, &labels()).unwrap();
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 9);
        // Column names + the message passthrough are the wire contract.
        assert_eq!(batch.schema().field(0).name(), "event_ts");
        assert_eq!(batch.schema().field(7).name(), "message");
        let msg = batch.column(7).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(msg.value(0), "GET / 200");
        assert_eq!(msg.value(1), "GET /x 404");
        let host = batch.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(host.value(0), "web-01");
    }

    #[test]
    fn backoff_is_capped_exponential() {
        assert_eq!(backoff_ms(0), 100);
        assert_eq!(backoff_ms(1), 200);
        assert_eq!(backoff_ms(2), 400);
        assert_eq!(backoff_ms(3), 800);
        // Monotonic non-decreasing and hard-capped at 10s regardless of attempt.
        assert_eq!(backoff_ms(20), 10_000);
        assert!((0..30).all(|a| backoff_ms(a) <= 10_000));
        assert!((0..30).all(|a| backoff_ms(a) <= backoff_ms(a + 1)));
    }

    #[tokio::test]
    async fn flush_buf_on_empty_is_a_noop() {
        // The flush timer fires on a schedule regardless of traffic; on an idle
        // stream the buffer is empty and flush_buf must return before touching
        // the client. A lazy channel never dials until used, so this test stays
        // fully offline — proving no wire traffic on the empty path.
        let channel = tonic::transport::Channel::from_shared("http://127.0.0.1:1")
            .unwrap()
            .connect_lazy();
        let mut client = FlightClient::new(channel);
        let schema = wire_schema();
        let mut buf: Vec<String> = Vec::new();
        let n = flush_buf(&mut client, &schema, &mut buf, &labels(), 0).await.unwrap();
        assert_eq!(n, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn schema_is_the_nine_v1_columns_in_order() {
        let schema = wire_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(
            names,
            [
                "event_ts", "host", "service", "source", "environment", "severity", "log_type",
                "message", "fields"
            ]
        );
    }
}
