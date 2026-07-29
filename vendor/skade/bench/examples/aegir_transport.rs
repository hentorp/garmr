//! Head-to-head **ureq vs io_uring** aegir transport on the plaintext RustFS hot
//! path. Isolates the S3 op cost (HEAD / GET / PUT) from the iceberg/parquet data
//! plane, so the byte-transport difference is what's measured.
//!
//! Run (RustFS up on :9000):
//!   cargo run --release --features uring --example aegir_transport
//!
//! Emits one JSONL line per (transport, op) with ops/sec + p50/p99 µs — append-
//! ready to the heavy-bench result file.

use std::time::Instant;

use aegir::{Client, Transport};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn pct(sorted: &[u128], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (((sorted.len() - 1) as f64) * q).round() as usize;
    sorted[idx] as f64 / 1000.0
}

/// Time `iters` calls of `op`, emit a JSONL result line.
fn bench(label: &str, op_name: &str, iters: usize, mut op: impl FnMut()) {
    // warm up
    for _ in 0..iters.min(50) {
        op();
    }
    let mut lat = Vec::with_capacity(iters);
    let wall = Instant::now();
    for _ in 0..iters {
        let t = Instant::now();
        op();
        lat.push(t.elapsed().as_nanos());
    }
    let secs = wall.elapsed().as_secs_f64().max(1e-9);
    lat.sort_unstable();
    let v = serde_json::json!({
        "name": format!("aegir.{op_name}"),
        "target": label,
        "ops": iters,
        "ops_sec": iters as f64 / secs,
        "p50_us": pct(&lat, 0.50),
        "p99_us": pct(&lat, 0.99),
        "p999_us": pct(&lat, 0.999),
        "elapsed_ms": wall.elapsed().as_millis(),
    });
    println!("{v}");
    eprintln!(
        "# {label} {op_name}: {:.0} ops/s  p50 {:.1}us  p99 {:.1}us",
        iters as f64 / secs,
        pct(&lat, 0.50),
        pct(&lat, 0.99)
    );
}

fn run(label: &str, transport: Transport, iters: usize) -> anyhow::Result<()> {
    let endpoint = env_or("BENCH_S3_ENDPOINT", "http://localhost:9000");
    let c = Client::new(&endpoint, "us-east-1", env_or("BENCH_S3_ACCESS_KEY", "rustfsadmin"), env_or("BENCH_S3_SECRET_KEY", "rustfsadmin"))
        .with_transport(transport);
    eprintln!("# transport {label}: effective = {:?}", c.effective_transport());

    let bucket = "aegir-bench";
    c.create_bucket(bucket).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Seed an object for HEAD/GET.
    let key = "hot/object.bin";
    let payload = vec![0xABu8; 4096];
    c.put_object(bucket, key, &payload, None).map_err(|e| anyhow::anyhow!("{e}"))?;

    bench(label, "head", iters, || {
        let _ = c.head_object(bucket, key).expect("head");
    });
    bench(label, "get_4k", iters, || {
        let g = c.get_object(bucket, key).expect("get");
        assert_eq!(g.len(), 4096);
    });
    // PUT a fresh small object each time (idempotent key reuse is fine).
    let small = b"x".repeat(256);
    bench(label, "put_256b", iters, || {
        c.put_object(bucket, "hot/put.bin", &small, None).expect("put");
    });
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let iters: usize = env_or("BENCH_AEGIR_ITERS", "5000").parse().unwrap_or(5000);

    run("aegir-ureq", Transport::Ureq, iters)?;
    run("aegir-uring", Transport::Uring, iters)?;
    Ok(())
}
