//! Bring up / tear down the bench's competitor backends (RustFS S3, Nessie,
//! Polaris). Replaces `containers/*.sh` — all the engine detection, UID mapping,
//! stale-warehouse cleanup, gateway wiring, and Polaris OAuth bootstrap live in
//! `skade_katalog_bench::containers` as pre-checks / pre-check-fixes.
//!
//!   bench-containers up [all|rustfs|nessie|polaris]   (default: all)
//!   bench-containers down [all|rustfs|nessie|polaris]
//!   bench-containers status

use anyhow::{bail, Result};
use skade_katalog_bench::containers;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("up");
    let svc = args.get(2).map(String::as_str).unwrap_or("all");
    match (cmd, svc) {
        ("up", "all") => containers::up_all(),
        ("up", "rustfs") => containers::rustfs_up(),
        ("up", "nessie") => containers::nessie_up(),
        ("up", "polaris") => containers::polaris_up(),
        // Spark+Iceberg writes a `rows`-row table (default 1M); read it back with
        // `cargo run --release --example skade_reads_spark`. The skade-vs-Spark baseline.
        ("up", "spark") => {
            let rows = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
            containers::spark_up(rows)
        }
        ("down", "all") => containers::down_all(),
        ("down", "spark") => containers::spark_down(),
        ("down", s) => containers::down(s),
        ("status", _) => containers::status(),
        _ => bail!("usage: bench-containers <up|down|status> [all|rustfs|nessie|polaris|spark]"),
    }
}
