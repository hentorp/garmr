//! Full TPC-H suite — all **8 tables** + all **22 queries** over `RedbCatalog`,
//! through DataFusion via `iceberg-datafusion`, on authentic `tpchgen` data.
//!
//! The harness (generate + ingest 8 tables, wire DataFusion, build query SQL with
//! standard validation params + DataFusion dialect fixups) lives in the shared
//! `../tpch_shared.rs` (also used by `examples/nornir-bench.rs`). Here we just run
//! all 22 and assert each plans + executes (answer values need SF=1; not checked).
//! Scale via `TPCH_SF` (default 0.01 ≈ 87k rows). Temp dir = `/tmp` (tmpfs/RAM).

#[path = "../tpch_shared.rs"]
mod tpch;

use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
async fn tpch_full_suite_22_queries() -> Result<()> {
    let sf: f64 = std::env::var("TPCH_SF").ok().and_then(|v| v.parse().ok()).unwrap_or(0.01);
    let (ctx, _tmp, total) = tpch::build_ctx(sf).await?;
    assert!(total > 0, "no TPC-H rows generated at SF={sf}");

    let mut failures: Vec<String> = Vec::new();
    for n in 1..=22 {
        let sql = tpch::query_sql(n);
        match ctx.sql(&sql).await {
            Ok(df) => match df.collect().await {
                Ok(b) => eprintln!("  Q{n:<2} ok  ({} rows)", b.iter().map(|x| x.num_rows()).sum::<usize>()),
                Err(e) => failures.push(format!("Q{n} (exec): {}", first_line(&e))),
            },
            Err(e) => failures.push(format!("Q{n} (plan): {}", first_line(&e))),
        }
    }
    eprintln!("TPC-H: {}/22 executed (SF={sf}, {total} rows across 8 tables)", 22 - failures.len());
    assert!(failures.is_empty(), "TPC-H queries failed:\n{}", failures.join("\n"));
    Ok(())
}

/// The same 22 queries, but the session is built by **skade** (`build_ctx_skade`
/// → `skade::Warehouse::session`) instead of hand-wired iceberg-datafusion —
/// dogfooding skade's SQL surface end-to-end on TPC-H.
#[tokio::test(flavor = "multi_thread")]
async fn tpch_full_suite_22_queries_through_skade() -> Result<()> {
    let sf: f64 = std::env::var("TPCH_SF").ok().and_then(|v| v.parse().ok()).unwrap_or(0.01);
    let (ctx, _tmp, total) = tpch::build_ctx_skade(sf).await?;
    assert!(total > 0, "no TPC-H rows generated at SF={sf}");

    let mut failures: Vec<String> = Vec::new();
    for n in 1..=22 {
        let sql = tpch::query_sql(n);
        match ctx.sql(&sql).await {
            Ok(df) => match df.collect().await {
                Ok(b) => eprintln!("  skade Q{n:<2} ok  ({} rows)", b.iter().map(|x| x.num_rows()).sum::<usize>()),
                Err(e) => failures.push(format!("Q{n} (exec): {}", first_line(&e))),
            },
            Err(e) => failures.push(format!("Q{n} (plan): {}", first_line(&e))),
        }
    }
    eprintln!("TPC-H via skade: {}/22 executed (SF={sf}, {total} rows)", 22 - failures.len());
    assert!(failures.is_empty(), "TPC-H-through-skade queries failed:\n{}", failures.join("\n"));
    Ok(())
}

fn first_line(e: &dyn std::fmt::Display) -> String {
    let s = format!("{e}");
    s.lines().next().unwrap_or(&s).to_string()
}
