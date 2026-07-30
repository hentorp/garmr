// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! garmr xtask — thin automation dispatcher (fleet convention: a plain `match`
//! on `argv[1]`, no clap). The one verb that matters here is `bench`, which
//! drives the detached `bench/` crate's nornir bencher.
//!
//!   cargo xtask bench            # run the garmr.* bench arms, print BenchRun JSON
//!   cargo xtask bench --preview  # tiny verify-it-works pass (NORNIR_BENCH_PREVIEW)
//!   cargo xtask bench --heavy    # fat-machine scale, e.g. Odin (NORNIR_BENCH_HEAVY)
//!
//! For the persisted + regression-gated path, use the nornir CLI directly:
//!   nornir bench run garmr
//! which spawns the same example, parses its stdout, and writes the run into the
//! bench_runs warehouse table.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Result};

fn main() {
    if let Err(e) = run() {
        eprintln!("✗ {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("bench") => bench(args.collect()),
        Some("help") | Some("--help") | Some("-h") | None => {
            usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown verb: {other}\n");
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    eprintln!(
        "usage: cargo xtask <verb>\n\n\
         verbs:\n  \
         bench [--preview|--heavy]   run the garmr nornir bench arms (BenchRun JSON on stdout)\n  \
         help                        show this message\n"
    );
}

/// The garmr workspace root (this crate's parent directory).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask has a parent").to_path_buf()
}

fn bench(rest: Vec<String>) -> Result<()> {
    let preview = rest.iter().any(|a| a == "--preview" || a == "-p");
    let heavy = rest.iter().any(|a| a == "--heavy");
    if preview && heavy {
        bail!("--preview and --heavy are mutually exclusive");
    }
    let manifest = repo_root().join("bench").join("Cargo.toml");

    let mut cmd = Command::new(env!("CARGO"));
    cmd.arg("run")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--example")
        .arg("nornir-bench");
    // Restrict to garmr's arms (the harness honors NORNIR_BENCH_ONLY the same way
    // the native nornir runner does).
    cmd.env("NORNIR_BENCH_ONLY", "garmr.");
    if preview {
        cmd.env("NORNIR_BENCH_PREVIEW", "1");
    }
    if heavy {
        cmd.env("NORNIR_BENCH_HEAVY", "1");
    }

    let tier = if preview {
        " (preview)"
    } else if heavy {
        " (heavy — fat-machine scale)"
    } else {
        ""
    };
    eprintln!("running garmr bench arms{tier} ({})", manifest.display());
    let status = cmd.status()?;
    if !status.success() {
        bail!("bench run failed: {status}");
    }
    Ok(())
}