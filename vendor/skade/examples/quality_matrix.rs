//! Standalone quality-matrix runner for THIS repo (skade).
//!
//! Runs the reusable `nornir-testmatrix` engine over the current directory,
//! persists the rows to `target/quality-matrix.jsonl`, and prints the rendered
//! human matrix. A human or CI can get skade's own quality matrix with:
//!
//! ```text
//! cargo run --example quality_matrix
//! ```
//!
//! NOTE: this shells `cargo build/test/clippy/...` under the hood (one process
//! per aspect), so it is intentionally NOT part of `cargo test` — running
//! cargo-inside-cargo is slow and recursive. Run it on demand only.

// `nornir-testmatrix` is an OPTIONAL dependency (linked only under
// `--features testmatrix`). Without the feature the runner cannot exist, so we
// compile a tiny stub `main` that tells the caller how to enable it, keeping a
// plain `cargo build --examples` green.
#[cfg(not(feature = "testmatrix"))]
fn main() {
    eprintln!(
        "quality_matrix needs the `testmatrix` feature: \
         cargo run --features testmatrix --example quality_matrix"
    );
}

#[cfg(feature = "testmatrix")]
use std::path::Path;

#[cfg(feature = "testmatrix")]
use nornir_testmatrix::{Aspect, JsonFileSink, TestSink, render_matrix};

#[cfg(feature = "testmatrix")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = Path::new(".");

    eprintln!("running quality matrix (Aspect::DEFAULT) over {repo_root:?} ...");
    let rows = nornir_testmatrix::run_full_matrix(repo_root, Aspect::DEFAULT);

    let out_path = Path::new("target").join("quality-matrix.jsonl");
    let sink = JsonFileSink::new(&out_path);
    sink.append(&rows)?;
    eprintln!("wrote {} rows -> {}", rows.len(), out_path.display());

    // Self-test emit: feed the runner's own real result (did it produce rows
    // for the default aspects?) into the matrix. Gated so a release build that
    // somehow runs this example still strips the emit to a no-op.
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "quality_matrix",
        "run_full_matrix_default_aspects",
        !rows.is_empty(),
        &format!(
            "ran {} default aspects → {} rows",
            Aspect::DEFAULT.len(),
            rows.len()
        ),
    );

    println!("{}", render_matrix(&rows));
    Ok(())
}
