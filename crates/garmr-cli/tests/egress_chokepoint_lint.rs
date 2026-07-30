// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Anti-bypass lint (invariant #2): NO raw egress client may be constructed
//! outside the single chokepoint. A source walk over `crates/*/src` fails the
//! build if a raw outbound-client constructor appears in a file that is neither a
//! gated chokepoint site (which routes its destination through
//! `garmr_core::egress::check`) nor an explicitly-enumerated, documented residual.
//! Adding a NEW egress site anywhere else breaks `cargo test` — forcing it through
//! the chokepoint or a reviewed allowlist edit.

use std::path::{Path, PathBuf};

/// Raw outbound-client construction markers. Covers the idiomatic variants of
/// each constructor, not just one spelling — a client built via `Client::default`,
/// `ClientBuilder`, `reqwest::blocking`, or a non-S3 object_store builder is just
/// as much an un-gated egress site.
const PATTERNS: &[&str] = &[
    // reqwest (async + blocking, all construction spellings)
    "reqwest::Client::new",
    "reqwest::Client::builder",
    "reqwest::Client::default",
    "reqwest::ClientBuilder",
    "reqwest::get(",
    "reqwest::blocking::Client",
    "reqwest::blocking::get(",
    // SMTP
    "AsyncSmtpTransport::",
    "SmtpTransport::",
    // external MCP child + raw process spawn
    "TokioChildProcess::new",
    "process::Command::new",
    // object_store cloud backends (any of them egresses)
    "AmazonS3Builder",
    "GoogleCloudStorageBuilder",
    "MicrosoftAzureBuilder",
    "object_store::http::HttpBuilder",
    // blocking HTTP (control-plane clients)
    "ureq::",
];

/// Repo-relative files permitted to construct a raw egress client.
const ALLOW: &[&str] = &[
    // GATED — route the destination through egress::check at construction.
    "garmr-agent/src/notify.rs",
    "garmr-agent/src/sink.rs",
    "garmr-agent/src/mcp_client.rs",
    "garmr-llm/src/anthropic.rs",
    "garmr-llm/src/openai_compat.rs",
    // The shared LLM client builder + bounded-retry helper: the client is
    // constructed only AFTER build_backend_provider's egress::check passes (both
    // providers delegate to it), and it refuses redirects, so it is as gated as
    // the two provider files above.
    "garmr-llm/src/retry.rs",
    "garmr-cli/src/ioc.rs",
    "garmr-retention/src/s3.rs",
    "garmr-retention/src/ha.rs",
    // OUT-OF-SCOPE residuals (documented in model-routing.md): the SOAR executor
    // (a human-approved subprocess, not garmr's autonomous egress) and the
    // control-plane clients to the loopback daemon / the separate garmr-ui process.
    "garmr-agent/src/executor.rs",
    "garmr-cli/src/cmd/ops.rs",
    "garmr-cli/src/cmd/mod.rs",
    "garmr-cli/src/bin/garmr-mcp.rs",
    // The pgAudit collector (`garmr pgaudit-ship`) is a delivery agent that runs ON
    // the PostgreSQL host and ships audit records INTO garmr's own ingest endpoint —
    // a control-plane client to a garmr endpoint, NOT the SOC's autonomous external
    // egress that the air-gap policy governs. Redirects are refused so the
    // configured ingest URL can't hop to another host.
    "garmr-cli/src/cmd/pgaudit.rs",
    "garmr-ui/src/api/fetch.rs",
    "garmr-ui/src/main.rs",
    "garmr-ui/src/api/mod.rs",
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

#[test]
fn no_raw_egress_client_outside_the_chokepoint() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf(); // crates/garmr-cli → crates
    let mut files = Vec::new();
    walk(&crates, &mut files);

    let mut violations = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        // Only a crate's own src/ (skip tests/, examples/, build scripts).
        if !rel.contains("/src/") || rel.contains("/tests/") {
            continue;
        }
        if ALLOW.contains(&rel.as_str()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(f) else {
            continue;
        };
        for pat in PATTERNS {
            if src.contains(pat) {
                violations.push(format!("{rel}: `{pat}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "raw egress client(s) found OUTSIDE the chokepoint — route through \
         garmr_core::egress::check, or add to the reviewed ALLOW list with a reason:\n{}",
        violations.join("\n")
    );
}
