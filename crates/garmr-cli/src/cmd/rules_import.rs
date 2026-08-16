// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr rules import` — bring community Sigma rules in, with the lint that
//! makes "compatible with community Sigma" a checkable claim.
//!
//! The failure mode this exists for is SILENT: a rule referencing a field
//! garmr's projection never carries parses cleanly, loads cleanly, and then
//! never fires — no error, no warning, just a detection that does not detect.
//! The lint turns that into a printed rejection naming the missing fields,
//! BEFORE the rule is installed and trusted.
//!
//! What the lint proves — and what it does not: it proves a rule's fields CAN
//! match garmr's projection, not that YOUR data carries them. A rule keyed on
//! `cmdline` is matchable, but fires only where an extractor (or collector)
//! actually populates cmdline. The report keeps the two statements separate.
//!
//! No LLM anywhere on this path — imports run identically in the LLM-off
//! posture.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use garmr_detect::{field_class, FieldClass};
use rsigma_parser::ast::Detection as SigDetection;

/// The lint verdict for one rule file.
#[derive(Debug)]
pub(crate) struct RuleLint {
    pub path: PathBuf,
    pub rule_id: String,
    pub title: String,
    /// Fields present in garmr's vocabulary (core or extracted).
    pub known_fields: BTreeSet<String>,
    /// Fields outside the vocabulary — the rule matches only if a collector
    /// ships them verbatim.
    pub unknown_fields: BTreeSet<String>,
    /// Parse/compile failure, when any (such a rule is never installable).
    pub error: Option<String>,
}

impl RuleLint {
    /// Installable without any escape hatch? (Test-facing: the handler prints
    /// the two failure classes separately, which is the whole report.)
    #[cfg(test)]
    pub fn clean(&self) -> bool {
        self.error.is_none() && self.unknown_fields.is_empty()
    }
}

/// Collect every field name a detection references, recursively.
fn collect_fields(d: &SigDetection, out: &mut BTreeSet<String>) {
    match d {
        SigDetection::AllOf(items) => {
            for item in items {
                if let Some(name) = &item.field.name {
                    out.insert(name.clone());
                }
            }
        }
        SigDetection::AnyOf(subs) | SigDetection::And(subs) => {
            for sub in subs {
                collect_fields(sub, out);
            }
        }
        // Keywords match the whole event's strings — always matchable, no field.
        SigDetection::Keywords(_) => {}
        SigDetection::ArrayMatch { field, body, .. } => {
            out.insert(field.clone());
            collect_fields(body, out);
        }
        SigDetection::Conditional { named, .. } => {
            for sub in named.values() {
                collect_fields(sub, out);
            }
        }
    }
}

/// Lint one rule file's text.
pub(crate) fn lint_rule(path: &Path, text: &str) -> RuleLint {
    let mut lint = RuleLint {
        path: path.to_path_buf(),
        rule_id: String::new(),
        title: String::new(),
        known_fields: BTreeSet::new(),
        unknown_fields: BTreeSet::new(),
        error: None,
    };
    let collection = match rsigma_parser::parse_sigma_yaml(text) {
        Ok(c) => c,
        Err(e) => {
            lint.error = Some(format!("parse: {e}"));
            return lint;
        }
    };
    let Some(rule) = collection.rules.first() else {
        lint.error = Some("no rule documents in file".into());
        return lint;
    };
    lint.rule_id = rule.id.clone().unwrap_or_else(|| rule.title.clone());
    lint.title = rule.title.clone();
    // The engine must also COMPILE it (a parseable rule can still fail the
    // evaluator's stricter checks) — same gate serve applies at load.
    if let Err(e) = garmr_detect::Detector::from_yaml(text) {
        lint.error = Some(format!("compile: {e}"));
        return lint;
    }
    let mut fields = BTreeSet::new();
    for d in rule.detection.named.values() {
        collect_fields(d, &mut fields);
    }
    for f in fields {
        match field_class(&f) {
            FieldClass::Unknown => lint.unknown_fields.insert(f),
            _ => lint.known_fields.insert(f),
        };
    }
    lint
}

/// Recursively collect .yml/.yaml files under `path` (or the file itself).
fn rule_files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(out);
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .flatten()
        {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yml" || e == "yaml")
            {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The import command. Dry-run by default: print the lint report, install
/// nothing. `--write` installs the clean rules (verbatim YAML + a provenance
/// header) into the rules dir and registers each in the registry.
pub(crate) async fn rules_import(
    cli: &crate::Cli,
    path: &Path,
    write: bool,
    allow_unknown: bool,
) -> Result<()> {
    let cfg = crate::load_config(cli)?;
    let files = rule_files(path)?;
    if files.is_empty() {
        println!("no .yml/.yaml files under {}", path.display());
        return Ok(());
    }

    let mut clean: Vec<(RuleLint, String)> = Vec::new();
    let mut rejected = 0usize;
    for f in &files {
        let text =
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        let lint = lint_rule(f, &text);
        if let Some(e) = &lint.error {
            println!("REJECT  {:<40} {e}", short(&lint.path));
            rejected += 1;
            continue;
        }
        if !lint.unknown_fields.is_empty() && !allow_unknown {
            // The whole point: the silent-never-match class becomes a printed
            // rejection naming exactly which fields the projection lacks.
            println!(
                "REJECT  {:<40} fields outside garmr's projection: {} — such a rule \
                 matches ONLY if your collectors ship these verbatim; re-run with \
                 --allow-unknown to install anyway",
                short(&lint.path),
                lint.unknown_fields
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            rejected += 1;
            continue;
        }
        let note = if lint.unknown_fields.is_empty() {
            String::new()
        } else {
            format!(
                " (unknown fields allowed: {})",
                lint.unknown_fields
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        println!(
            "OK      {:<40} id={} fields=[{}]{note}",
            short(&lint.path),
            lint.rule_id,
            lint.known_fields
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
        clean.push((lint, text));
    }
    println!(
        "\n{} rule(s) importable, {} rejected{}",
        clean.len(),
        rejected,
        if write {
            ""
        } else {
            " — dry run; re-run with --write to install"
        }
    );
    if !write || clean.is_empty() {
        return Ok(());
    }

    // Install: verbatim YAML under rules_dir/imported/, provenance header on
    // top (comments — the rule body itself is untouched, so its content digest
    // is reproducible from the source), one registry record each.
    let store = garmr_store::Store::open(&cfg)
        .await
        .context("opening store")?;
    let dest_dir = cfg.detect.rules_dir.join("imported");
    std::fs::create_dir_all(&dest_dir)?;
    let mut installed = 0usize;
    for (lint, text) in &clean {
        let digest = blake3::hash(text.as_bytes()).to_hex().to_string();
        let header = format!(
            "# imported-by: garmr rules import\n# imported-from: {}\n# imported-at: {}\n# content-blake3: {}\n",
            lint.path.display(),
            chrono::Utc::now().to_rfc3339(),
            digest
        );
        let fname = format!(
            "{}.yml",
            lint.rule_id
                .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "-")
        );
        let dest = dest_dir.join(&fname);
        if dest.exists() {
            println!("skip    {} already installed", fname);
            continue;
        }
        std::fs::write(&dest, format!("{header}{text}"))?;
        let rec = garmr_core::RegistryRecord {
            id: uuid::Uuid::new_v4().to_string(),
            kind: garmr_core::RegistryKind::Rule,
            name: lint.rule_id.clone(),
            version: "imported-1".into(),
            content_digest: digest,
            parent_version: None,
            rationale: format!("community import from {}", lint.path.display()),
            eval_run_refs: Vec::new(),
            approval: garmr_core::ApprovalState::Draft,
            source: garmr_core::RegistrySource::Operator,
            registered_at: chrono::Utc::now(),
            registered_by: "rules-import".into(),
            audit_id: None,
            spec: serde_json::json!({ "installed_as": dest.display().to_string() }),
        };
        match store.state.register_record(&rec) {
            Ok(_) => {}
            Err(e) => println!("warn    {} registry record failed: {e}", lint.rule_id),
        }
        installed += 1;
        println!("install {} -> {}", lint.rule_id, dest.display());
    }
    println!("\ninstalled {installed} rule(s) — they load at the next `serve` start");
    Ok(())
}

fn short(p: &Path) -> String {
    p.file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("?")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_projection_compatible_rule_lints_clean() {
        let rule = r#"
title: SSH failures from one address
id: import-test-clean
logsource:
    product: linux
detection:
    selection:
        source.ip: '203.0.113.7'
        message|contains: 'Failed password'
    condition: selection
level: medium
"#;
        let lint = lint_rule(Path::new("clean.yml"), rule);
        assert!(lint.clean(), "{lint:?}");
        assert!(lint.known_fields.contains("source.ip"));
        assert!(lint.known_fields.contains("message"));
    }

    #[test]
    fn the_silent_never_match_class_is_named_not_swallowed() {
        // A Windows community rule keyed on fields garmr's projection never
        // carries: parses fine, compiles fine, and would never fire — the
        // exact class the lint exists to catch, naming the fields.
        let rule = r#"
title: Suspicious LSASS access
id: import-test-windows
logsource:
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess: '0x1010'
    condition: selection
level: high
"#;
        let lint = lint_rule(Path::new("win.yml"), rule);
        assert!(lint.error.is_none(), "it parses and compiles: {lint:?}");
        assert!(!lint.clean());
        assert!(lint.unknown_fields.contains("TargetImage"));
        assert!(lint.unknown_fields.contains("GrantedAccess"));
    }

    #[test]
    fn keyword_rules_are_matchable_without_any_field() {
        // Keywords scan every string value — no field reference to lint.
        let rule = r#"
title: Keyword hunt
id: import-test-keywords
logsource:
    product: linux
detection:
    keywords:
        - 'wget http'
    condition: keywords
level: low
"#;
        let lint = lint_rule(Path::new("kw.yml"), rule);
        assert!(lint.clean(), "{lint:?}");
    }

    #[test]
    fn a_broken_file_is_a_named_rejection() {
        let lint = lint_rule(Path::new("broken.yml"), "title: [unclosed");
        assert!(lint.error.is_some());
    }
}
