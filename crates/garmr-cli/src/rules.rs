// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Load the Sigma rule set both as an evaluatable [`Detector`] and as a
//! `rule_id -> YAML` map for the agent's `get_rule` tool. The map keys on the
//! Sigma `id:` field, matching the `rule_id` a [`Detection`] carries.

use std::collections::HashMap;
use std::path::Path;

use garmr_core::{Error, Result};
use garmr_detect::Detector;

/// Returns the loaded detector and a `rule_id -> YAML text` map.
pub fn load(dir: &Path) -> Result<(Detector, HashMap<String, String>)> {
    let detector = Detector::load(dir)?;
    let mut map = HashMap::new();

    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::Detect(format!("read rules dir {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "yml" || e == "yaml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(id) = extract_id(&text) {
                map.insert(id, text);
            }
        }
    }
    Ok((detector, map))
}

/// Pull the top-level `id:` value out of a Sigma YAML document (cheap scan —
/// avoids a full YAML parse just to index the file).
fn extract_id(yaml: &str) -> Option<String> {
    for line in yaml.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("id:") {
            let v = rest.trim().trim_matches(|c| c == '"' || c == '\'');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}