// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Scheduled hunt definitions: one TOML file per hunt in `detect.hunts_dir`,
//! loaded + de-duplicated at startup. Pure config parsing, independent of the
//! agent loop in [`super`].

/// A scheduled hunt definition (one TOML file in `detect.hunts_dir`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HuntDef {
    /// Stable id, e.g. `beacon-outbound`.
    pub id: String,
    /// The hypothesis handed to the agent, in prose.
    pub hypothesis: String,
    /// Run every N seconds (default 6h). Wall-clock, best effort.
    #[serde(default = "default_schedule_secs")]
    pub schedule_secs: u64,
}

fn default_schedule_secs() -> u64 {
    6 * 3600
}

/// Load every `*.toml` hunt definition from a directory. A missing dir means
/// no scheduled hunts; an unparsable file is skipped loudly.
pub fn load_hunts(dir: &std::path::Path) -> Vec<HuntDef> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|s| toml::from_str::<HuntDef>(&s).map_err(|e| e.to_string()))
        {
            Ok(def) => {
                if def.id.trim().is_empty() || def.hypothesis.trim().is_empty() {
                    tracing::warn!(file = %path.display(), "hunt definition skipped: empty id/hypothesis");
                    continue;
                }
                out.push(def);
            }
            Err(e) => tracing::warn!(file = %path.display(), error = %e, "hunt definition skipped"),
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    // Duplicate ids would share schedule state and dedup keys — keep the first,
    // drop the rest loudly.
    out.dedup_by(|b, a| {
        let dup = a.id == b.id;
        if dup {
            tracing::warn!(id = %b.id, "duplicate hunt id — later definition ignored");
        }
        dup
    });
    out
}
