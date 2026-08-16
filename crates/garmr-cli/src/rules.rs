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
/// The live, swappable rule set: the compiled detector and the id→text map,
/// swapped TOGETHER because they are two views of the same directory — a
/// reload that replaced one but not the other would detect with new rules
/// while the audit trail's get_rule resolved old text (or vice versa).
///
/// Readers take a cheap snapshot (`Arc` clone under a read lock) per batch;
/// a reload swaps atomically. A reload that fails to PARSE keeps the previous
/// set: a SIEM whose detection plane vanishes because an operator fat-fingered
/// one YAML file is worse than one that keeps detecting on yesterday's rules
/// and says so loudly.
pub struct LiveRules {
    detector: std::sync::RwLock<std::sync::Arc<Detector>>,
    /// Shared with the agent's get_rule tool — the SAME handle, so the tool
    /// can never resolve text from a different generation than the detector.
    texts: std::sync::Arc<std::sync::RwLock<std::sync::Arc<HashMap<String, String>>>>,
}

impl LiveRules {
    /// Load the directory and wrap it live.
    pub fn load_live(dir: &Path) -> Result<std::sync::Arc<Self>> {
        let (detector, map) = load(dir)?;
        Ok(std::sync::Arc::new(Self {
            detector: std::sync::RwLock::new(std::sync::Arc::new(detector)),
            texts: std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(map))),
        }))
    }

    /// The current detector snapshot.
    pub fn detector(&self) -> std::sync::Arc<Detector> {
        self.detector
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The shared rule-text handle (for the agent's get_rule tool).
    pub fn texts_handle(
        &self,
    ) -> std::sync::Arc<std::sync::RwLock<std::sync::Arc<HashMap<String, String>>>> {
        self.texts.clone()
    }

    /// Reload from `dir`. Returns (rules_before, rules_after). On ANY failure
    /// the previous set stays installed and keeps detecting.
    ///
    /// STRICTER than the startup load: startup tolerates per-file parse errors
    /// (best-effort — a daemon that refuses to boot over one bad file is an
    /// outage), but a reload is an operator actively changing rules NOW, and
    /// silently skipping their broken file would report success while their
    /// edit is absent — rules_before == rules_after and nobody the wiser. A
    /// tree with parse errors refuses to swap, naming the files.
    pub fn reload(&self, dir: &Path) -> Result<(usize, usize)> {
        let before = self.detector().rule_count();
        let collection = rsigma_parser::parse_sigma_directory(dir)
            .map_err(|e| Error::Detect(format!("parsing rules in {}: {e}", dir.display())))?;
        if !collection.errors.is_empty() {
            return Err(Error::Detect(format!(
                "{} file(s) failed to parse — refusing to swap (the previous rule set \
                 is still active): {}",
                collection.errors.len(),
                collection.errors.join("; ")
            )));
        }
        let (detector, map) = load(dir)?;
        let after = detector.rule_count();
        // Two locks, taken in a fixed order, held only for the pointer swaps.
        *self.detector.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(detector);
        *self.texts.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(map);
        Ok((before, after))
    }
}

pub fn load(dir: &Path) -> Result<(Detector, HashMap<String, String>)> {
    let detector = Detector::load(dir)?;
    let mut map = HashMap::new();

    // RECURSIVE, matching parse_sigma_directory: the Detector already loads
    // rules from subdirectories (rules/imported/, future packs/), and an id
    // missing from this map means the audit trail cannot resolve which rule
    // text produced a detection — the map must cover exactly what loads.
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| Error::Detect(format!("read rules dir {}: {e}", d.display())))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_A: &str = "title: A\nid: live-a\nlogsource:\n    product: linux\ndetection:\n    selection:\n        message|contains: 'marker-a'\n    condition: selection\nlevel: low\n";
    const RULE_B: &str = "title: B\nid: live-b\nlogsource:\n    product: linux\ndetection:\n    selection:\n        message|contains: 'marker-b'\n    condition: selection\nlevel: low\n";

    fn tmpdir() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "garmr-liverules-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn ev(msg: &str) -> garmr_core::Event {
        garmr_core::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            service: "s".into(),
            source: "src".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: msg.into(),
            fields: Default::default(),
        }
    }

    #[test]
    fn reload_swaps_rules_and_texts_together() {
        let dir = tmpdir();
        std::fs::write(dir.join("a.yml"), RULE_A).unwrap();
        let live = LiveRules::load_live(&dir).unwrap();
        assert_eq!(live.detector().rule_count(), 1);
        assert!(live.detector().evaluate(&ev("has marker-a inside")).len() == 1);

        std::fs::write(dir.join("b.yml"), RULE_B).unwrap();
        let (before, after) = live.reload(&dir).unwrap();
        assert_eq!((before, after), (1, 2));
        assert_eq!(
            live.detector().evaluate(&ev("has marker-b inside")).len(),
            1,
            "the NEW rule fires without a restart"
        );
        // And the text map follows the same generation.
        let texts = live.texts_handle();
        let texts = texts.read().unwrap();
        assert!(
            texts.contains_key("live-b"),
            "get_rule resolves the new rule"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_reload_keeps_the_previous_set_detecting() {
        // The availability property: a fat-fingered YAML file must not take the
        // detection plane down. The reload errors, the OLD rules keep firing.
        let dir = tmpdir();
        std::fs::write(dir.join("a.yml"), RULE_A).unwrap();
        let live = LiveRules::load_live(&dir).unwrap();

        std::fs::write(dir.join("broken.yml"), "title: [unclosed\ndetection: 5\n").unwrap();
        assert!(live.reload(&dir).is_err(), "a broken tree must not swap in");
        assert_eq!(live.detector().rule_count(), 1, "previous set intact");
        assert_eq!(
            live.detector().evaluate(&ev("has marker-a inside")).len(),
            1,
            "and it still detects"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
