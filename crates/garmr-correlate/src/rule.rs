// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The correlation rule TOML shape, loader, and placeholder substitution.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    /// MITRE ATT&CK technique(s), e.g. "T1110->T1078".
    #[serde(default)]
    pub attack: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    /// How often the rule runs (scheduled mode).
    #[serde(default = "default_schedule")]
    pub schedule_secs: u64,
    /// How far back `{since_us}` reaches; defaults to the schedule interval.
    #[serde(default)]
    pub window_secs: Option<u64>,
    /// Suppress repeat hits for the same key for this long (honoured by the
    /// caller via the store's suppression window).
    #[serde(default = "default_realert")]
    pub realert_secs: u64,
    pub message: String,
    pub sql: String,
    /// Operator-tunable substitutions for the SQL, on top of
    /// `{since_us}`/`{now_us}`. A `[params]` table in the rule TOML — e.g.
    /// `min_lookups = 50`, `tz_offset = 2`, `day_start = 6` — is substituted as
    /// `{min_lookups}` etc. at render time, so environment-specific thresholds,
    /// timezone offsets and working-hours live as CONFIG DATA rather than baked
    /// into the SQL string (making a rule portable across deployments by editing
    /// values, not SQL). Values render without quotes (integer `50` → `50`);
    /// keep params to numbers / simple tokens. Rules are operator-authored and
    /// already guarded to SELECT/WITH, so this is not a new trust boundary.
    #[serde(default)]
    pub params: BTreeMap<String, toml::Value>,
}

/// Render a param value into the SQL without TOML quoting (an integer becomes a
/// bare `50`, a string its raw text).
fn param_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        other => other.to_string().trim_matches('"').to_string(),
    }
}

fn default_severity() -> String {
    "warning".into()
}
fn default_schedule() -> u64 {
    300
}
fn default_realert() -> u64 {
    3600
}

impl Rule {
    /// The correlation window in seconds (falls back to the schedule interval).
    pub fn window_secs(&self) -> u64 {
        self.window_secs.unwrap_or(self.schedule_secs)
    }

    /// Substitute the run-time placeholders and the operator `[params]` into the
    /// rule's SQL. Run-time placeholders (`{since_us}`/`{now_us}`) are applied
    /// first; then every `[params]` entry substitutes its `{name}`.
    pub fn render_sql(&self, since_us: i64, now_us: i64) -> String {
        let mut sql = self
            .sql
            .replace("{since_us}", &since_us.to_string())
            .replace("{now_us}", &now_us.to_string());
        for (k, v) in &self.params {
            sql = sql.replace(&format!("{{{k}}}"), &param_str(v));
        }
        sql
    }
}

/// Load and parse every `*.toml` rule under `dir`, sorted by id for stable
/// ordering. Bad files are logged and skipped.
pub fn load_rules(dir: &Path) -> Vec<Rule> {
    let mut rules = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        tracing::warn!(dir = %dir.display(), "correlation rules dir not found");
        return rules;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("toml") {
            continue;
        }
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|s| toml::from_str::<Rule>(&s).map_err(|e| e.to_string()))
        {
            Ok(r) => rules.push(r),
            Err(err) => {
                tracing::warn!(file = %path.display(), error = %err, "bad correlation rule")
            }
        }
    }
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_defaults() {
        let r: Rule =
            toml::from_str("id = \"t\"\ntitle = \"T\"\nmessage = \"m\"\nsql = \"SELECT 1\"\n")
                .unwrap();
        assert_eq!(r.schedule_secs, 300);
        assert_eq!(r.severity, "warning");
        assert_eq!(r.window_secs(), 300);
    }

    #[test]
    fn substitutes_placeholders() {
        let r: Rule = toml::from_str(
            "id=\"t\"\ntitle=\"T\"\nmessage=\"m\"\nsql=\"SELECT * WHERE event_ts > to_timestamp_micros({since_us}) AND x < {now_us}\"\n",
        )
        .unwrap();
        let sql = r.render_sql(123, 456);
        assert!(sql.contains("to_timestamp_micros(123)"));
        assert!(sql.contains("< 456"));
    }

    #[test]
    fn substitutes_operator_params_as_bare_values() {
        // A [params] table substitutes {name} with the un-quoted value, so a
        // threshold / timezone offset lives as config data, not baked SQL.
        let r: Rule = toml::from_str(
            "id=\"t\"\ntitle=\"T\"\nmessage=\"m\"\nsql=\"HAVING count(*) >= {min_lookups} AND h + {tz_offset} >= {day_end}\"\n[params]\nmin_lookups = 50\ntz_offset = 2\nday_end = 18\n",
        )
        .unwrap();
        let sql = r.render_sql(0, 0);
        assert_eq!(sql, "HAVING count(*) >= 50 AND h + 2 >= 18");
    }
}
