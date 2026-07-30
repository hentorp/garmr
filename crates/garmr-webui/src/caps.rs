// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The client side of the capability manifest (`GET /api/capabilities`).
//!
//! Fetched once on load into a reactive signal. The shell reads it to badge or
//! dim navigation, and every view reads its own feature state to render a clear
//! *disabled / degraded / not-configured* panel instead of a dead control or a
//! generic error. It is advisory only — the server authorizes every write
//! independently; the manifest just stops us drawing a button that can't work.

use serde_json::Value;

/// One feature's runtime state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureState {
    /// `healthy` | `degraded` | `disabled` | `not_configured` | `unknown`.
    pub state: String,
    pub reason: Option<String>,
}

impl FeatureState {
    pub fn healthy(&self) -> bool {
        self.state == "healthy"
    }
    /// A short human label for the state.
    pub fn label(&self) -> &str {
        match self.state.as_str() {
            "healthy" => "healthy",
            "degraded" => "degraded",
            "disabled" => "disabled",
            "not_configured" => "not configured",
            _ => "unknown",
        }
    }
    /// The reserved status class for this state (paired with the label, never
    /// colour-alone).
    pub fn class(&self) -> &'static str {
        match self.state.as_str() {
            "healthy" => "pass",
            "degraded" => "warn",
            "disabled" | "not_configured" => "dim",
            _ => "dim",
        }
    }
}

/// The parsed manifest. Backed by the raw JSON so an added backend field never
/// breaks the console.
#[derive(Clone, Debug)]
pub struct Caps {
    raw: Value,
}

impl Caps {
    pub fn from_value(raw: Value) -> Self {
        Self { raw }
    }

    /// A feature's state by key; `unknown` when the manifest omits it (fail open
    /// for reads — the view still renders, the server still authorizes).
    pub fn feature(&self, key: &str) -> FeatureState {
        let f = self.raw.get("features").and_then(|f| f.get(key));
        FeatureState {
            state: f
                .and_then(|f| f.get("state"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            reason: f
                .and_then(|f| f.get("reason"))
                .and_then(Value::as_str)
                .map(String::from),
        }
    }

    pub fn healthy(&self, key: &str) -> bool {
        self.feature(key).healthy()
    }
    /// True unless the feature is explicitly `disabled` (degraded/not_configured
    /// still render, with a banner).
    pub fn usable(&self, key: &str) -> bool {
        self.feature(key).state != "disabled"
    }

    fn flag(&self, key: &str) -> bool {
        self.raw.get(key).and_then(Value::as_bool).unwrap_or(false)
    }
    pub fn airgap(&self) -> bool {
        self.flag("airgap")
    }
    pub fn read_only(&self) -> bool {
        self.flag("read_only")
    }
    pub fn writes_enabled(&self) -> bool {
        self.raw
            .get("writes_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true)
    }
    pub fn passkey_enabled(&self) -> bool {
        self.raw
            .get("auth")
            .and_then(|a| a.get("passkey_enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
    pub fn auth_enabled(&self) -> bool {
        self.raw
            .get("auth")
            .and_then(|a| a.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
    pub fn ha_role(&self) -> String {
        self.raw
            .get("ha_role")
            .and_then(Value::as_str)
            .unwrap_or("leader")
            .to_string()
    }
    pub fn backend_version(&self) -> String {
        self.raw
            .get("backend_version")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string()
    }
}