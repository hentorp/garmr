// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-analytics` — statistical/ML analytics over the event lakehouse (M4).
//!
//! - Slice 1: log-line [`templatize`]ation and new-template [`anomaly`]
//!   detection — a shape never seen before becomes a synthetic detection on the
//!   same case path as every other signal.
//! - Slice 2: [`risk`]-based alerting (RBA) — per-host risk accumulated from
//!   adjudicated cases; a host over threshold opens one risk case.
//! - Slice 3: frequency [`baseline`] anomaly — a (host, service) whose hourly
//!   volume is far above its own same-clock-hour norm opens a case.
//!
//! Later phases added the [`ensemble`] detector fusion, environment-aware
//! [`envdetect`], and registry [`drift`] signal. Semantic (embedding) search
//! shipped separately in the `garmr-query`/`garmr-search` crates (Phase 6), not
//! in this analytics crate.

pub mod anomaly;
pub mod baseline;
pub mod drift;
pub mod ensemble;
pub mod envdetect;
pub mod risk;
pub mod silence;
pub mod template;

pub use anomaly::{detect, seed};
pub use baseline::BaselineParams;
pub use risk::{
    risk_detection, score_hosts, score_hosts_with, score_staff, score_staff_with, Contributor,
    OutcomeIndex, RiskObject, RiskParams, WINDOW_HOURS,
};
pub use template::{templatize, Template};