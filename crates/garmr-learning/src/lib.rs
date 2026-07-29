// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-learning` — the safe learning plane (Phase 8).
//!
//! An OFFLINE, LLM-free champion/challenger loop over immutable, content-addressed
//! [`garmr_core::DatasetSnapshot`]s. It fits and evaluates a candidate detection
//! policy (a *challenger*) against the live one (the *champion*), and refuses any
//! challenger that raises dangerous false negatives — but it NEVER mutates
//! protected state: a challenger lands only as a Draft registry record that a
//! human promotes through the existing audited channel (invariants #2/#3).
//!
//! The crate is pure and self-contained: its only dependencies are the pure
//! `garmr-core` types, the local `garmr-store`, and the pure `garmr-analytics`
//! scorers. No `garmr-agent`/`garmr-llm`, no network — so it ships in the base
//! build and does zero egress.
//!
//! Modules land across the Phase-8 commits: [`dataset`] (the Trusted-only,
//! poison-excluded, temporally-split builder), then the challenger replay,
//! champion/challenger comparison, and the bounded producer.

pub mod challenger;
pub mod compare;
pub mod dataset;
pub mod producer;
pub mod reflect;

pub use challenger::{replay, score_row, ChallengerPolicy, ChallengerScore};
pub use compare::{compare, promotable, ChallengerReport, PromotableVerdict, PromotionPolicy};
pub use dataset::{build_snapshot, collect_inputs, DatasetInputs};
pub use producer::{challenger_to_spec, fit_challenger, Challenger, SearchConfig};
pub use reflect::{reflect, validate_reflection, ReflectPolicy};