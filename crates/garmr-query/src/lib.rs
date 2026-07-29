// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 6 — the hybrid-search **Query IR**.
//!
//! A typed [`HybridQuery`] the agent (or CLI/API) composes to retrieve events by
//! fusing three signals: a **structured** filter (typed per-column predicates), a
//! **full-text** clause (Tantivy BM25), and a **semantic** clause (local
//! embedding cosine). It is SAFE BY CONSTRUCTION — the structured filter compiles
//! to bounded, read-only SQL whose every identifier is a compile-time constant
//! and whose every value reaches SQL only inside a doubled-quote literal, so no
//! model-authored string is ever an injection or exfil surface (a strict
//! improvement over handing the model a raw SQL string).
//!
//! The crate is layered like `garmr-graph`: the pure default layer (this module,
//! the SQL compiler, the fusion math, and the `SemanticSearch` trait) needs no
//! store and is fully unit-testable; the `store` feature adds the async
//! `Executor` that runs the IR against the lakehouse + Tantivy + a
//! `SemanticSearch` impl.

mod compile;
mod fuse;
mod ir;
mod result;

#[cfg(feature = "store")]
mod exec;

pub use compile::{like_escape, sql_lit, PROJECTION};
pub use fuse::{fuse, Row, SemanticHit, SemanticSearch};
pub use ir::*;
pub use result::*;

#[cfg(feature = "store")]
pub use exec::Executor;