// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr reflect` — the offline, LLM-free mistake-learning loop (Phase 9).
//!
//! Distil analyst-authored mistakes into a Draft procedural-memory LessonSet
//! (fail-closed on any injection/weakening/cap finding), register it in the
//! existing registry, and stop there. A lesson goes LIVE only through the
//! existing human-admin-gated, audited `garmr registry promote lesson triage
//! <version>` channel — nothing here touches the serving agent (invariants
//! #2/#3). Promotion re-validates the lesson at the approval boundary.

use super::*;

use garmr_audit::action::LESSON_PROPOSE;
use garmr_core::{category_tag, LessonSet, LessonSetSpec, RegistryKind};
use garmr_learning::{reflect, validate_reflection, ReflectPolicy};

use crate::cli::ReflectCmd;

fn short(d: &str) -> &str {
    &d[..d.len().min(12)]
}

pub(crate) async fn reflect_cmd(cli: &Cli, what: &ReflectCmd) -> Result<()> {
    match what {
        ReflectCmd::Build { hours, min_support } => reflect_build(cli, *hours, *min_support).await,
        ReflectCmd::List => reflect_list(cli).await,
        ReflectCmd::Show { version } => reflect_show(cli, version).await,
        ReflectCmd::Verify { version } => reflect_verify(cli, version).await,
    }
}

async fn reflect_build(cli: &Cli, hours: i64, min_support: usize) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable)")?;
    let now = Utc::now();
    let hours = hours.clamp(0, 8_760_000);
    let cutoff = now - chrono::Duration::hours(hours);
    let mistakes: Vec<_> = store
        .state
        .list_mistakes()?
        .into_iter()
        .filter(|m| m.created_at >= cutoff)
        .collect();
    let decisions = store.state.list_decisions()?;
    // Phase 13: the analyst's normal adjudication also feeds MissedEvidence —
    // decisions flagging missed evidence and false negatives discovered in the
    // window, so an overturn/miss teaches without a separately-filed mistake.
    let false_negatives: Vec<_> = store
        .state
        .list_false_negatives()?
        .into_iter()
        .filter(|f| f.created_at >= cutoff)
        .collect();
    let policy = ReflectPolicy {
        min_support,
        lookback_hours: hours,
    };
    let set = reflect(
        &mistakes,
        &decisions,
        &false_negatives,
        Some(cutoff),
        &policy,
    );
    if set.is_empty() {
        println!("no lessons drafted (no category reached min_support={min_support} corroborated mistakes)");
        return Ok(());
    }
    // FAIL-CLOSED gate: a lesson that could smuggle an injection or weaken
    // detection never even becomes a Draft.
    let findings = validate_reflection(&set);
    if !findings.is_empty() {
        eprintln!(
            "refusing to draft — {} validation finding(s):",
            findings.len()
        );
        for f in &findings {
            eprintln!("  [{}] {}", f.kind, f.detail);
        }
        anyhow::bail!("lesson set failed validation");
    }
    let digest = set.digest();
    let version = format!("l-{}", short(&digest));
    let spec = LessonSetSpec {
        lessons: set.lessons.clone(),
        mistake_count: mistakes.len() as u32,
        window_from_us: cutoff.timestamp_micros(),
        window_to_us: now.timestamp_micros(),
        reflection_version: "phase9-mlp-v1".into(),
    };
    ensure_registered_local(
        &store,
        &cfg,
        RegistryKind::Lesson,
        "triage",
        &version,
        &digest,
        LESSON_PROPOSE,
        serde_json::to_value(&spec).unwrap_or_default(),
    )?;
    println!(
        "drafted Draft lesson set  lesson triage@{version}  ({} lesson(s) from {} mistake(s))",
        set.lessons.len(),
        mistakes.len()
    );
    for l in &set.lessons {
        println!(
            "  - [{}] support {} — {}",
            category_tag(l.category),
            l.support,
            l.guidance
        );
    }
    println!(
        "\nto approve (human-gated, audited, re-validated at the boundary): garmr registry promote lesson triage {version} --channel production"
    );
    Ok(())
}

async fn reflect_list(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let recs = store.state.list_kind(RegistryKind::Lesson)?;
    if recs.is_empty() {
        println!("(no lesson sets)");
    }
    for r in recs {
        let n = serde_json::from_value::<LessonSetSpec>(r.spec.clone())
            .map(|s| s.lessons.len())
            .unwrap_or(0);
        println!(
            "{}  {}  {} lesson(s)  {:?}",
            r.version, r.name, n, r.approval
        );
    }
    Ok(())
}

fn load_spec(store: &Store, version: &str) -> Result<LessonSetSpec> {
    let rec = store
        .state
        .get_record(RegistryKind::Lesson, "triage", version)?
        .context("no such lesson set")?;
    serde_json::from_value(rec.spec).context("lesson record spec will not decode")
}

async fn reflect_show(cli: &Cli, version: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let spec = load_spec(&store, version)?;
    println!(
        "lesson set triage@{version}  ({} lesson(s))",
        spec.lessons.len()
    );
    println!(
        "  from {} mistake(s), reflection {}",
        spec.mistake_count, spec.reflection_version
    );
    for l in &spec.lessons {
        println!(
            "  - [{}] support {} — {}",
            category_tag(l.category),
            l.support,
            l.guidance
        );
    }
    Ok(())
}

async fn reflect_verify(cli: &Cli, version: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let rec = store
        .state
        .get_record(RegistryKind::Lesson, "triage", version)?
        .context("no such lesson set")?;
    let spec: LessonSetSpec =
        serde_json::from_value(rec.spec.clone()).context("lesson record spec will not decode")?;
    let set = LessonSet {
        lessons: spec.lessons.clone(),
    };
    let digest_ok = set.digest() == rec.content_digest;
    // Scan per-lesson guidance only (never the render() framing).
    let findings = garmr_core::validate_lesson_set(&spec.lessons, garmr_core::LESSON_CAPS);
    println!("digest: {}", if digest_ok { "OK" } else { "MISMATCH" });
    if findings.is_empty() {
        println!("validation: OK ({} lesson(s))", spec.lessons.len());
    } else {
        println!("validation: {} finding(s)", findings.len());
        for f in &findings {
            println!("  [{}] {}", f.kind, f.detail);
        }
    }
    if !digest_ok || !findings.is_empty() {
        anyhow::bail!("lesson set failed verification");
    }
    Ok(())
}
