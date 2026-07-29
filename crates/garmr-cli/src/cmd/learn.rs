// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr learn` — the offline, LLM-free safe-learning loop (Phase 8).
//!
//! Build an immutable, content-addressed dataset from Trusted-only, poison-
//! excluded labels; fit + evaluate a challenger detector-config against the live
//! champion on a never-fit Test holdout; and shadow the divergence. Every stage
//! is a local, egress-free computation over the store. The only thing that goes
//! LIVE is a challenger, and ONLY through the existing human-admin-gated, audited
//! `garmr registry promote detector_config …` channel — nothing here mutates the
//! serving policy (invariants #2/#3).

use super::*;

use garmr_analytics::ensemble::EnsemblePolicy;
use garmr_analytics::risk::RiskParams;
use garmr_audit::action::{DATASET_CREATE, EVAL_RUN, THRESHOLD_PROPOSE};
use garmr_core::{
    is_dangerous, DatasetSnapshot, DatasetVersions, DetectorConfigSpec, RegistryKind, SeverityBand,
    SnapshotWindow, SplitBucket,
};
use garmr_learning::{
    build_snapshot, challenger_to_spec, collect_inputs, compare, fit_challenger, promotable,
    replay, score_row, ChallengerPolicy, ChallengerScore, PromotionPolicy, SearchConfig,
};

use crate::cli::LearnCmd;

/// The champion policy = EXACTLY what serve builds in `env_detect_loop`
/// (pipeline.rs): the ensemble coefficients from `environment.detect`, the bands
/// the hardcoded default; the RBA knobs verbatim from `[detect]`.
fn champion_policy(cfg: &garmr_core::Config) -> ChallengerPolicy {
    ChallengerPolicy {
        ensemble: EnsemblePolicy {
            crit_coef: cfg.environment.detect.crit_coef,
            corr_coef: cfg.environment.detect.corr_coef,
            ..Default::default()
        },
        risk: RiskParams {
            threshold: cfg.detect.risk_threshold,
            halflife_hours: cfg.detect.risk_halflife_hours,
            realert_secs: cfg.detect.risk_realert_secs,
            prediction_discount: cfg.detect.prediction_discount,
        },
    }
}

fn short(d: &str) -> &str {
    &d[..d.len().min(12)]
}

fn find_dataset(store: &Store, prefix: &str) -> Result<Option<DatasetSnapshot>> {
    Ok(store
        .state
        .list_datasets()?
        .into_iter()
        .find(|d| d.digest.starts_with(prefix)))
}

fn score_json(s: &ChallengerScore) -> serde_json::Value {
    serde_json::json!({
        "rows": s.rows, "tp": s.tp, "fp": s.fp, "tn": s.tn, "fn": s.fn_,
        "precision": s.precision, "recall": s.recall,
        "precision_at_budget": s.precision_at_budget,
        "brier_est": s.brier_est, "dangerous_fn": s.dangerous_fn,
    })
}

pub(crate) async fn learn_cmd(cli: &Cli, what: &LearnCmd) -> Result<()> {
    match what {
        LearnCmd::DatasetBuild {
            hours,
            train,
            val,
            name,
        } => dataset_build(cli, *hours, *train, *val, name).await,
        LearnCmd::DatasetList => dataset_list(cli).await,
        LearnCmd::DatasetShow { digest } => dataset_show(cli, digest).await,
        LearnCmd::DatasetVerify { digest } => dataset_verify(cli, digest).await,
        LearnCmd::ChallengerFit {
            dataset,
            alert_budget,
        } => challenger_fit(cli, dataset, *alert_budget).await,
        LearnCmd::ChallengerEval {
            dataset,
            challenger,
            alert_budget,
        } => challenger_eval(cli, dataset, challenger.as_deref(), *alert_budget).await,
        LearnCmd::Shadow {
            dataset,
            challenger,
        } => shadow(cli, dataset, challenger).await,
    }
}

async fn dataset_build(cli: &Cli, hours: i64, train: f64, val: f64, name: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable)")?;
    let now = Utc::now();
    // Clamp to [0, ~1000 years] so an absurd `--hours` can't overflow chrono's
    // TimeDelta (which panics above ~2.56e15 hours).
    let hours = hours.clamp(0, 8_760_000);
    let window = SnapshotWindow {
        from_us: (now - chrono::Duration::hours(hours)).timestamp_micros(),
        to_us: now.timestamp_micros(),
    };
    let versions = DatasetVersions {
        feature_version: "phase8-mlp-v1".into(),
        ..Default::default()
    };
    let inputs = collect_inputs(&store, name, window, versions, (train, val))?;
    let snap = build_snapshot(inputs);
    let outcome = store.state.put_dataset(&snap)?;
    let c = snap.bucket_counts();
    let version = format!("d-{}", short(&snap.digest));
    ensure_registered_local(
        &store,
        &cfg,
        RegistryKind::Dataset,
        name,
        &version,
        &snap.digest,
        DATASET_CREATE,
        serde_json::json!({
            "rows": snap.rows.len(),
            "excluded": snap.excluded.len(),
            "window_from_us": snap.window.from_us,
            "window_to_us": snap.window.to_us,
            "feature_version": snap.versions.feature_version,
            "bucket_counts": {
                "train": {"total": c.train.total, "dangerous": c.train.dangerous},
                "val": {"total": c.val.total, "dangerous": c.val.dangerous},
                "test": {"total": c.test.total, "dangerous": c.test.dangerous},
            },
        }),
    )?;
    println!("dataset {} ({:?})", snap.digest, outcome);
    println!(
        "  rows: {}  excluded: {}",
        snap.rows.len(),
        snap.excluded.len()
    );
    println!(
        "  train {}/{}dgr   val {}/{}dgr   test {}/{}dgr   (total/dangerous)",
        c.train.total,
        c.train.dangerous,
        c.val.total,
        c.val.dangerous,
        c.test.total,
        c.test.dangerous
    );
    if c.test.dangerous == 0 {
        println!("  NOTE: the Test holdout has no dangerous positives — a challenger cannot be promoted against it (the dangerous-FN guard would be vacuous).");
    }
    Ok(())
}

async fn dataset_list(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let ds = store.state.list_datasets()?;
    if ds.is_empty() {
        println!("(no datasets)");
    }
    for d in ds {
        let c = d.bucket_counts();
        println!(
            "{}  {:<16} rows={:<4} test={}/{}dgr",
            short(&d.digest),
            d.name,
            d.rows.len(),
            c.test.total,
            c.test.dangerous
        );
    }
    Ok(())
}

async fn dataset_show(cli: &Cli, prefix: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let d = find_dataset(&store, prefix)?.context("no such dataset")?;
    let c = d.bucket_counts();
    println!("dataset {}", d.digest);
    println!("  name:    {}", d.name);
    println!("  rows:    {}", d.rows.len());
    println!("  excluded:{}", d.excluded.len());
    println!(
        "  split:   train {}  val {}  test {}",
        c.train.total, c.val.total, c.test.total
    );
    println!(
        "  dangerous positives per bucket: train {} val {} test {}",
        c.train.dangerous, c.val.dangerous, c.test.dangerous
    );
    println!(
        "  verify:  {}",
        if d.verify_digest() { "OK" } else { "FAILED" }
    );
    Ok(())
}

async fn dataset_verify(cli: &Cli, prefix: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let d = find_dataset(&store, prefix)?.context("no such dataset")?;
    let digest_ok = d.verify_digest();
    let version = format!("d-{}", short(&d.digest));
    let rec = store
        .state
        .get_record(RegistryKind::Dataset, &d.name, &version)?;
    let joined = rec
        .as_ref()
        .map(|r| r.content_digest == d.digest)
        .unwrap_or(false);
    println!(
        "digest verify: {}",
        if digest_ok { "OK" } else { "MISMATCH" }
    );
    println!(
        "registry join: {}",
        if joined { "OK" } else { "missing/mismatch" }
    );
    if !digest_ok || !joined {
        anyhow::bail!("dataset integrity check failed");
    }
    Ok(())
}

async fn challenger_fit(cli: &Cli, prefix: &str, alert_budget: usize) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open_writable(&cfg).await?;
    let snap = find_dataset(&store, prefix)?.context("no such dataset")?;
    let champion = champion_policy(&cfg);
    let scfg = SearchConfig {
        alert_floor: SeverityBand::High,
        alert_budget,
    };
    match fit_challenger(&snap, &champion, &scfg) {
        None => {
            println!("no challenger beats the champion within the dangerous-FN guard");
        }
        Some(ch) => {
            let (spec, cdigest) = challenger_to_spec(&ch);
            let version = format!("chal-{}", short(&cdigest));
            ensure_registered_local(
                &store,
                &cfg,
                RegistryKind::DetectorConfig,
                "ensemble",
                &version,
                &cdigest,
                THRESHOLD_PROPOSE,
                serde_json::to_value(&spec).unwrap_or_default(),
            )?;
            println!("registered Draft challenger  detector_config ensemble@{version}");
            println!(
                "  crit_coef {:.2}  bands {:?}",
                ch.policy.ensemble.crit_coef, ch.policy.ensemble.bands
            );
            println!(
                "  val precision@budget {:.3}  dangerous_fn {}",
                ch.val_score.precision_at_budget, ch.val_score.dangerous_fn
            );
            println!(
                "  evaluate: garmr learn challenger eval {} --challenger {version}",
                short(&snap.digest)
            );
        }
    }
    Ok(())
}

async fn challenger_eval(
    cli: &Cli,
    prefix: &str,
    challenger_version: Option<&str>,
    alert_budget: usize,
) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open_writable(&cfg).await?;
    let snap = find_dataset(&store, prefix)?.context("no such dataset")?;
    let champion = champion_policy(&cfg);

    let (challenger, chal_label) = match challenger_version {
        Some(v) => {
            let rec = store
                .state
                .get_record(RegistryKind::DetectorConfig, "ensemble", v)?
                .context("no such challenger version")?;
            let spec: DetectorConfigSpec = serde_json::from_value(rec.spec).unwrap_or_default();
            (ChallengerPolicy::from_spec(&spec), v.to_string())
        }
        None => match fit_challenger(
            &snap,
            &champion,
            &SearchConfig {
                alert_floor: SeverityBand::High,
                alert_budget,
            },
        ) {
            Some(ch) => (ch.policy, "fitted".to_string()),
            None => {
                println!("no challenger to evaluate (none beats the champion)");
                return Ok(());
            }
        },
    };

    let gate = PromotionPolicy {
        alert_budget,
        ..Default::default()
    };
    let champ = replay(
        &snap,
        &champion,
        SplitBucket::Test,
        gate.alert_floor,
        gate.alert_budget,
    );
    let chal = replay(
        &snap,
        &challenger,
        SplitBucket::Test,
        gate.alert_floor,
        gate.alert_budget,
    );
    let report = compare(champ.clone(), chal.clone());
    let verdict = promotable(&report, snap.bucket_counts().test, &gate);

    println!(
        "champion   : prec {:.3}  recall {:.3}  p@budget {:.3}  dangerous_fn {}",
        champ.precision, champ.recall, champ.precision_at_budget, champ.dangerous_fn
    );
    println!(
        "challenger : prec {:.3}  recall {:.3}  p@budget {:.3}  dangerous_fn {}",
        chal.precision, chal.recall, chal.precision_at_budget, chal.dangerous_fn
    );
    println!(
        "delta      : dangerous_fn {:+}   p@budget {:+.3}",
        report.dangerous_fn_delta, report.precision_at_budget_delta
    );
    println!("promotable : {}", verdict.promotable);
    for r in &verdict.reasons {
        println!("  - {r}");
    }

    let metrics = serde_json::json!({
        "champion": score_json(&champ),
        "challenger": score_json(&chal),
        "dangerous_fn_delta": report.dangerous_fn_delta,
        "promotable": verdict.promotable,
        "reasons": verdict.reasons,
    });
    let run_digest = garmr_core::frame(&[
        b"eval_run",
        snap.digest.as_bytes(),
        chal_label.as_bytes(),
        metrics.to_string().as_bytes(),
    ]);
    let version = format!("e-{}", short(&run_digest));
    ensure_registered_local(
        &store,
        &cfg,
        RegistryKind::EvalRun,
        "ensemble",
        &version,
        &run_digest,
        EVAL_RUN,
        serde_json::json!({
            "dataset_digest": snap.digest,
            "challenger": chal_label,
            "metrics": metrics,
        }),
    )?;
    if verdict.promotable {
        println!(
            "\nto promote (human-gated, audited): first `garmr learn challenger fit {}` to register a versioned challenger, then `garmr registry promote detector_config ensemble <version> --channel production`",
            short(&snap.digest)
        );
    }
    Ok(())
}

async fn shadow(cli: &Cli, prefix: &str, challenger_version: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let snap = find_dataset(&store, prefix)?.context("no such dataset")?;
    let champion = champion_policy(&cfg);
    let rec = store
        .state
        .get_record(RegistryKind::DetectorConfig, "ensemble", challenger_version)?
        .context("no such challenger version")?;
    let spec: DetectorConfigSpec = serde_json::from_value(rec.spec).unwrap_or_default();
    let challenger = ChallengerPolicy::from_spec(&spec);
    let floor = SeverityBand::High;

    let mut newly_suppressed = 0usize;
    let mut newly_escalated = 0usize;
    let mut suppressed_dangerous = 0usize;
    for r in &snap.rows {
        let c_esc = score_row(&champion, r).1 >= floor;
        let h_esc = score_row(&challenger, r).1 >= floor;
        if c_esc && !h_esc {
            newly_suppressed += 1;
            if is_dangerous(r.trusted_disposition) {
                suppressed_dangerous += 1;
            }
        }
        if !c_esc && h_esc {
            newly_escalated += 1;
        }
    }
    println!(
        "shadow divergence over {} rows (OFFLINE, read-only — nothing written):",
        snap.rows.len()
    );
    println!(
        "  newly suppressed by challenger: {newly_suppressed}  (dangerous positives among them: {suppressed_dangerous})"
    );
    println!("  newly escalated by challenger:  {newly_escalated}");
    if suppressed_dangerous > 0 {
        println!("  WARNING: the challenger would newly suppress {suppressed_dangerous} dangerous positive(s) — it is NOT promotable.");
    }
    Ok(())
}