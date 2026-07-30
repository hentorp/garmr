use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{
    Catalog, CatalogBuilder, ErrorKind, NamespaceIdent, TableCreation, TableIdent,
    TableRequirement, TableUpdate,
};
use skade_katalog::RedbCatalogBuilder;
use tempfile::TempDir;

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::String)).into(),
        ])
        .build()
        .expect("schema")
}

async fn make_catalog(tmp: &TempDir) -> Result<skade_katalog::RedbCatalog> {
    let db_path = tmp.path().join("catalog.redb");
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;

    let cat = RedbCatalogBuilder::default()
        .db_path(db_path)
        .warehouse_location(format!("file://{}", warehouse.display()))
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?;
    Ok(cat)
}

/// Exercises the real `atomic_release_raw` code path (the multi-table
/// all-or-nothing pointer swap in atomic.rs).
///
/// Asserts:
/// 1. All three table pointers advance together in a single `atomic_release_raw` call.
/// 2. Each returned table carries the property that was set.
///
/// NOTE: this test covers the happy path + the *stage-phase* requirement
/// rejection only. The load-bearing atomicity claim — that a conflict detected
/// *inside* the redb write transaction (the CAS at atomic.rs:232-243) rolls
/// back every pointer all-or-nothing — is proven by
/// `in_txn_cas_conflict_rolls_back_all_pointers` below. Keep them separate:
/// the requirement-rejection path aborts during staging, *before* any I/O and
/// before the redb write txn opens, so it does not exercise the CAS.
#[tokio::test]
async fn atomic_release_advances_all_tables_together() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;

    let ns = NamespaceIdent::new("release".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;

    let names = ["bench_runs", "dep_graph", "components"];
    for n in names {
        let creation = TableCreation::builder()
            .name(n.to_string())
            .schema(schema())
            .build();
        cat.create_table(&ns, creation).await?;
    }

    let idents: Vec<TableIdent> = names
        .iter()
        .map(|n| TableIdent::new(ns.clone(), (*n).to_string()))
        .collect();

    // Capture pointer locations before the atomic commit.
    let before: Vec<String> = {
        let mut out = Vec::new();
        for i in &idents {
            out.push(
                cat.load_table(i)
                    .await?
                    .metadata_location_result()?
                    .to_string(),
            );
        }
        out
    };

    // Build raw commit triples — one per table, each setting a release property.
    let commits: Vec<_> = idents
        .iter()
        .map(|id| {
            (
                id.clone(),
                vec![], // no requirements
                vec![TableUpdate::SetProperties {
                    updates: [("nornir.release".to_string(), "2026.05.31".to_string())]
                        .into_iter()
                        .collect(),
                }],
            )
        })
        .collect();

    // Drive the real atomic_release_raw path.
    let updated = cat.atomic_release_raw(commits).await?;

    // Assert 1: all three pointers advanced.
    assert_eq!(
        updated.len(),
        names.len(),
        "wrong number of returned tables"
    );
    for (idx, (table, i)) in updated.iter().zip(idents.iter()).enumerate() {
        let now = table.metadata_location_result()?.to_string();
        assert_ne!(
            now, before[idx],
            "table {i} did not advance after atomic_release_raw"
        );
        // Assert 2: the property is present on each returned handle.
        assert_eq!(
            table
                .metadata()
                .properties()
                .get("nornir.release")
                .map(String::as_str),
            Some("2026.05.31"),
            "release property missing on returned handle for {i}"
        );
    }

    // Confirm the catalog also reflects the advance for each table.
    for (idx, i) in idents.iter().enumerate() {
        let loc = cat
            .load_table(i)
            .await?
            .metadata_location_result()?
            .to_string();
        assert_ne!(loc, before[idx], "catalog pointer for {i} did not advance");
    }

    // Assert 3 — STAGE-PHASE requirement rejection (a *different*, earlier path
    // than the in-txn CAS):
    //
    // Build a batch where the first table has a UuidMatch requirement that
    // will be satisfied (real UUID), but the second table has a deliberate
    // bogus UuidMatch (wrong UUID). `atomic_release_raw` checks every
    // requirement during the stage loop (atomic.rs:179) — so this batch is
    // rejected *before* any metadata blob is written and *before* the redb
    // write transaction opens. This proves "a bad requirement aborts before
    // I/O", which is real and worth keeping, but it does NOT exercise the
    // CAS at atomic.rs:232-243; that is covered by
    // `in_txn_cas_conflict_rolls_back_all_pointers`.

    // Capture each table's metadata_location before the rejected batch, so we
    // can assert no pointer moved at all (a more direct "no pointer advanced"
    // proof than only checking the `nornir.release` property).
    let loc_before_reject: Vec<String> = {
        let mut out = Vec::new();
        for i in &idents {
            out.push(
                cat.load_table(i)
                    .await?
                    .metadata_location_result()?
                    .to_string(),
            );
        }
        out
    };

    let real_uuid = cat.load_table(&idents[0]).await?.metadata().uuid();

    let bad_uuid = uuid::Uuid::new_v4(); // never matches

    let failing_commits: Vec<_> = idents
        .iter()
        .enumerate()
        .map(|(idx, id)| {
            let req = if idx == 1 {
                // Second table gets an impossible requirement.
                vec![TableRequirement::UuidMatch { uuid: bad_uuid }]
            } else {
                vec![TableRequirement::UuidMatch { uuid: real_uuid }]
            };
            (
                id.clone(),
                req,
                vec![TableUpdate::SetProperties {
                    updates: [(
                        "nornir.release".to_string(),
                        "SHOULD_NOT_APPEAR".to_string(),
                    )]
                    .into_iter()
                    .collect(),
                }],
            )
        })
        .collect();

    let err = cat
        .atomic_release_raw(failing_commits)
        .await
        .expect_err("batch with failing requirement must fail");
    assert_eq!(
        err.kind(),
        ErrorKind::CatalogCommitConflicts,
        "expected CatalogCommitConflicts for failing UuidMatch, got: {err}"
    );

    // All three pointers must remain at their post-first-commit locations
    // (not the "SHOULD_NOT_APPEAR" value), and — more directly — no table's
    // metadata_location may have moved at all.
    for (idx, i) in idents.iter().enumerate() {
        let loaded = cat.load_table(i).await?;
        let loc_now = loaded.metadata_location_result()?.to_string();
        assert_eq!(
            loc_now, loc_before_reject[idx],
            "table {i} metadata_location moved despite a stage-rejected batch"
        );
        let prop = loaded
            .metadata()
            .properties()
            .get("nornir.release")
            .cloned()
            .unwrap_or_default();
        assert_ne!(
            prop, "SHOULD_NOT_APPEAR",
            "table {i} was incorrectly updated by a failing atomic batch"
        );
        assert_eq!(
            prop, "2026.05.31",
            "table {i} lost its release property after a failed batch"
        );
    }

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "atomic",
        "atomic_release_advances_all_tables_together",
        updated.len() == names.len() && err.kind() == ErrorKind::CatalogCommitConflicts,
        &format!(
            "{}/{} tables advanced together; stage-phase bad requirement rejected as {:?}, no pointer moved",
            updated.len(),
            names.len(),
            err.kind()
        ),
    );
    Ok(())
}

/// THE LOAD-BEARING ATOMICITY TEST (audit MED fix).
///
/// Proves that a conflict detected *inside* the redb write transaction — the
/// compare-and-swap at `src/atomic.rs:232-243`, where the stored
/// `metadata_location` no longer equals the `base` the batch captured at stage
/// time — aborts the whole batch with `CatalogCommitConflicts` and advances
/// **none** of the pointers (all-or-nothing).
///
/// This is distinct from the stage-phase requirement rejection above: here the
/// batch carries *no* requirements, so the stage loop passes cleanly; the only
/// thing that can stop it is the in-txn CAS. We trip it by advancing one
/// table's pointer out-of-band (via `commit_table`) *after* the batch has
/// captured its base but *before* it acquires the redb write lock.
///
/// We run on a multi-thread runtime and fire the atomic batch and the
/// out-of-band single-table commit in parallel, aligned by a 2-party
/// `Barrier` so they collide on the redb write lock. The batch captures its
/// base from the lock-free pointer cache (no lock), so when the out-of-band
/// commit wins the lock race and advances the victim off `base`, the batch's
/// in-txn CAS sees the moved pointer and aborts the whole batch.
///
/// This is wrapped in a bounded retry: on each attempt the batch either (a)
/// hit the CAS conflict — in which case we assert all-or-nothing and stop, or
/// (b) raced through and succeeded — in which case we assert it advanced
/// cleanly and retry. We require that the CAS conflict was actually observed
/// at least once, so a green test genuinely exercised atomic.rs:232-243.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_txn_cas_conflict_rolls_back_all_pointers() -> Result<()> {
    use std::sync::Barrier as StdBarrier;

    let mut observed_conflict = false;

    for attempt in 0..256 {
        let tmp = TempDir::new()?;
        let cat = make_catalog(&tmp).await?;

        let ns = NamespaceIdent::new("release".to_string());
        cat.create_namespace(&ns, HashMap::new()).await?;

        // Two-table logical release. `victim` is the one we'll move out-of-band
        // (it must stage fine, then conflict in the txn); `bystander` stages
        // fine and must NOT advance when the batch aborts.
        let names = ["victim", "bystander"];
        for n in names {
            let creation = TableCreation::builder()
                .name(n.to_string())
                .schema(schema())
                .build();
            cat.create_table(&ns, creation).await?;
        }
        let victim = TableIdent::new(ns.clone(), "victim".to_string());
        let bystander = TableIdent::new(ns.clone(), "bystander".to_string());

        // Pointer locations the batch will capture as `base`.
        let victim_base = cat
            .load_table(&victim)
            .await?
            .metadata_location_result()?
            .to_string();
        let bystander_base = cat
            .load_table(&bystander)
            .await?
            .metadata_location_result()?
            .to_string();

        // The atomic batch: no requirements (so the stage loop cannot reject
        // it), each table just sets a release marker. The only thing that can
        // stop it is the in-txn CAS.
        let batch: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)> = vec![
            (
                victim.clone(),
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: [("nornir.release".to_string(), "BATCH_VICTIM".to_string())]
                        .into_iter()
                        .collect(),
                }],
            ),
            (
                bystander.clone(),
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: [("nornir.release".to_string(), "BATCH_BYSTANDER".to_string())]
                        .into_iter()
                        .collect(),
                }],
            ),
        ];

        // Fire both operations in parallel, aligned on a 2-party barrier so
        // they collide on the redb write lock. The batch captures its base
        // from the lock-free pointer cache, so if the out-of-band commit wins
        // the lock and advances the victim off `base`, the batch's in-txn CAS
        // (atomic.rs:232-243) must abort the whole batch.
        let gate = Arc::new(StdBarrier::new(2));

        let cat_batch = cat.clone();
        let gate_batch = gate.clone();
        let handle = tokio::spawn(async move {
            gate_batch.wait();
            cat_batch.atomic_release_raw(batch).await
        });

        let cat_oob = cat.clone();
        let gate_oob = gate.clone();
        let victim_oob = victim.clone();
        let oob_handle = tokio::spawn(async move {
            gate_oob.wait();
            cat_oob
                .commit_table(
                    victim_oob,
                    vec![],
                    vec![TableUpdate::SetProperties {
                        updates: [("nornir.release".to_string(), "OUT_OF_BAND".to_string())]
                            .into_iter()
                            .collect(),
                    }],
                )
                .await
        });

        let oob = oob_handle.await.expect("oob task panicked");
        // The out-of-band commit may itself lose a race to the batch (if the
        // batch already grabbed the lock and advanced). Handle both outcomes.
        let oob_loc = oob.as_ref().ok().map(|t| {
            t.metadata_location_result()
                .expect("oob metadata location")
                .to_string()
        });

        let batch_result = handle.await.expect("batch task panicked");

        match batch_result {
            Err(e) if e.kind() == ErrorKind::CatalogCommitConflicts => {
                observed_conflict = true;

                // ATOMICITY: the bystander (which staged fine) must NOT have
                // advanced — neither its pointer nor its property moved.
                let by = cat.load_table(&bystander).await?;
                assert_eq!(
                    by.metadata_location_result()?.to_string(),
                    bystander_base,
                    "attempt {attempt}: bystander pointer advanced despite \
                     in-txn CAS abort (NOT all-or-nothing)"
                );
                assert_ne!(
                    by.metadata()
                        .properties()
                        .get("nornir.release")
                        .map(String::as_str),
                    Some("BATCH_BYSTANDER"),
                    "attempt {attempt}: bystander got the batch's property \
                     despite the batch aborting"
                );

                // And the victim must reflect ONLY the out-of-band write, never
                // the batch's value.
                let vi = cat.load_table(&victim).await?;
                assert_ne!(
                    vi.metadata()
                        .properties()
                        .get("nornir.release")
                        .map(String::as_str),
                    Some("BATCH_VICTIM"),
                    "attempt {attempt}: victim got the batch's property \
                     despite the batch aborting"
                );
                if let Some(loc) = &oob_loc {
                    assert_eq!(
                        vi.metadata_location_result()?.to_string(),
                        *loc,
                        "attempt {attempt}: victim pointer is not at the \
                         out-of-band location after the batch aborted"
                    );
                }
                break;
            }
            Ok(_) => {
                // The batch raced ahead of the out-of-band commit and committed
                // cleanly. That is still a *correct* outcome (both pointers
                // advanced together); just retry to provoke the conflict.
                let vi = cat
                    .load_table(&victim)
                    .await?
                    .metadata_location_result()?
                    .to_string();
                let by = cat
                    .load_table(&bystander)
                    .await?
                    .metadata_location_result()?
                    .to_string();
                assert_ne!(
                    vi, victim_base,
                    "attempt {attempt}: batch reported success but victim \
                     pointer did not advance"
                );
                assert_ne!(
                    by, bystander_base,
                    "attempt {attempt}: batch reported success but bystander \
                     pointer did not advance"
                );
                continue;
            }
            Err(e) => panic!("attempt {attempt}: unexpected batch error: {e}"),
        }
    }

    assert!(
        observed_conflict,
        "never observed an in-txn CAS CatalogCommitConflicts across all \
         attempts — the conflict path (atomic.rs:232-243) was not exercised"
    );
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "atomic",
        "in_txn_cas_conflict_rolls_back_all_pointers",
        observed_conflict,
        &format!(
            "in-txn CAS conflict observed + all-or-nothing rollback verified (observed={observed_conflict})"
        ),
    );
    Ok(())
}

#[tokio::test]
async fn empty_atomic_release_is_noop() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let out = cat.atomic_release(std::iter::empty()).await?;
    let empty = out.is_empty();
    assert!(empty);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "atomic",
        "empty_atomic_release_is_noop",
        empty,
        &format!("empty release returned {} tables (want 0)", out.len()),
    );
    Ok(())
}
