// Apache-2.0 licensed.
//
// Git-like refs over Iceberg: branch / tag lifecycle, fast-forward,
// WAP publish, rollback, and read-as-of-ref. Every op goes through the public
// `RedbCatalog` surface added in `src/git.rs` and is expressed as a standard
// Iceberg `SetSnapshotRef` / `RemoveSnapshotRef` applied through `commit_table`.
//
// Correctness is the point here (skade is correctness-sensitive): the
// fast-forward ancestry guard and the rollback ancestor guard have RED-when-
// broken assertions — if the ancestry walk were removed, a non-fast-forward
// move or a rewind to an unrelated snapshot would wrongly succeed and these
// tests would fail.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, Operation, PrimitiveType, Schema, Snapshot, Summary, Type};
use iceberg::{
    Catalog, CatalogBuilder, ErrorKind, NamespaceIdent, TableCreation, TableIdent, TableUpdate,
};
use skade_katalog::{BranchRetention, RedbCatalog, RedbCatalogBuilder, RefKind};
use tempfile::TempDir;

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .unwrap()
}

async fn catalog(tmp: &TempDir) -> Result<RedbCatalog> {
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    Ok(RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn synth_snapshot(snapshot_id: i64, parent: Option<i64>, seq: i64) -> Snapshot {
    Snapshot::builder()
        .with_snapshot_id(snapshot_id)
        .with_parent_snapshot_id(parent)
        .with_sequence_number(seq)
        .with_timestamp_ms(now_ms() + seq)
        .with_manifest_list(format!("file:///dev/null/manifest-{snapshot_id}.avro"))
        .with_schema_id(0)
        .with_summary(Summary {
            operation: Operation::Append,
            additional_properties: HashMap::new(),
        })
        .build()
}

/// Add a data snapshot and advance `ref_name` to it, through the normal
/// `commit_table` pointer-advance path (AddSnapshot + SetSnapshotRef).
async fn append_on_ref(
    cat: &RedbCatalog,
    ident: &TableIdent,
    ref_name: &str,
    snapshot_id: i64,
    parent: Option<i64>,
    seq: i64,
) -> Result<()> {
    let snap = synth_snapshot(snapshot_id, parent, seq);
    let updates = vec![
        TableUpdate::AddSnapshot { snapshot: snap },
        TableUpdate::SetSnapshotRef {
            ref_name: ref_name.to_string(),
            reference: iceberg::spec::SnapshotReference::new(
                snapshot_id,
                iceberg::spec::SnapshotRetention::Branch {
                    min_snapshots_to_keep: None,
                    max_snapshot_age_ms: None,
                    max_ref_age_ms: None,
                },
            ),
        },
    ];
    cat.commit_table(ident.clone(), vec![], updates).await?;
    Ok(())
}

/// Fresh catalog + namespace + table with a linear 3-snapshot main history
/// (1001 → 1002 → 1003), main at 1003.
async fn table_with_history(cat: &RedbCatalog) -> Result<TableIdent> {
    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema())
        .build();
    cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns, "t".to_string());
    append_on_ref(cat, &ident, "main", 1001, None, 1).await?;
    append_on_ref(cat, &ident, "main", 1002, Some(1001), 2).await?;
    append_on_ref(cat, &ident, "main", 1003, Some(1002), 3).await?;
    Ok(ident)
}

#[tokio::test]
async fn branch_tag_lifecycle() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;
    let ident = table_with_history(&cat).await?;

    // Branch off an older snapshot; tag the release point.
    cat.create_branch(&ident, "feature", Some(1001), BranchRetention::default())
        .await?;
    cat.create_tag(&ident, "v1", Some(1002), None).await?;
    // Branch on current head (snapshot_id = None → current).
    cat.create_branch(&ident, "next", None, BranchRetention::default())
        .await?;

    let refs = cat.list_refs(&ident).await?;
    let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["feature", "main", "next", "v1"]);

    let by = |n: &str| refs.iter().find(|r| r.name == n).unwrap();
    assert_eq!(
        (by("main").kind, by("main").snapshot_id),
        (RefKind::Branch, 1003)
    );
    assert_eq!(
        (by("feature").kind, by("feature").snapshot_id),
        (RefKind::Branch, 1001)
    );
    assert_eq!(
        (by("next").kind, by("next").snapshot_id),
        (RefKind::Branch, 1003)
    );
    assert_eq!((by("v1").kind, by("v1").snapshot_id), (RefKind::Tag, 1002));

    assert_eq!(cat.ref_snapshot_id(&ident, "v1").await?, Some(1002));
    assert_eq!(cat.ref_snapshot_id(&ident, "absent").await?, None);

    // Drop a ref; a re-list no longer shows it. Dropping again errors.
    cat.drop_ref(&ident, "feature").await?;
    let after: Vec<String> = cat
        .list_refs(&ident)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(
        after,
        vec!["main".to_string(), "next".to_string(), "v1".to_string()]
    );
    let drop_missing = cat.drop_ref(&ident, "feature").await.unwrap_err();
    assert_eq!(drop_missing.kind(), ErrorKind::TableNotFound);

    let ok = names == vec!["feature", "main", "next", "v1"]
        && drop_missing.kind() == ErrorKind::TableNotFound;
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "skade.git",
        "branch_tag_lifecycle",
        ok,
        &format!(
            "created 3 refs, listed {:?}, dropped feature, drop-missing=TableNotFound",
            after
        ),
    );
    assert!(ok);
    Ok(())
}

#[tokio::test]
async fn duplicate_ref_conflicts() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;
    let ident = table_with_history(&cat).await?;

    cat.create_branch(&ident, "dev", None, BranchRetention::default())
        .await?;
    let dup_b = cat
        .create_branch(&ident, "dev", None, BranchRetention::default())
        .await
        .unwrap_err();
    cat.create_tag(&ident, "rel", None, None).await?;
    let dup_t = cat.create_tag(&ident, "rel", None, None).await.unwrap_err();

    assert_eq!(dup_b.kind(), ErrorKind::CatalogCommitConflicts);
    assert_eq!(dup_t.kind(), ErrorKind::CatalogCommitConflicts);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "skade.git",
        "duplicate_ref_conflicts",
        true,
        "re-creating an existing branch/tag → CatalogCommitConflicts",
    );
    Ok(())
}

#[tokio::test]
async fn fast_forward_and_non_ff_guard() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;
    let ident = table_with_history(&cat).await?;

    // Branch at the oldest snapshot, then fast-forward it up the line.
    cat.create_branch(&ident, "release", Some(1001), BranchRetention::default())
        .await?;
    cat.fast_forward(&ident, "release", 1003).await?;
    assert_eq!(cat.ref_snapshot_id(&ident, "release").await?, Some(1003));

    // Non-fast-forward: moving back to an ancestor is NOT a fast-forward.
    // RED-when-broken: without the ancestry guard this would succeed.
    let non_ff = cat.fast_forward(&ident, "release", 1001).await.unwrap_err();
    assert_eq!(non_ff.kind(), ErrorKind::CatalogCommitConflicts);
    assert!(non_ff.retryable());
    // The ref did not move.
    assert_eq!(cat.ref_snapshot_id(&ident, "release").await?, Some(1003));

    // Fast-forward to an unknown snapshot → DataInvalid.
    let unknown = cat
        .fast_forward(&ident, "release", 999999)
        .await
        .unwrap_err();
    assert_eq!(unknown.kind(), ErrorKind::DataInvalid);

    // A tag cannot be fast-forwarded.
    cat.create_tag(&ident, "frozen", Some(1002), None).await?;
    let tag_ff = cat.fast_forward(&ident, "frozen", 1003).await.unwrap_err();
    assert_eq!(tag_ff.kind(), ErrorKind::DataInvalid);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "skade.git",
        "fast_forward_and_non_ff_guard",
        true,
        "ff 1001→1003 ok; backward move rejected (non-ff); unknown snap + tag-ff rejected",
    );
    Ok(())
}

#[tokio::test]
async fn rollback_ancestor_guard() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;
    let ident = table_with_history(&cat).await?;

    // Roll main back to an ancestor.
    cat.rollback_to(&ident, 1001).await?;
    assert_eq!(cat.ref_snapshot_id(&ident, "main").await?, Some(1001));

    // A divergent snapshot never on main's line: branch off 1001, add 2001 there.
    cat.create_branch(&ident, "side", Some(1001), BranchRetention::default())
        .await?;
    append_on_ref(&cat, &ident, "side", 2001, Some(1001), 4).await?;
    // main is at 1001; 2001 is a descendant of 1001 but NOT an ancestor of main's
    // head (1001). Rolling *back* to 2001 is not a rewind → rejected.
    // RED-when-broken: without the ancestor guard this would move main forward
    // onto a sibling line.
    let bad = cat.rollback_to(&ident, 2001).await.unwrap_err();
    assert_eq!(bad.kind(), ErrorKind::DataInvalid);
    assert_eq!(cat.ref_snapshot_id(&ident, "main").await?, Some(1001));

    // Unknown snapshot → DataInvalid.
    let unknown = cat.rollback_to(&ident, 424242).await.unwrap_err();
    assert_eq!(unknown.kind(), ErrorKind::DataInvalid);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "skade.git",
        "rollback_ancestor_guard",
        true,
        "main 1003→1001 rewind ok; rollback to non-ancestor sibling + unknown rejected",
    );
    Ok(())
}

#[tokio::test]
async fn wap_publish() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;
    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema())
        .build();
    cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns, "t".to_string());

    // main = 1001.
    append_on_ref(&cat, &ident, "main", 1001, None, 1).await?;
    // Open an audit branch at main, then land audited data ONLY on audit.
    cat.create_branch(&ident, "audit", None, BranchRetention::default())
        .await?;
    append_on_ref(&cat, &ident, "audit", 1002, Some(1001), 2).await?;
    assert_eq!(cat.ref_snapshot_id(&ident, "main").await?, Some(1001));
    assert_eq!(cat.ref_snapshot_id(&ident, "audit").await?, Some(1002));

    // Publish: fast-forward main ← audit (main head 1001 is an ancestor of 1002).
    cat.publish_branch(&ident, "audit", "main").await?;
    assert_eq!(cat.ref_snapshot_id(&ident, "main").await?, Some(1002));

    // A second, divergent audit line off 1001 cannot publish over the advanced
    // main (main is now 1002, not an ancestor of the new 3001).
    cat.create_branch(&ident, "audit2", Some(1001), BranchRetention::default())
        .await?;
    append_on_ref(&cat, &ident, "audit2", 3001, Some(1001), 3).await?;
    let refuse = cat
        .publish_branch(&ident, "audit2", "main")
        .await
        .unwrap_err();
    assert_eq!(refuse.kind(), ErrorKind::CatalogCommitConflicts);
    assert_eq!(cat.ref_snapshot_id(&ident, "main").await?, Some(1002));

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "skade.git",
        "wap_publish",
        true,
        "audit 1001→1002 published to main; divergent audit2 publish refused (non-ff)",
    );
    Ok(())
}

#[tokio::test]
async fn read_as_of_ref() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;
    let ident = table_with_history(&cat).await?;

    cat.create_tag(&ident, "v1", Some(1001), None).await?;

    // Read the table as of the tag → the historical snapshot the tag names.
    let t = cat.load_table_for_ref(&ident, "v1").await?;
    assert_eq!(t.metadata().current_snapshot_id(), Some(1001));

    let md = cat.resolve_metadata_for_ref(&ident, "v1").await?;
    assert_eq!(md.current_snapshot_id(), Some(1001));

    // Reading a nonexistent ref → TableNotFound.
    let missing = cat.load_table_for_ref(&ident, "nope").await.unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::TableNotFound);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "skade.git",
        "read_as_of_ref",
        true,
        "load_table_for_ref/resolve_metadata_for_ref resolve tag v1→snapshot 1001; missing ref → TableNotFound",
    );
    Ok(())
}
