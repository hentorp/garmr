use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use skade_katalog::RedbCatalogBuilder;
use tempfile::TempDir;

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

fn schema_v1() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "run_id", Type::Primitive(PrimitiveType::String)).into(),
            NestedField::required(2, "ops_sec", Type::Primitive(PrimitiveType::Double)).into(),
        ])
        .build()
        .expect("schema v1")
}

#[tokio::test]
async fn namespace_lifecycle() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;

    let ns = NamespaceIdent::new("bench".to_string());
    assert!(!cat.namespace_exists(&ns).await?);

    let mut props = HashMap::new();
    props.insert("owner".to_string(), "nornir".to_string());
    let created = cat.create_namespace(&ns, props.clone()).await?;
    assert_eq!(created.name(), &ns);
    assert_eq!(created.properties(), &props);
    assert!(cat.namespace_exists(&ns).await?);

    let fetched = cat.get_namespace(&ns).await?;
    assert_eq!(
        fetched.properties().get("owner"),
        Some(&"nornir".to_string())
    );

    let listed = cat.list_namespaces(None).await?;
    assert!(listed.contains(&ns));

    // Replace properties.
    let mut new_props = HashMap::new();
    new_props.insert("owner".to_string(), "rickard".to_string());
    new_props.insert("env".to_string(), "ci".to_string());
    cat.update_namespace(&ns, new_props.clone()).await?;
    let after = cat.get_namespace(&ns).await?;
    assert_eq!(after.properties(), &new_props);

    cat.drop_namespace(&ns).await?;
    let dropped = !cat.namespace_exists(&ns).await?;
    assert!(dropped);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "namespace_lifecycle",
        dropped && after.properties() == &new_props,
        &format!("created+updated owner=rickard, dropped={dropped}"),
    );
    Ok(())
}

#[tokio::test]
async fn nested_namespace_listing() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;

    let top = NamespaceIdent::new("warehouse".to_string());
    let a = NamespaceIdent::from_strs(["warehouse", "a"])?;
    let b = NamespaceIdent::from_strs(["warehouse", "b"])?;
    let nested = NamespaceIdent::from_strs(["warehouse", "a", "deep"])?;

    cat.create_namespace(&top, HashMap::new()).await?;
    cat.create_namespace(&a, HashMap::new()).await?;
    cat.create_namespace(&b, HashMap::new()).await?;
    cat.create_namespace(&nested, HashMap::new()).await?;

    let roots = cat.list_namespaces(None).await?;
    assert!(roots.contains(&top), "roots = {roots:?}");
    assert!(!roots.contains(&a));

    let children = cat.list_namespaces(Some(&top)).await?;
    assert!(children.contains(&a));
    assert!(children.contains(&b));
    assert!(!children.contains(&nested));

    let grandchildren = cat.list_namespaces(Some(&a)).await?;
    assert!(grandchildren.contains(&nested));
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "nested_namespace_listing",
        roots.contains(&top)
            && children.contains(&a)
            && children.contains(&b)
            && grandchildren.contains(&nested),
        &format!(
            "roots={} children={} grandchildren={}",
            roots.len(),
            children.len(),
            grandchildren.len()
        ),
    );
    Ok(())
}

#[tokio::test]
async fn table_create_load_list_drop() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;

    let creation = TableCreation::builder()
        .name("bench_runs".to_string())
        .schema(schema_v1())
        .build();
    let table = cat.create_table(&ns, creation).await?;
    assert_eq!(table.identifier().name(), "bench_runs");

    let ident = TableIdent::new(ns.clone(), "bench_runs".to_string());
    assert!(cat.table_exists(&ident).await?);

    let listed = cat.list_tables(&ns).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name(), "bench_runs");

    let reloaded = cat.load_table(&ident).await?;
    assert_eq!(reloaded.metadata().current_schema().schema_id(), 0);
    assert_eq!(
        reloaded
            .metadata()
            .current_schema()
            .as_struct()
            .fields()
            .len(),
        2
    );

    cat.drop_table(&ident).await?;
    let gone = !cat.table_exists(&ident).await?;
    assert!(gone);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "table_create_load_list_drop",
        gone && listed.len() == 1 && reloaded.metadata().current_schema().schema_id() == 0,
        &format!(
            "listed={} schema_id={} fields={} dropped={gone}",
            listed.len(),
            reloaded.metadata().current_schema().schema_id(),
            reloaded
                .metadata()
                .current_schema()
                .as_struct()
                .fields()
                .len()
        ),
    );
    Ok(())
}

#[tokio::test]
async fn drop_namespace_with_tables_fails() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t1".to_string())
        .schema(schema_v1())
        .build();
    cat.create_table(&ns, creation).await?;

    let rejected = cat.drop_namespace(&ns).await.is_err();
    assert!(rejected);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "drop_namespace_with_tables_fails",
        rejected,
        &format!("drop of non-empty namespace rejected={rejected}"),
    );
    Ok(())
}

#[tokio::test]
async fn rename_table_across_namespaces() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let src_ns = NamespaceIdent::new("src".to_string());
    let dst_ns = NamespaceIdent::new("dst".to_string());
    cat.create_namespace(&src_ns, HashMap::new()).await?;
    cat.create_namespace(&dst_ns, HashMap::new()).await?;

    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema_v1())
        .build();
    cat.create_table(&src_ns, creation).await?;

    let src = TableIdent::new(src_ns.clone(), "t".to_string());
    let dst = TableIdent::new(dst_ns.clone(), "renamed".to_string());
    cat.rename_table(&src, &dst).await?;

    let src_gone = !cat.table_exists(&src).await?;
    let dst_here = cat.table_exists(&dst).await?;
    assert!(src_gone);
    assert!(dst_here);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "rename_table_across_namespaces",
        src_gone && dst_here,
        &format!("src_gone={src_gone} dst_present={dst_here}"),
    );
    Ok(())
}

#[tokio::test]
async fn transaction_property_update_persists() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("bench_runs".to_string())
        .schema(schema_v1())
        .build();
    let table = cat.create_table(&ns, creation).await?;

    let tx = Transaction::new(&table);
    let action = tx
        .update_table_properties()
        .set("nornir.marker".to_string(), "v1".to_string());
    let v2 = action.apply(tx)?.commit(&cat).await?;
    assert_eq!(
        v2.metadata().properties().get("nornir.marker"),
        Some(&"v1".to_string())
    );

    let ident = TableIdent::new(ns, "bench_runs".to_string());
    let reloaded = cat.load_table(&ident).await?;
    let persisted = reloaded.metadata().properties().get("nornir.marker");
    assert_eq!(persisted, Some(&"v1".to_string()));
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "transaction_property_update_persists",
        persisted == Some(&"v1".to_string()),
        &format!("nornir.marker reloaded={:?}", persisted.map(String::as_str)),
    );
    Ok(())
}

#[tokio::test]
async fn second_open_sees_previous_data() -> Result<()> {
    let tmp = TempDir::new()?;
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    let db_path = tmp.path().join("catalog.redb");
    let warehouse_uri = format!("file://{}", warehouse.display());

    {
        let cat = RedbCatalogBuilder::default()
            .db_path(&db_path)
            .warehouse_location(&warehouse_uri)
            .with_storage_factory(Arc::new(LocalFsStorageFactory))
            .load("nornir", HashMap::new())
            .await?;
        let ns = NamespaceIdent::new("bench".to_string());
        cat.create_namespace(&ns, HashMap::new()).await?;
        let creation = TableCreation::builder()
            .name("t".to_string())
            .schema(schema_v1())
            .build();
        cat.create_table(&ns, creation).await?;
        drop(cat);
    }

    let cat2 = RedbCatalogBuilder::default()
        .db_path(&db_path)
        .warehouse_location(&warehouse_uri)
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?;
    let ns = NamespaceIdent::new("bench".to_string());
    let ns_ok = cat2.namespace_exists(&ns).await?;
    assert!(ns_ok);
    let ident = TableIdent::new(ns, "t".to_string());
    let tbl_ok = cat2.table_exists(&ident).await?;
    assert!(tbl_ok);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "second_open_sees_previous_data",
        ns_ok && tbl_ok,
        &format!("durable reopen: ns_exists={ns_ok} table_exists={tbl_ok}"),
    );
    Ok(())
}

// `commit_table` is the raw REST-style commit primitive (apply N
// requirements + N updates, persist via the optimistic group-commit path). It
// backs the REST shim's `commit_table` endpoint, which cannot reconstruct a
// crate-private `TableCommit`. These tests drive it directly.

#[tokio::test]
async fn commit_table_applies_updates_and_persists() -> Result<()> {
    use iceberg::{TableRequirement, TableUpdate};

    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;

    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema_v1())
        .build();
    let table = cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns.clone(), "t".to_string());
    let loc_before = table.metadata_location_result()?.to_string();
    let uuid = table.metadata().uuid();

    // A UUID-match requirement (the common write-conflict guard) + a property
    // set update — the same shapes an Iceberg-REST `update_table` sends.
    let updates = vec![TableUpdate::SetProperties {
        updates: HashMap::from([("answer".to_string(), "42".to_string())]),
    }];
    let requirements = vec![TableRequirement::UuidMatch { uuid }];

    let committed = cat
        .commit_table(ident.clone(), requirements, updates)
        .await?;

    let loc_after = committed.metadata_location_result()?.to_string();
    assert_ne!(loc_before, loc_after, "commit writes a new metadata file");
    assert_eq!(
        committed
            .metadata()
            .properties()
            .get("answer")
            .map(String::as_str),
        Some("42")
    );

    // Persisted: a fresh load (post drop of the handle cache via reload) sees it.
    let reloaded = cat.load_table(&ident).await?;
    assert_eq!(reloaded.metadata_location_result()?, loc_after);
    assert_eq!(
        reloaded
            .metadata()
            .properties()
            .get("answer")
            .map(String::as_str),
        Some("42")
    );
    // And the resolve fast path agrees.
    let meta = cat.resolve_metadata(&ident).await?;
    let resolved = meta.properties().get("answer").map(String::as_str);
    assert_eq!(resolved, Some("42"));
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "commit_table_applies_updates_and_persists",
        loc_before != loc_after && resolved == Some("42"),
        &format!(
            "new metadata file written={} answer-resolved={:?}",
            loc_before != loc_after,
            resolved
        ),
    );
    Ok(())
}

#[tokio::test]
async fn commit_table_rejects_failed_requirement() -> Result<()> {
    use iceberg::{ErrorKind, TableRequirement, TableUpdate};

    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema_v1())
        .build();
    cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns.clone(), "t".to_string());

    // A current-schema-id requirement that cannot match (the table's schema id
    // is 0) → the commit must fail and nothing should be persisted.
    let requirements = vec![TableRequirement::CurrentSchemaIdMatch {
        current_schema_id: 999,
    }];
    let updates = vec![TableUpdate::SetProperties {
        updates: HashMap::from([("k".to_string(), "v".to_string())]),
    }];
    let err = cat
        .commit_table(ident.clone(), requirements, updates)
        .await
        .expect_err("requirement mismatch must fail the commit");
    // iceberg surfaces a failed requirement as a data-invalid/unexpected error.
    assert_ne!(err.kind(), ErrorKind::TableNotFound);

    // No property leaked into the table.
    let meta = cat.resolve_metadata(&ident).await?;
    let no_leak = meta.properties().get("k").is_none();
    assert!(no_leak);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "commit_table_rejects_failed_requirement",
        no_leak && err.kind() != ErrorKind::TableNotFound,
        &format!(
            "commit rejected (kind={:?}), no property leak={no_leak}",
            err.kind()
        ),
    );
    Ok(())
}

#[tokio::test]
async fn commit_table_missing_table_is_not_found() -> Result<()> {
    use iceberg::{ErrorKind, TableUpdate};

    let tmp = TempDir::new()?;
    let cat = make_catalog(&tmp).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let ident = TableIdent::new(ns, "ghost".to_string());
    let updates = vec![TableUpdate::SetProperties {
        updates: HashMap::from([("k".to_string(), "v".to_string())]),
    }];
    let err = cat
        .commit_table(ident, Vec::new(), updates)
        .await
        .expect_err("commit on missing table");
    let is_not_found = err.kind() == ErrorKind::TableNotFound;
    assert!(is_not_found);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "catalog",
        "commit_table_missing_table_is_not_found",
        is_not_found,
        &format!("err.kind={:?} (want TableNotFound)", err.kind()),
    );
    Ok(())
}
