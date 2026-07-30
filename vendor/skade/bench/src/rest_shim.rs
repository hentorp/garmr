//! A thin Iceberg-REST front for nornir-catalog (axum), so the benchmark can
//! compare nornir **over the same HTTP path** as Nessie/Polaris — REST-vs-REST,
//! not embedded-vs-REST.
//!
//! Scope: exactly the endpoints the iceberg-rust REST client exercises in our
//! scenarios (config, namespace create/exists, table create/load/exists/list/
//! drop). Table metadata is forwarded as the raw on-disk JSON (which is the
//! canonical Iceberg metadata document) — nornir's `TableMetadata` is not
//! `Serialize`, but the file already is the wire form, so we splice its bytes
//! into `LoadTableResult` rather than re-serializing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use iceberg::spec::Schema;
use iceberg::{
    Catalog, ErrorKind, NamespaceIdent, TableCreation, TableIdent, TableRequirement, TableUpdate,
};
use skade_katalog::RedbCatalog;
use serde::Deserialize;
use serde_json::{json, Value};

type Cat = Arc<RedbCatalog>;

/// Serve the shim until the process exits. Returns once it is bound + listening.
pub async fn spawn(cat: RedbCatalog, addr: SocketAddr) -> Result<SocketAddr> {
    let state: Cat = Arc::new(cat);
    let app = Router::new()
        .route("/v1/config", get(config))
        .route("/v1/namespaces", get(list_namespaces).post(create_namespace))
        .route("/v1/namespaces/:ns", get(get_namespace).head(head_namespace))
        .route("/v1/namespaces/:ns/tables", get(list_tables).post(create_table))
        .route(
            "/v1/namespaces/:ns/tables/:table",
            get(load_table)
                .head(head_table)
                .delete(drop_table)
                .post(commit_table),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(bound)
}

// Namespace path segments are joined with the unit separator () per the
// Iceberg REST spec; single-level namespaces are just the bare name.
fn parse_ns(s: &str) -> NamespaceIdent {
    let parts: Vec<String> = s.split('\u{1f}').map(|p| p.to_string()).collect();
    NamespaceIdent::from_vec(parts).unwrap_or_else(|_| NamespaceIdent::new(s.to_string()))
}

async fn read_metadata_json(loc: &str) -> Result<Value> {
    let path = loc.strip_prefix("file://").unwrap_or(loc);
    let bytes = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": {"message": msg, "type": "Error", "code": code.as_u16()}}))).into_response()
}

async fn config() -> Response {
    Json(json!({ "overrides": {}, "defaults": {} })).into_response()
}

#[derive(Deserialize)]
struct CreateNamespaceRequest {
    namespace: Vec<String>,
    #[serde(default)]
    properties: HashMap<String, String>,
}

async fn create_namespace(State(cat): State<Cat>, Json(req): Json<CreateNamespaceRequest>) -> Response {
    let ns = match NamespaceIdent::from_vec(req.namespace.clone()) {
        Ok(n) => n,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid namespace"),
    };
    match cat.create_namespace(&ns, req.properties.clone()).await {
        Ok(_) => Json(json!({ "namespace": req.namespace, "properties": req.properties })).into_response(),
        Err(e) => err(StatusCode::CONFLICT, &e.to_string()),
    }
}

async fn head_namespace(State(cat): State<Cat>, Path(ns): Path<String>) -> StatusCode {
    match cat.namespace_exists(&parse_ns(&ns)).await {
        Ok(true) => StatusCode::NO_CONTENT,
        _ => StatusCode::NOT_FOUND,
    }
}

async fn get_namespace(State(cat): State<Cat>, Path(ns): Path<String>) -> Response {
    let nsi = parse_ns(&ns);
    match cat.get_namespace(&nsi).await {
        Ok(n) => Json(json!({ "namespace": nsi.inner(), "properties": n.properties() })).into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn list_namespaces(State(cat): State<Cat>) -> Response {
    match cat.list_namespaces(None).await {
        Ok(list) => {
            let ns: Vec<Vec<String>> = list.into_iter().map(|n| n.inner()).collect();
            Json(json!({ "namespaces": ns })).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn list_tables(State(cat): State<Cat>, Path(ns): Path<String>) -> Response {
    let nsi = parse_ns(&ns);
    match cat.list_tables(&nsi).await {
        Ok(idents) => {
            let ids: Vec<Value> = idents
                .into_iter()
                .map(|t| json!({ "namespace": t.namespace().clone().inner(), "name": t.name() }))
                .collect();
            Json(json!({ "identifiers": ids })).into_response()
        }
        Err(e) => err(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

#[derive(Deserialize)]
struct CreateTableRequest {
    name: String,
    schema: Schema,
    #[serde(default)]
    location: Option<String>,
    // partition-spec / write-order / stage-create / properties are accepted and
    // ignored for the benchmark workload.
}

async fn create_table(State(cat): State<Cat>, Path(ns): Path<String>, Json(req): Json<CreateTableRequest>) -> Response {
    let nsi = parse_ns(&ns);
    // The TableCreation builder is typestate (bon) — branch rather than reassign.
    let creation = match req.location {
        Some(loc) => TableCreation::builder().name(req.name).schema(req.schema).location(loc).build(),
        None => TableCreation::builder().name(req.name).schema(req.schema).build(),
    };
    match cat.create_table(&nsi, creation).await {
        Ok(table) => load_table_result(&table).await,
        Err(e) => err(StatusCode::CONFLICT, &e.to_string()),
    }
}

async fn load_table(State(cat): State<Cat>, Path((ns, table)): Path<(String, String)>) -> Response {
    let ident = TableIdent::new(parse_ns(&ns), table);
    match cat.load_table(&ident).await {
        Ok(t) => load_table_result(&t).await,
        Err(e) => err(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

async fn load_table_result(table: &iceberg::table::Table) -> Response {
    let loc = table.metadata_location().unwrap_or_default().to_string();
    match read_metadata_json(&loc).await {
        Ok(meta) => Json(json!({ "metadata-location": loc, "metadata": meta, "config": {} })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn head_table(State(cat): State<Cat>, Path((ns, table)): Path<(String, String)>) -> StatusCode {
    let ident = TableIdent::new(parse_ns(&ns), table);
    match cat.table_exists(&ident).await {
        Ok(true) => StatusCode::NO_CONTENT,
        _ => StatusCode::NOT_FOUND,
    }
}

async fn drop_table(State(cat): State<Cat>, Path((ns, table)): Path<(String, String)>) -> StatusCode {
    let ident = TableIdent::new(parse_ns(&ns), table);
    match cat.drop_table(&ident).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

// Iceberg-REST commit: apply the request's `requirements` + `updates` against
// the backing `RedbCatalog` and return a `CommitTableResponse`. We can't
// deserialize the wire body into iceberg's `CommitTableRequest`/`TableCommit`
// (the `TableCommit` builder is crate-private to iceberg), so the body is
// captured as the raw `requirements`/`updates` vectors and handed to
// `RedbCatalog::commit_table`, which mirrors `TableCommit::apply` + persists
// through the optimistic group-commit path. The response splices the freshly
// written on-disk metadata JSON in place of a (non-`Serialize`) `TableMetadata`,
// exactly as `load_table_result` does.
#[derive(Deserialize)]
struct CommitTableRequest {
    #[serde(default)]
    requirements: Vec<TableRequirement>,
    #[serde(default)]
    updates: Vec<TableUpdate>,
}

async fn commit_table(
    State(cat): State<Cat>,
    Path((ns, table)): Path<(String, String)>,
    Json(req): Json<CommitTableRequest>,
) -> Response {
    let ident = TableIdent::new(parse_ns(&ns), table);
    match cat.commit_table(ident, req.requirements, req.updates).await {
        Ok(t) => commit_table_result(&t).await,
        Err(e) => {
            let code = match e.kind() {
                ErrorKind::TableNotFound => StatusCode::NOT_FOUND,
                ErrorKind::CatalogCommitConflicts => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            err(code, &e.to_string())
        }
    }
}

// `CommitTableResponse` is `{ metadata-location, metadata }` — same metadata
// JSON-splice trick as `load_table_result`, minus the `config` field.
async fn commit_table_result(table: &iceberg::table::Table) -> Response {
    let loc = table.metadata_location().unwrap_or_default().to_string();
    match read_metadata_json(&loc).await {
        Ok(meta) => Json(json!({ "metadata-location": loc, "metadata": meta })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
