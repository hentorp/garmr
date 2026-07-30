//! Bring up / tear down the bench's competitor backends — **RustFS** (S3),
//! **Nessie** (RocksDB + Iceberg REST), **Polaris** (Quarkus + Iceberg REST) —
//! in Rust, ported from the old `containers/*.sh`. Every operational gotcha we
//! hit bringing these up is encoded here as a **pre-check** (refuse early with a
//! clear message) or a **pre-check-fix** (repair automatically), so a fresh
//! machine gets a working stack from `bench-containers up all`:
//!
//! - **engine detection** — podman preferred (docker has rootless quirks here).
//! - **stale container** — `rm -f` the named container before (re)starting.
//! - **RustFS named volume** — a named volume sidesteps the UID-10001 ownership
//!   requirement a bind mount would impose.
//! - **Nessie → RustFS gateway** — Nessie reaches the host-published S3 endpoint
//!   via `host.containers.internal`; the bench client uses `localhost`.
//! - **Nessie needs S3** — if RustFS isn't up, start it first (dependency).
//! - **Nessie takes no OAuth** — its client must NOT be handed `credential=…`
//!   (it answers `501` on `/v1/oauth/tokens`); that's a bench-run env concern,
//!   flagged in [`up_all`]'s closing notes.
//! - **Polaris UID mapping** — Polaris runs as container uid 10000; without a
//!   userns map it writes the bind-mounted warehouse as a subuid the bench
//!   client can't write alongside (first a `503` writing metadata, then `EACCES`
//!   on the data dir). `--userns=keep-id:uid=10000,gid=10001` makes all warehouse
//!   writes land as the host user, so server + client share it cleanly.
//! - **Polaris stale warehouse** — a prior non-userns run leaves subuid-owned
//!   files the host user can't delete; we wipe them via `<engine> unshare rm`.
//! - **Polaris feature flags** — FILE storage needs three quoted-key feature
//!   flags passed as `-D` (JVM) props, not `-e` (Quarkus strips the quotes).
//! - **Polaris bootstrap** — fetch an OAuth token and create the FILE catalog.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

const RUSTFS: &str = "nornir-bench-rustfs";
const NESSIE: &str = "nornir-bench-nessie";
const POLARIS: &str = "nornir-bench-polaris";
const POLARIS_WH: &str = "/tmp/nornir_bench_wh";
const SPARK: &str = "nornir-bench-spark";
/// Built from `knut/containers/spark-iceberg/Containerfile` (Spark 4.2 + Iceberg
/// 1.11, Hadoop `lake` catalog). `podman build -t knut-spark-iceberg …`.
const SPARK_IMAGE: &str = "knut-spark-iceberg";
/// Host path that MUST match the container's catalog warehouse — the Hadoop
/// catalog writes absolute `/tmp/warehouse/...` paths into the metadata, so skade
/// reads the copied-out tree at the same absolute path.
const SPARK_WH: &str = "/tmp/warehouse";

// ---- engine + small process/HTTP helpers -----------------------------------

/// Detected container engine. podman first — its rootless userns is what the
/// Polaris UID fix relies on; docker is accepted as a fallback.
fn engine() -> Result<&'static str> {
    for bin in ["podman", "docker"] {
        let ok = Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(if bin == "podman" { "podman" } else { "docker" });
        }
    }
    bail!("pre-check failed: need `podman` (preferred) or `docker` on PATH")
}

fn run(bin: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin).args(args).output().with_context(|| format!("{bin} {args:?}"))?;
    if !out.status.success() {
        bail!("{bin} {}: {}", args.first().copied().unwrap_or(""), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn rm_force(bin: &str, name: &str) {
    let _ = Command::new(bin).args(["rm", "-f", name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

fn running(bin: &str, name: &str) -> bool {
    run(bin, &["ps", "--filter", &format!("name={name}"), "--format", "{{.Names}}"])
        .map(|s| s.lines().any(|l| l.trim() == name))
        .unwrap_or(false)
}

fn http() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(3)).build()
}

/// A backend is "up" once its endpoint answers at all (any non-5xx — an
/// unauthenticated 4xx still proves the port is serving). ureq surfaces a 4xx/5xx
/// as `Err(Status)`, so a 4xx (e.g. RustFS's `403` on `/`) counts as up.
fn http_up(url: &str) -> bool {
    match http().get(url).call() {
        Ok(_) => true,
        Err(ureq::Error::Status(code, _)) => code < 500,
        Err(_) => false, // transport error (connection refused / DNS) ⇒ down
    }
}

fn poll(label: &str, secs: u64, ready: impl Fn() -> bool) -> Result<()> {
    for i in 0..secs {
        if ready() {
            eprintln!("✅ {label} ready after {i}s");
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    bail!("timeout waiting for {label} after {secs}s")
}

// ---- RustFS (shared S3 warehouse) ------------------------------------------

/// Host port the RustFS S3 endpoint is published on — configurable via
/// `BENCH_RUSTFS_PORT` (default `9000`) so it can dodge a host-port clash (e.g. a
/// Njord MinIO `kubectl port-forward` already holding :9000). The container's
/// internal port stays 9000; only the host publish + the S3-client / Nessie-gateway
/// endpoints follow this. When you override it, also set
/// `BENCH_S3_ENDPOINT=http://localhost:<port>` for the bench client.
pub fn rustfs_port() -> String {
    std::env::var("BENCH_RUSTFS_PORT").unwrap_or_else(|_| "9000".into())
}

pub fn rustfs_up() -> Result<()> {
    let bin = engine()?;
    rm_force(bin, RUSTFS);
    // pre-check-fix: a named volume avoids the UID-10001 ownership a bind mount needs.
    let _ = run(bin, &["volume", "create", "nornir_bench_rustfs_data"]);
    let port = rustfs_port();
    let console = std::env::var("BENCH_RUSTFS_CONSOLE_PORT").unwrap_or_else(|_| "9001".into());
    let publish = format!("{port}:9000");
    let publish_console = format!("{console}:9001");
    eprintln!("🚀 RustFS S3 on :{port} (console :{console})");
    run(bin, &[
        "run", "-d", "--name", RUSTFS,
        "-p", &publish, "-p", &publish_console,
        "-v", "nornir_bench_rustfs_data:/data",
        "-e", "RUSTFS_ACCESS_KEY=rustfsadmin",
        "-e", "RUSTFS_SECRET_KEY=rustfsadmin",
        "-e", "RUSTFS_CONSOLE_ENABLE=true",
        "docker.io/rustfs/rustfs:latest", "/data",
    ])?;
    let health = format!("http://localhost:{port}/");
    poll("RustFS", 60, || http_up(&health))?;
    eprintln!("   S3: http://localhost:{port}  (rustfsadmin/rustfsadmin); the bench client creates the `warehouse` bucket on first use");
    Ok(())
}

// ---- Nessie (RocksDB + Iceberg REST over the shared S3) ---------------------

pub fn nessie_up() -> Result<()> {
    let bin = engine()?;
    // pre-check-fix: Nessie's warehouse is the shared S3 — bring RustFS up first.
    if !running(bin, RUSTFS) {
        eprintln!("⚙ RustFS not running — starting it first (Nessie's warehouse is the shared S3)");
        rustfs_up()?;
    }
    rm_force(bin, NESSIE);
    eprintln!("🚀 Nessie (RocksDB) on :19120, warehouse s3://warehouse/wh");
    // Nessie (in the container) reaches the host-published S3 via the gateway —
    // follow BENCH_RUSTFS_PORT so it tracks a relocated RustFS (see rustfs_port).
    let nessie_s3_endpoint = format!(
        "nessie.catalog.service.s3.default-options.endpoint=http://host.containers.internal:{}",
        rustfs_port(),
    );
    run(bin, &[
        "run", "-d", "--name", NESSIE, "-p", "19120:19120",
        "-e", "nessie.version.store.type=ROCKSDB",
        "-e", "nessie.version.store.persist.rocks.database-path=/tmp/rocksdb",
        "-e", "nessie.catalog.default-warehouse=warehouse",
        "-e", "nessie.catalog.warehouses.warehouse.location=s3://warehouse/wh",
        "-e", "nessie.catalog.service.s3.default-options.region=us-east-1",
        "-e", &nessie_s3_endpoint,
        "-e", "nessie.catalog.service.s3.default-options.path-style-access=true",
        "-e", "nessie.catalog.service.s3.default-options.auth-type=STATIC",
        "-e", "nessie.catalog.service.s3.default-options.access-key=urn:nessie-secret:quarkus:nessie.catalog.secrets.access-key",
        "-e", "nessie.catalog.secrets.access-key.name=rustfsadmin",
        "-e", "nessie.catalog.secrets.access-key.secret=rustfsadmin",
        "ghcr.io/projectnessie/nessie:latest",
    ])?;
    poll("Nessie", 120, || http_up("http://localhost:19120/iceberg/v1/config"))?;
    eprintln!("   REST: http://localhost:19120/iceberg  (no OAuth — do NOT set BENCH_REST_PROPS for the Nessie client)");
    Ok(())
}

// ---- Polaris (Quarkus + Iceberg REST, FILE warehouse) ----------------------

/// pre-check-fix: remove a stale warehouse. After a non-userns run its files are
/// owned by a subuid the host user can't `rm`; delete them inside the engine's
/// user namespace (`podman unshare`), falling back to a plain remove.
fn clean_polaris_warehouse(bin: &str) -> Result<()> {
    if !Path::new(POLARIS_WH).exists() {
        return Ok(());
    }
    if std::fs::remove_dir_all(POLARIS_WH).is_ok() {
        return Ok(());
    }
    if bin == "podman" {
        let _ = Command::new("podman").args(["unshare", "rm", "-rf", POLARIS_WH]).status();
    }
    // Last resort if anything survived (e.g. docker): best-effort.
    let _ = std::fs::remove_dir_all(POLARIS_WH);
    Ok(())
}

pub fn polaris_up() -> Result<()> {
    let bin = engine()?;
    rm_force(bin, POLARIS);
    clean_polaris_warehouse(bin)?;
    std::fs::create_dir_all(POLARIS_WH).with_context(|| format!("create {POLARIS_WH}"))?;
    eprintln!("🚀 Polaris on :8181 (mgmt :8182), FILE warehouse {POLARIS_WH}");
    run(bin, &[
        "run", "-d", "--name", POLARIS,
        "-p", "8181:8181", "-p", "8182:8182",
        "-v", &format!("{POLARIS_WH}:{POLARIS_WH}:z"),
        // FIX: map container uid 10000 (the `polaris` user) to the host user, so
        // metadata/data it writes to the bind mount is host-owned and the bench
        // client can write alongside it (else 503 on metadata, then EACCES on data).
        "--userns=keep-id:uid=10000,gid=10001",
        "-e", "POLARIS_BOOTSTRAP_CREDENTIALS=POLARIS,root,s3cr3t",
        "-e", "polaris.persistence.type=in-memory",
        "-e", "polaris.readiness.ignore-severe-issues=true",
        // For the (attempted) S3 catalog: feed RustFS creds via the AWS provider
        // chain — Polaris vends *subscoped* creds and ignores the catalog's static
        // creds for that step, so without these it fails at credential loading.
        "-e", "AWS_ACCESS_KEY_ID=rustfsadmin",
        "-e", "AWS_SECRET_ACCESS_KEY=rustfsadmin",
        "-e", "AWS_REGION=us-east-1",
        // Storage gated by feature flags whose keys carry a quoted segment; passed
        // as JVM -D props so the quotes survive (a bare -e would have Quarkus
        // reject them as "does not map to any root"). FILE works end-to-end; S3 is
        // enabled + SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION clears the STS wall, but
        // the vended S3FileIO still 301s against RustFS (path-style not honored on
        // the data write) — so the S3 catalog is created best-effort, FILE is the
        // one the bench relies on.
        "-e", r#"JAVA_OPTS_APPEND=-Dpolaris.features."SUPPORTED_CATALOG_STORAGE_TYPES"=["FILE","S3"] -Dpolaris.features."ALLOW_INSECURE_STORAGE_TYPES"=true -Dpolaris.features."ALLOW_SPECIFYING_FILE_IO_IMPL"=true -Dpolaris.features."SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION"=true"#,
        "docker.io/apache/polaris:latest",
    ])?;
    poll("Polaris", 120, || http_up("http://localhost:8182/q/health"))?;
    polaris_bootstrap()?;
    eprintln!("   REST: http://localhost:8181/api/catalog  (client creds root/s3cr3t via BENCH_POLARIS_CRED)");
    Ok(())
}

/// OAuth token → create the FILE-backed `warehouse` catalog (idempotent).
fn polaris_bootstrap() -> Result<()> {
    eprintln!("🔑 Polaris OAuth token + catalog bootstrap…");
    let agent = http();
    let resp = agent
        .post("http://localhost:8181/api/catalog/v1/oauth/tokens")
        .send_form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "root"),
            ("client_secret", "s3cr3t"),
            ("scope", "PRINCIPAL_ROLE:ALL"),
        ])
        .context("polaris oauth token request")?;
    let token = resp
        .into_json::<serde_json::Value>()?
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("polaris token response had no access_token"))?;

    // The FILE catalog the bench relies on (works end-to-end).
    let file_cat = serde_json::json!({
        "catalog": {
            "name": "warehouse",
            "type": "INTERNAL",
            "properties": { "default-base-location": format!("file://{POLARIS_WH}") },
            "storageConfigInfo": {
                "storageType": "FILE",
                "allowedLocations": [format!("file://{POLARIS_WH}")]
            }
        }
    });
    create_catalog(&agent, &token, "warehouse", file_cat)?;

    // Best-effort S3 catalog over RustFS. Cleared the STS wall (skip-subscoping +
    // AWS env), but the vended S3FileIO 301s on the data write (path-style not
    // applied) — so this may exist yet not serve writes. Kept so the slot is ready
    // if a future Polaris/RustFS combo honors path-style on vended creds.
    let s3_cat = serde_json::json!({
        "catalog": {
            "name": "wh_s3",
            "type": "INTERNAL",
            "properties": {
                "default-base-location": "s3://warehouse/pol",
                "s3.endpoint": "http://host.containers.internal:9000",
                "s3.path-style-access": "true",
                "s3.access-key-id": "rustfsadmin",
                "s3.secret-access-key": "rustfsadmin",
                "s3.region": "us-east-1"
            },
            "storageConfigInfo": {
                "storageType": "S3",
                "allowedLocations": ["s3://warehouse/pol"],
                "roleArn": "arn:aws:iam::000000000000:role/polaris",
                "endpoint": "http://host.containers.internal:9000",
                "pathStyleAccess": true,
                "region": "us-east-1"
            }
        }
    });
    create_catalog(&agent, &token, "wh_s3 (best-effort S3)", s3_cat)?;
    Ok(())
}

fn create_catalog(agent: &ureq::Agent, token: &str, label: &str, body: serde_json::Value) -> Result<()> {
    match agent
        .post("http://localhost:8181/api/management/v1/catalogs")
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(body)
    {
        Ok(_) => eprintln!("✅ catalog '{label}' created"),
        Err(ureq::Error::Status(409, _)) => eprintln!("✅ catalog '{label}' already exists"),
        Err(ureq::Error::Status(c, _)) => eprintln!("⚠️ catalog '{label}' create returned HTTP {c}"),
        Err(e) => return Err(anyhow!("polaris catalog '{label}' create: {e}")),
    }
    Ok(())
}

// ---- Spark + Iceberg (the external "skade vs Spark" baseline) --------------

/// Bring up Spark+Iceberg and have **Spark** write a `rows`-row Iceberg table
/// (`lake.db.t`, Hadoop catalog), then copy the warehouse to the host at
/// [`SPARK_WH`] so skade can read the SAME table. Prints Spark's write time;
/// read it back with the `skade_reads_spark` example to compare scan speed.
pub fn spark_up(rows: u64) -> Result<()> {
    let bin = engine()?;
    rm_force(bin, SPARK);
    eprintln!("🚀 Spark 4.2 + Iceberg 1.11 (Hadoop `lake` catalog → {SPARK_WH})");
    // Detached: the Connect-server CMD keeps it alive so we can `exec spark-sql`.
    run(bin, &["run", "-d", "--name", SPARK, SPARK_IMAGE])?;
    std::thread::sleep(Duration::from_secs(6)); // JVM/connect warmup

    let sql = format!(
        "CREATE NAMESPACE IF NOT EXISTS lake.db; \
         CREATE TABLE lake.db.t USING iceberg AS \
         SELECT id, CAST(id AS STRING) AS name FROM range({rows});"
    );
    let t0 = Instant::now();
    run(bin, &[
        "exec", SPARK, "/opt/spark/bin/spark-sql",
        "--conf", "spark.sql.extensions=org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions",
        "--conf", "spark.sql.catalog.lake=org.apache.iceberg.spark.SparkCatalog",
        "--conf", "spark.sql.catalog.lake.type=hadoop",
        "--conf", "spark.sql.catalog.lake.warehouse=/tmp/warehouse",
        "-e", &sql,
    ])?;
    let secs = t0.elapsed().as_secs_f64();
    eprintln!("   Spark wrote {rows} rows in {secs:.2}s ({:.1} Mrows/s)", rows as f64 / secs / 1e6);

    // Copy the warehouse to the host at the SAME absolute path (Hadoop catalog
    // embeds absolute paths into the metadata/manifests).
    let _ = std::fs::remove_dir_all(SPARK_WH);
    run(bin, &["cp", &format!("{SPARK}:/tmp/warehouse"), SPARK_WH])?;
    eprintln!("   warehouse → {SPARK_WH}; read it with skade:");
    eprintln!(
        "   cargo run --release --example skade_reads_spark -- {SPARK_WH}/db/t/metadata/v1.metadata.json"
    );
    Ok(())
}

pub fn spark_down() -> Result<()> {
    let bin = engine()?;
    rm_force(bin, SPARK);
    eprintln!("⏹  down {SPARK}");
    Ok(())
}

// ---- orchestration ---------------------------------------------------------

pub fn up_all() -> Result<()> {
    rustfs_up()?;
    nessie_up()?;
    polaris_up()?;
    eprintln!("\n✅ stack up. Run the cross-catalog bench (one bencher at a time):");
    eprintln!("   TPCH_COMPARE_SF=0.5 nornir bench run nornir-catalog");
    eprintln!("   (do NOT set BENCH_REST_PROPS — Nessie has no OAuth; Polaris uses BENCH_POLARIS_CRED, default root:s3cr3t)");
    Ok(())
}

pub fn down(service: &str) -> Result<()> {
    let bin = engine()?;
    let name = match service {
        "rustfs" => RUSTFS,
        "nessie" => NESSIE,
        "polaris" => POLARIS,
        other => bail!("unknown service `{other}` (rustfs|nessie|polaris|all)"),
    };
    rm_force(bin, name);
    eprintln!("⏹  down {name}");
    Ok(())
}

pub fn down_all() -> Result<()> {
    let bin = engine()?;
    for n in [RUSTFS, NESSIE, POLARIS] {
        rm_force(bin, n);
    }
    eprintln!("⏹  down all bench containers");
    Ok(())
}

pub fn status() -> Result<()> {
    let bin = engine()?;
    for (svc, name, probe) in [
        ("rustfs", RUSTFS, "http://localhost:9000/"),
        ("nessie", NESSIE, "http://localhost:19120/iceberg/v1/config"),
        ("polaris", POLARIS, "http://localhost:8182/q/health"),
    ] {
        let state = if !running(bin, name) {
            "stopped"
        } else if http_up(probe) {
            "ready"
        } else {
            "starting"
        };
        eprintln!("  {svc:<8} {state}");
    }
    Ok(())
}
