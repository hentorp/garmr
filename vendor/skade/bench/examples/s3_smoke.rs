//! Keystone smoke test: round-trip through the rust-s3-backed iceberg `Storage`
//! against a running RustFS (`containers/rustfs_up.sh`).
//!
//! Run: cargo run --example s3_smoke

use bytes::Bytes;
use iceberg::io::Storage;

#[path = "../src/s3_storage.rs"]
mod s3_storage;
use s3_storage::{ensure_bucket, S3Cfg, S3Storage};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = S3Cfg {
        endpoint: "http://localhost:9000".to_string(),
        region: "us-east-1".to_string(),
        bucket: "warehouse".to_string(),
        access_key_id: "rustfsadmin".to_string(),
        secret_access_key: "rustfsadmin".to_string(),
        path_style: true,
    };
    ensure_bucket(&cfg).await?;
    println!("✓ bucket ensured");

    let st = S3Storage::new(cfg)?;
    let path = "s3://warehouse/smoke/hello.txt";
    let body = Bytes::from_static(b"hello rustfs from iceberg Storage");

    // write via the OutputFile -> FileWrite path (what iceberg uses)
    let out = st.new_output(path)?;
    let mut w = out.writer().await?;
    w.write(body.clone()).await?;
    w.close().await?;
    println!("✓ wrote {} bytes", body.len());

    // metadata + exists
    let meta = st.metadata(path).await?;
    assert_eq!(meta.size, body.len() as u64, "size mismatch");
    assert!(st.exists(path).await?, "should exist");
    assert!(!st.exists("s3://warehouse/smoke/nope.txt").await?, "should not exist");
    println!("✓ metadata.size={} exists=true", meta.size);

    // full read
    let got = st.read(path).await?;
    assert_eq!(got, body, "read mismatch");
    println!("✓ full read matches");

    // ranged read via InputFile -> FileRead
    let inp = st.new_input(path)?;
    let r = inp.reader().await?;
    let range = r.read(6..11).await?; // "rustf"
    assert_eq!(&range[..], &body[6..11], "range mismatch");
    println!("✓ ranged read [6..11] = {:?}", String::from_utf8_lossy(&range));

    // delete + confirm gone
    st.delete(path).await?;
    assert!(!st.exists(path).await?, "should be deleted");
    println!("✓ delete confirmed");

    println!("\nALL S3 STORAGE ROUND-TRIPS PASSED ✅");
    Ok(())
}
