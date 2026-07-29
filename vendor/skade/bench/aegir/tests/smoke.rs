//! Live S3 round-trip against `AEGIR_S3_ENDPOINT` (e.g. a RustFS container).
//! Skips cleanly when unset.

#[test]
fn aegir_round_trip() {
    let ep = match std::env::var("AEGIR_S3_ENDPOINT") {
        Ok(e) if !e.is_empty() => e,
        _ => {
            eprintln!("[skip] AEGIR_S3_ENDPOINT unset");
            return;
        }
    };
    let ak = std::env::var("AEGIR_S3_KEY").unwrap_or_else(|_| "rustfsadmin".into());
    let sk = std::env::var("AEGIR_S3_SECRET").unwrap_or_else(|_| "rustfsadmin".into());
    let c = aegir::Client::new(ep.clone(), "us-east-1", ak.clone(), sk.clone());

    round_trip(&c, "aegir-smoke");

    // With the `uring` feature on, run the identical round-trip through the
    // io_uring transport (plaintext only). Proves SigV4 + semantics are transport-
    // independent against a live RustFS.
    #[cfg(feature = "uring")]
    if !ep.starts_with("https://") {
        let cu = aegir::Client::new(ep, "us-east-1", ak, sk)
            .with_transport(aegir::Transport::Uring);
        assert_eq!(cu.effective_transport(), aegir::Transport::Uring, "uring transport should be active");
        round_trip(&cu, "aegir-smoke-uring");
        eprintln!("aegir uring round-trip ✓");
    }
}

fn round_trip(c: &aegir::Client, bucket: &str) {
    c.create_bucket(bucket).expect("create_bucket");
    let key = "wh/data/hello.txt";
    c.put_object(bucket, key, b"hello aegir", Some("text/plain")).expect("put");
    assert!(c.head_object(bucket, key).expect("head"), "object should exist after put");
    let got = c.get_object(bucket, key).expect("get");
    assert_eq!(&got[..], b"hello aegir", "round-trip body mismatch");
    let listed = c.list_objects(bucket, "wh/").expect("list");
    assert!(listed.iter().any(|k| k == key), "list missing key: {listed:?}");
    c.delete_object(bucket, key).expect("delete");
    assert!(!c.head_object(bucket, key).expect("head after delete"), "object should be gone");
    eprintln!("aegir round-trip ✓ (create/put/head/get/list/delete)");
}
