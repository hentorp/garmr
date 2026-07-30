use std::io::Write as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::var("OUT_DIR")?;

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&out)
        .inputs(["proto/fileformat.proto", "proto/osmformat.proto"])
        .include("proto")
        .run()?;

    // Write a mod.rs so that `include!(OUT_DIR/proto_mod.rs)` can declare both
    // generated modules and Rust will resolve them relative to OUT_DIR.
    std::fs::File::create(format!("{out}/proto_mod.rs"))?
        .write_all(b"pub mod fileformat;\npub mod osmformat;\n")?;

    println!("cargo:rerun-if-changed=proto/fileformat.proto");
    println!("cargo:rerun-if-changed=proto/osmformat.proto");

    Ok(())
}
