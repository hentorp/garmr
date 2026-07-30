use bindgen::EnumVariation;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let mut build = cc::Build::new();
    build
        .include("zstd/lib")
        .include("zstd/lib/common")
        .include("zstd/lib/compress")
        .include("zstd/lib/decompress")
        .include("zstd/include")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-march=native")
        .define("ZSTD_MULTITHREAD", None)
        .define("ZSTD_STATIC_LINKING_ONLY", None)
        .files([
            // common
            "zstd/lib/common/debug.c",
            "zstd/lib/common/entropy_common.c",
            "zstd/lib/common/error_private.c",
            "zstd/lib/common/fse_decompress.c",
            "zstd/lib/common/pool.c",
            "zstd/lib/common/threading.c",
            "zstd/lib/common/xxhash.c",
            "zstd/lib/common/zstd_common.c",
            // compress
            "zstd/lib/compress/fse_compress.c",
            "zstd/lib/compress/huf_compress.c",
            "zstd/lib/compress/hist.c",
            "zstd/lib/compress/zstd_compress.c",
            "zstd/lib/compress/zstd_compress_literals.c",
            "zstd/lib/compress/zstd_compress_sequences.c",
            "zstd/lib/compress/zstd_compress_superblock.c",
            "zstd/lib/compress/zstd_double_fast.c",
            "zstd/lib/compress/zstd_fast.c",
            "zstd/lib/compress/zstd_lazy.c",
            "zstd/lib/compress/zstd_ldm.c",
            "zstd/lib/compress/zstd_opt.c",
            "zstd/lib/compress/zstd_preSplit.c",
            "zstd/lib/compress/zstdmt_compress.c",
            // decompress
            "zstd/lib/decompress/zstd_decompress.c",
            "zstd/lib/decompress/zstd_ddict.c",
            "zstd/lib/decompress/zstd_decompress_block.c",
            "zstd/lib/decompress/huf_decompress.c",
        ]);

    // Plattformsspecifik ASM
    if cfg!(target_arch = "x86_64") {
        build.file("zstd/lib/decompress/huf_decompress_amd64.S");
    } else if cfg!(target_arch = "aarch64") {
        build.file("zstd/lib/decompress/huf_decompress_arm64.S");
    }

    build.compile("zstd");

    println!("cargo:rustc-link-lib=static=zstd");

    // Bindings
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-DZSTD_STATIC_LINKING_ONLY")
        .clang_arg("-DZSTD_MULTITHREAD")
        .clang_arg("-Izstd/include")
        .clang_arg("-Izstd/lib")
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
        .allowlist_function("ZSTD_.*")
        .allowlist_var("ZSTD_.*")
        .allowlist_var("ZSTD_e_.*")
        .allowlist_var("ZSTD_cParameter_.*")
        .allowlist_type("ZSTD_cParameter")
        .allowlist_type("ZSTD_EndDirective")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!(
        "cargo:warning=Bindings written to: {}",
        out_path.join("bindings.rs").display()
    );
}
