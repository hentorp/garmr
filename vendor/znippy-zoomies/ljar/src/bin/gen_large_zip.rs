//! Generate a large synthetic JAR/ZIP for benchmarking.
//!
//! Creates a ZIP with many .class-like entries totaling ~10GB uncompressed.
//! Each entry is compressible (Java class file-like patterns).
//!
//! Usage: cargo run --release --bin gen_large_zip -- /tmp/large_test.zip 10

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("/tmp/large_test.zip");
    let target_gb: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);

    let target_bytes = target_gb * 1024 * 1024 * 1024;
    // Each "class file" is ~64KB uncompressed (realistic for large classes)
    let entry_size = 64 * 1024;
    let num_entries = target_bytes / entry_size;

    eprintln!(
        "Generating {output_path}: {num_entries} entries × {entry_size} bytes = {target_gb} GB uncompressed"
    );

    let file = std::fs::File::create(output_path).expect("create output file");
    let buf_writer = std::io::BufWriter::with_capacity(4 * 1024 * 1024, file);
    let mut zw = zip::ZipWriter::new(buf_writer);

    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(6));

    // Pre-generate a class-like template (compressible, realistic)
    let template = make_class_template(entry_size);

    let start = std::time::Instant::now();
    let mut total_uncompressed = 0u64;

    for i in 0..num_entries {
        let name = format!("com/example/gen/Class{:06}.class", i);
        zw.start_file(&name, opts).expect("start_file");

        // Vary the data slightly per entry (so entries aren't identical)
        let mut entry_data = template.clone();
        // Patch first 8 bytes with entry index (simulating different constant pools)
        let idx_bytes = (i as u64).to_le_bytes();
        entry_data[4..12].copy_from_slice(&idx_bytes);
        // Patch bytes at 1/3 and 2/3 to add variety
        let third = entry_size / 3;
        entry_data[third..third + 8]
            .copy_from_slice(&(i as u64).wrapping_mul(0x517cc1b727220a95).to_le_bytes());
        entry_data[2 * third..2 * third + 8]
            .copy_from_slice(&(i as u64).wrapping_mul(0x6c62272e07bb0142).to_le_bytes());

        zw.write_all(&entry_data).expect("write entry");
        total_uncompressed += entry_data.len() as u64;

        if i % 10000 == 0 && i > 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let pct = (i as f64 / num_entries as f64) * 100.0;
            let rate = total_uncompressed as f64 / elapsed / 1e6;
            eprintln!("  {pct:.1}% ({i}/{num_entries}) — {rate:.0} MB/s compress");
        }
    }

    let mut inner = zw.finish().expect("finish zip");
    inner.flush().expect("flush");

    let elapsed = start.elapsed();
    let compressed_size = std::fs::metadata(output_path).unwrap().len();
    eprintln!(
        "Done in {:.1}s: {} entries, {:.2} GB uncompressed, {:.2} GB compressed ({:.1}% ratio)",
        elapsed.as_secs_f64(),
        num_entries,
        total_uncompressed as f64 / 1e9,
        compressed_size as f64 / 1e9,
        compressed_size as f64 / total_uncompressed as f64 * 100.0,
    );
}

/// Generate a class-file-like byte pattern that compresses well.
fn make_class_template(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    // Java class file magic
    data.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    // Version (Java 17)
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x3D]);
    // Constant pool-like structure (lots of repetitive tag bytes + utf8)
    let pool_entries = &[
        b"java/lang/Object\x00" as &[u8],
        b"java/lang/String\x00",
        b"java/util/ArrayList\x00",
        b"java/util/HashMap\x00",
        b"com/example/service/AbstractServiceFactory\x00",
        b"org/springframework/beans/factory/BeanFactory\x00",
        b"<init>\x00()V\x00",
        b"getLogger\x00(Ljava/lang/Class;)Lorg/slf4j/Logger;\x00",
        b"SourceFile\x00Code\x00LineNumberTable\x00LocalVariableTable\x00",
        b"StackMapTable\x00Exceptions\x00InnerClasses\x00",
    ];

    while data.len() < size {
        for entry in pool_entries {
            if data.len() + entry.len() + 3 > size {
                break;
            }
            data.push(0x01); // CONSTANT_Utf8 tag
            let len = entry.len() as u16;
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(entry);
        }
        // Method bytecode-like padding (repetitive opcodes)
        let remaining = size.saturating_sub(data.len());
        let chunk = remaining.min(256);
        for j in 0..chunk {
            data.push(match j % 8 {
                0 => 0x2A, // aload_0
                1 => 0xB7, // invokespecial
                2 => 0x00,
                3 => 0x01,
                4 => 0xB1, // return
                5 => 0x00,
                6 => 0x2A, // aload_0
                _ => 0xB4, // getfield
            });
        }
    }
    data.truncate(size);
    data
}
