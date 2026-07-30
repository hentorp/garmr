//! Profile individual decode stages to identify optimization targets.
//!
//! Run: cargo test --release profile_stages -- --nocapture --ignored

use lbzip2::BLOCK_MAGIC;
use lbzip2::FINAL_MAGIC;
use lbzip2::bitreader::BitReader;
use lbzip2::block;
use std::time::Instant;

#[test]
fn profile_stages() {
    let data = include_bytes!("../test_data/liechtenstein.osm.bz2");

    println!("\n=== Stage Profiling ===");

    // Count blocks
    let mut reader = BitReader::from_bit_offset(data, 4 * 8);
    let mut block_count = 0;
    loop {
        let magic = reader.read_u64(48).unwrap();
        if magic == BLOCK_MAGIC {
            block_count += 1;
            let level = data[3] - b'0';
            let _ = block::decode_block(&mut reader, 100_000 * level as u32).unwrap();
        } else if magic == FINAL_MAGIC {
            break;
        }
    }
    println!("Blocks in file: {}", block_count);

    // Time the full decode 5 times
    let mut times = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let _ = lbzip2::stream::decompress(data).unwrap();
        times.push(start.elapsed());
    }
    let best = times.iter().min().unwrap();
    println!("Best full decode: {:.1} ms", best.as_secs_f64() * 1000.0);
    println!(
        "Per block avg: {:.2} ms",
        best.as_secs_f64() * 1000.0 / block_count as f64
    );
}
