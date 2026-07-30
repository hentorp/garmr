//! Breakdown: which part of decode_block is slowest?
//! Run: cargo test --release stage_breakdown -- --nocapture --ignored

use lbzip2::BLOCK_MAGIC;
use lbzip2::FINAL_MAGIC;
use lbzip2::bitreader::BitReader;
use lbzip2::bwt;
use lbzip2::huffman::HuffmanTree;
use lbzip2::mtf::MtfDecoder;
use std::time::{Duration, Instant};

#[test]
fn stage_breakdown() {
    let data = include_bytes!("../test_data/liechtenstein.osm.bz2");
    let level = data[3] - b'0';
    let max_blocksize = 100_000 * level as u32;

    println!("\n=== Decode Stage Breakdown (71 blocks, best of 3 full runs) ===\n");

    // Time the full pipeline 3 times, take the best
    let mut best_total = Duration::MAX;
    let mut best_huffman = Duration::MAX;
    let mut best_bwt = Duration::MAX;
    let mut best_rle2 = Duration::MAX;
    let mut best_header = Duration::MAX;

    for _ in 0..3 {
        let mut t_header = Duration::ZERO;
        let mut t_huffman = Duration::ZERO;
        let mut t_bwt = Duration::ZERO;
        let mut t_rle2 = Duration::ZERO;
        let total_start = Instant::now();

        let mut reader = BitReader::from_bit_offset(data, 4 * 8);

        loop {
            let magic = reader.read_u64(48).unwrap();
            if magic == FINAL_MAGIC {
                break;
            }
            assert_eq!(magic, BLOCK_MAGIC);

            // ── Header + bitmap + selector + huffman trees ──
            let hdr_start = Instant::now();
            let _crc = reader.read_u32(32).unwrap();
            let randomised = reader.read_bit().unwrap();
            assert!(!randomised);
            let orig_ptr = reader.read_u32(24).unwrap() as usize;

            let mut used_bytes: Vec<u8> = Vec::new();
            let mut ranges_present = [false; 16];
            for range in &mut ranges_present {
                *range = reader.read_bit().unwrap();
            }
            for (range_idx, &present) in ranges_present.iter().enumerate() {
                if !present {
                    continue;
                }
                for sub in 0..16u8 {
                    if reader.read_bit().unwrap() {
                        used_bytes.push(range_idx as u8 * 16 + sub);
                    }
                }
            }
            let n_symbols = used_bytes.len() + 2;

            let n_groups = reader.read_u8(3).unwrap();
            let n_selectors = reader.read_u16(15).unwrap() as usize;
            let mut selectors = Vec::with_capacity(n_selectors);
            let mut sel_mtf = MtfDecoder::new();
            for _ in 0..n_selectors {
                let mut trees = 0u8;
                while reader.read_bit().unwrap() {
                    trees += 1;
                }
                selectors.push(sel_mtf.decode(trees));
            }

            let mut trees: Vec<HuffmanTree> = Vec::with_capacity(n_groups as usize);
            for _ in 0..n_groups {
                let mut length = reader.read_u8(5).unwrap() as i32;
                let mut lengths = Vec::with_capacity(n_symbols);
                for _ in 0..n_symbols {
                    loop {
                        if !reader.read_bit().unwrap() {
                            break;
                        }
                        if reader.read_bit().unwrap() {
                            length -= 1;
                        } else {
                            length += 1;
                        }
                    }
                    lengths.push(length as u8);
                }
                trees.push(HuffmanTree::from_lengths(&lengths).unwrap());
            }
            t_header += hdr_start.elapsed();

            // ── Huffman decode + MTF + RLE1 → tt array ──
            let huff_start = Instant::now();
            let mut tt: Vec<u32> = Vec::with_capacity(max_blocksize as usize);
            let mut c = [0u32; 256];
            let mut byte_symbols = [0u8; 256];
            byte_symbols[..used_bytes.len()].copy_from_slice(&used_bytes);
            let mut mtf = MtfDecoder::with_symbols(byte_symbols);

            let mut sel_idx: usize = 0;
            let mut decoded_in_group: usize = 0;
            let mut current_tree = &trees[selectors[0] as usize];
            let mut repeat: u32 = 0;
            let mut repeat_power: u32 = 0;
            let eob_symbol = (n_symbols - 1) as u16;

            loop {
                if decoded_in_group == 50 {
                    sel_idx += 1;
                    current_tree = &trees[selectors[sel_idx] as usize];
                    decoded_in_group = 0;
                }
                let sym = current_tree.decode(&mut reader).unwrap();
                decoded_in_group += 1;
                if sym < 2 {
                    if repeat == 0 {
                        repeat_power = 1;
                    }
                    repeat += repeat_power << sym;
                    repeat_power <<= 1;
                    continue;
                }
                if repeat > 0 {
                    let b = mtf.first();
                    let new_len = tt.len() + repeat as usize;
                    tt.resize(new_len, u32::from(b));
                    c[b as usize] += repeat;
                    repeat = 0;
                }
                if sym == eob_symbol {
                    break;
                }
                let b = mtf.decode((sym - 1) as u8);
                tt.push(u32::from(b));
                c[b as usize] += 1;
            }
            t_huffman += huff_start.elapsed();

            // ── Inverse BWT ──
            let bwt_start = Instant::now();
            let mut t_pos = bwt::inverse_bwt(&mut tt, orig_ptr, c).expect("consistent block");
            t_bwt += bwt_start.elapsed();

            // ── RLE2 decode ──
            let rle2_start = Instant::now();
            let mut output = Vec::with_capacity(tt.len());
            let mut last_byte: i16 = -1;
            let mut byte_repeats: u8 = 0;
            let mut pre_rle_used: usize = 0;
            while pre_rle_used < tt.len() {
                let b = bwt::next_byte(&tt, &mut t_pos);
                pre_rle_used += 1;
                if byte_repeats == 3 {
                    for _ in 0..b {
                        output.push(last_byte as u8);
                    }
                    byte_repeats = 0;
                    last_byte = -1;
                    continue;
                }
                if last_byte == i16::from(b) {
                    byte_repeats += 1;
                } else {
                    byte_repeats = 0;
                }
                last_byte = i16::from(b);
                output.push(b);
            }
            t_rle2 += rle2_start.elapsed();
        }
        let total = total_start.elapsed();

        if total < best_total {
            best_total = total;
            best_header = t_header;
            best_huffman = t_huffman;
            best_bwt = t_bwt;
            best_rle2 = t_rle2;
        }
    }

    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let pct = |d: Duration| d.as_secs_f64() / best_total.as_secs_f64() * 100.0;

    println!(
        "Header+bitmap+selectors+trees:  {:>7.1} ms  ({:>5.1}%)",
        ms(best_header),
        pct(best_header)
    );
    println!(
        "Huffman decode + MTF + RLE1:     {:>7.1} ms  ({:>5.1}%)",
        ms(best_huffman),
        pct(best_huffman)
    );
    println!(
        "Inverse BWT:                     {:>7.1} ms  ({:>5.1}%)",
        ms(best_bwt),
        pct(best_bwt)
    );
    println!(
        "RLE2 + output:                   {:>7.1} ms  ({:>5.1}%)",
        ms(best_rle2),
        pct(best_rle2)
    );
    println!("───────────────────────────────────────────────");
    println!(
        "Total:                           {:>7.1} ms  (100.0%)",
        ms(best_total)
    );
}
