//! A/B benchmark: generic XML scanner (`xml`) vs OSM specialization (`vtd`).
//!
//! Corpus: deterministic synthetic OSM-ish XML (~100 MB) generated in-memory —
//! same byte stream on every run/machine, so numbers are comparable across the
//! refactor (baseline captured against the pre-extraction vtd, see
//! bench_history.json at the crate root if recorded).
//!
//! Run: `cargo bench -p znippy-zoomies --bench xml_scan`

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// ── Deterministic corpus generator ───────────────────────────────────────────

/// xorshift64* — deterministic, no rand dependency in the hot loop.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const TAG_KEYS: [&str; 10] = [
    "highway", "building", "natural", "landuse", "waterway", "railway", "amenity", "boundary",
    "name", "surface",
];

/// Generate ~`target_bytes` of OSM-shaped XML: ~85% nodes (mostly self-closing),
/// ways with nd refs + tags, occasional relations. Mirrors planet-file shape.
fn synth_osm_xml(target_bytes: usize) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(target_bytes + 4096);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<osm version=\"0.6\" generator=\"xml_scan bench\">\n");
    out.push_str(" <bound box=\"47.0,9.4,47.3,9.7\" origin=\"bench\"/>\n");

    let mut rng = Rng(0x5EED_CAFE_F00D_BEEF);
    let mut id: i64 = 1_000_000;
    while out.len() < target_bytes {
        id += 1;
        let lat = 47_000_0000i64 + rng.below(3_000_000) as i64;
        let lon = 9_400_0000i64 + rng.below(3_000_000) as i64;
        match rng.below(100) {
            // 80% bare self-closing nodes
            0..=79 => {
                let _ = writeln!(
                    out,
                    " <node id=\"{id}\" lat=\"{}.{:07}\" lon=\"{}.{:07}\" version=\"3\"/>",
                    lat / 10_000_000,
                    lat % 10_000_000,
                    lon / 10_000_000,
                    lon % 10_000_000,
                );
            }
            // 8% tagged nodes
            80..=87 => {
                let _ = writeln!(
                    out,
                    " <node id=\"{id}\" lat=\"{}.{:07}\" lon=\"{}.{:07}\" version=\"3\">",
                    lat / 10_000_000,
                    lat % 10_000_000,
                    lon / 10_000_000,
                    lon % 10_000_000,
                );
                for _ in 0..=rng.below(3) {
                    let k = TAG_KEYS[rng.below(10) as usize];
                    let _ = writeln!(out, "  <tag k=\"{k}\" v=\"value {}\"/>", rng.below(1000));
                }
                out.push_str(" </node>\n");
            }
            // 10% ways
            88..=97 => {
                let _ = writeln!(out, " <way id=\"{id}\" version=\"2\">");
                for _ in 0..(4 + rng.below(20)) {
                    let _ = writeln!(out, "  <nd ref=\"{}\"/>", 1_000_000 + rng.below(id as u64));
                }
                for _ in 0..=rng.below(4) {
                    let k = TAG_KEYS[rng.below(10) as usize];
                    let _ = writeln!(out, "  <tag k=\"{k}\" v=\"value {}\"/>", rng.below(1000));
                }
                out.push_str(" </way>\n");
            }
            // 2% relations
            _ => {
                let _ = writeln!(out, " <relation id=\"{id}\" version=\"1\">");
                for _ in 0..(2 + rng.below(8)) {
                    let _ = writeln!(
                        out,
                        "  <member type=\"way\" ref=\"{}\" role=\"outer\"/>",
                        1_000_000 + rng.below(id as u64),
                    );
                }
                let _ = writeln!(out, "  <tag k=\"boundary\" v=\"administrative\"/>");
                out.push_str(" </relation>\n");
            }
        }
    }
    out.push_str("</osm>\n");
    out.into_bytes()
}

const CORPUS_BYTES: usize = 100 * 1024 * 1024; // ~100 MB

// ── Benches ──────────────────────────────────────────────────────────────────

fn bench_xml_scan(c: &mut Criterion) {
    let corpus = synth_osm_xml(CORPUS_BYTES);
    let n_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let mut g = c.benchmark_group("xml_scan");
    g.throughput(Throughput::Bytes(corpus.len() as u64));
    g.sample_size(10);

    // ── OSM specialization (vtd) — the pre/post-refactor comparable ─────────
    g.bench_function("vtd/sequential", |b| {
        b.iter(|| {
            let mut count = 0u64;
            znippy_zoomies::vtd::build_elem_index(&corpus, |_| count += 1).unwrap();
            count
        })
    });

    for n in [4, n_cores] {
        g.bench_with_input(BenchmarkId::new("vtd/parallel", n), &n, |b, &n| {
            b.iter(|| {
                let mut count = 0u64;
                znippy_zoomies::vtd::build_elem_index_parallel(&corpus, n, |_| count += 1).unwrap();
                count
            })
        });
    }

    g.bench_function("vtd/count_elements", |b| {
        b.iter(|| znippy_zoomies::vtd::count_elements(&corpus))
    });

    g.bench_function("vtd/find_safe_slot_end", |b| {
        b.iter(|| znippy_zoomies::vtd::find_safe_slot_end(&corpus))
    });

    g.finish();
}

criterion_group!(benches, bench_xml_scan);
criterion_main!(benches);
