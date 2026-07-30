//! `search-index` side-output — a compact inverted text/tag index over the
//! pipeline's GeoParquet features.
//!
//! ## What it consumes
//!
//! Exactly the two columns every stage of the built feed emits (see
//! `convert` / `optimize` / `geo2arrow`): a Binary **WKB** `geometry` column and
//! a Utf8 **JSON** `tags` column. So it indexes `nodes.parquet` + `ways.parquet`
//! (a GeoParquet dir) OR a single optimized `.parquet` file interchangeably —
//! whatever the earlier stage produced.
//!
//! ## What it produces
//!
//! A [`SearchIndex`]: an inverted index mapping search *tokens* to feature
//! *postings* (sorted feature-id lists), plus a small [`Hit`] record per feature
//! (id, optional display name, and a lon/lat centroid decoded from the WKB) so a
//! result can be placed on a map and labelled. It serialises to a JSON `.idx`
//! file alongside the parquet and reloads without touching the parquet again.
//!
//! ## Query model
//!
//! Two token kinds are indexed per feature:
//!   * **exact tag** tokens `key=value` (e.g. `amenity=cafe`, `highway=primary`),
//!   * **word** tokens from every string value and the bare key (e.g. `cafe`,
//!     `stockholm`, `amenity`).
//!
//! A query is tokenised the same way; a query containing `=` is one exact-tag
//! token, otherwise it is split into words that are AND-combined (every word must
//! be present). Postings are sorted, so the intersection is a linear merge.
//!
//! ## Gatling shape, mirrors `optimize` / `geo2arrow`
//!
//! ROOT LAW #0: the fan-out is `gatling_for_each_balanced`, one unit per ROW
//! GROUP, LPT-scheduled heaviest-first by the group's compressed footer size. Each
//! unit opens its OWN projected reader over its single group and does the parallel
//! work (zstd-decompress + arrow-decode + JSON parse + WKB decode + tokenise);
//! results come back in row-group order. The serial tail concatenates them,
//! assigns the global feature ids and folds the postings — cheap, no 100 M-row
//! sort. Because the order is row-group order rather than "whichever thread
//! finished first", the index is a pure function of the parquet.
//!
//! Feature-gated behind the `search-index` Cargo feature (compiled out of the
//! lean default build), so nothing here is pulled unless explicitly enabled.
#![cfg(feature = "search-index")]

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use arrow::array::{Array, BinaryArray, StringArray};
use parquet::arrow::ProjectionMask;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};
use serde::{Deserialize, Serialize};

/// One indexed feature: enough to place a search result on a map and label it.
/// `lon`/`lat` is the centroid (mean of the WKB coordinates) so a Point, a road
/// LineString and a building Polygon all resolve to a single pin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hit {
    /// Dense feature id — the index into [`SearchIndex::features`], also the
    /// value stored in the postings lists.
    pub id: u32,
    /// The feature's `name` tag, if any (the human label for a result).
    pub name: Option<String>,
    /// Centroid longitude.
    pub lon: f64,
    /// Centroid latitude.
    pub lat: f64,
}

/// An inverted text/tag index over a GeoParquet feature set. Build it with
/// [`SearchIndex::build`], query it with [`SearchIndex::search`], and persist it
/// with [`SearchIndex::save`] / [`SearchIndex::load`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SearchIndex {
    /// Feature id → its [`Hit`] record. `features[i].id == i`.
    features: Vec<Hit>,
    /// Token → sorted, deduped feature-id postings.
    ///
    /// Serialised through [`postings_sorted`] so the `.idx` file is REPRODUCIBLE.
    /// `HashMap`'s iteration order is randomised per map instance, so serialising
    /// it directly made two saves of the same index differ byte-for-byte — the
    /// same class of bug as the `serialize_tags` HashMap. Lookups stay O(1); only
    /// the write is ordered.
    #[serde(serialize_with = "postings_sorted")]
    postings: HashMap<String, Vec<u32>>,
}

/// Serialise the postings map with its keys in sorted order, so the on-disk
/// `.idx` is a pure function of the index content.
fn postings_sorted<S>(m: &HashMap<String, Vec<u32>>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap as _;
    // Sort the ENTRIES, not the keys: one pass over the map, no second hash probe
    // per token on the way out. A country-sized table holds ~740 k tokens and the
    // comparator chases pointers into 740 k scattered heap `String`s, so this is
    // not free — it goes through `gatling_sort_unstable_by`, which is the drop-in
    // for `sort_unstable_by` (same total order, all cores) and hands the save path
    // its determinism back for nothing. ROOT LAW #0: even the sort is gatling.
    let mut entries: Vec<(&String, &Vec<u32>)> = m.iter().collect();
    gatling::gatling_sort::gatling_sort_unstable_by(&mut entries, |a, b| a.0.cmp(b.0));
    let mut map = s.serialize_map(Some(entries.len()))?;
    for (k, v) in entries {
        map.serialize_entry(k, v)?;
    }
    map.end()
}

/// The heavy per-feature product a worker hands back before global ids exist:
/// the (partial, id-less) hit and its deduped token set.
struct RawFeature {
    name: Option<String>,
    lon: f64,
    lat: f64,
    tokens: Vec<String>,
}

/// Lowercase a value into word tokens: runs of ASCII-alphanumeric of length ≥ 2,
/// so `"Stockholm Central"` → `["stockholm", "central"]` and punctuation / short
/// noise is dropped. Non-ASCII bytes (e.g. `ö`) split words like other separators
/// — a deliberate simplification that keeps the tokenizer allocation-light; exact
/// tag tokens (`name=Malmö`) still preserve the full value for precise lookups.
fn word_tokens(value: &str, out: &mut Vec<String>) {
    let mut cur = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            if cur.len() >= 2 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 2 {
        out.push(cur);
    }
}

/// Turn a tags-JSON object into a deduped token set: an exact `key=value` token
/// per tag, the bare (lowercased) `key`, and word tokens from every string value.
/// Returns `(name, tokens)` — `name` is the raw `name` tag for the [`Hit`] label.
fn tags_to_tokens(tags: &str) -> (Option<String>, Vec<String>) {
    let mut tokens: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    if tags.is_empty() || tags == "{}" {
        return (name, tokens);
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(tags) else {
        return (name, tokens);
    };
    for (k, v) in &map {
        let value = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => continue,
            other => other.to_string(),
        };
        if value.is_empty() {
            continue;
        }
        if k == "name" {
            name = Some(value.clone());
        }
        let key_lc = k.to_ascii_lowercase();
        // exact tag token: `key=value` (value lowercased for case-insensitive hits)
        tokens.push(format!("{key_lc}={}", value.to_ascii_lowercase()));
        // the bare key is a token too (e.g. query "building")
        tokens.push(key_lc);
        // free-text word tokens from the value (e.g. "cafe", "stockholm")
        word_tokens(&value, &mut tokens);
    }
    tokens.sort();
    tokens.dedup();
    (name, tokens)
}

/// Mean of the WKB coordinate list — the feature's map pin. `None` if the WKB is
/// missing/undecodable (such a feature is skipped: a search hit must be placeable).
fn wkb_centroid(wkb: &[u8]) -> Option<(f64, f64)> {
    let coords = crate::shared::geometry::decode_coords(wkb)?;
    if coords.is_empty() {
        return None;
    }
    let n = coords.len() as f64;
    let (mut sx, mut sy) = (0.0f64, 0.0f64);
    for (x, y) in &coords {
        sx += *x;
        sy += *y;
    }
    Some((sx / n, sy / n))
}

/// Decode one arrow batch (geometry + tags) into id-less [`RawFeature`]s — the
/// per-unit heavy work a worker does (JSON parse + WKB decode + tokenise).
fn process_batch(batch: &arrow::record_batch::RecordBatch) -> Vec<RawFeature> {
    let geom = batch
        .column_by_name("geometry")
        .and_then(|c| c.as_any().downcast_ref::<BinaryArray>());
    let Some(geom) = geom else { return Vec::new() };
    let tags = batch
        .column_by_name("tags")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    let n = geom.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if geom.is_null(i) {
            continue; // no geometry → not placeable (e.g. relations)
        }
        let Some((lon, lat)) = wkb_centroid(geom.value(i)) else {
            continue;
        };
        let raw_tags = tags
            .filter(|t| !t.is_null(i))
            .map(|t| t.value(i))
            .unwrap_or("");
        let (name, tokens) = tags_to_tokens(raw_tags);
        if tokens.is_empty() {
            continue; // nothing to index → skip (untagged geometry)
        }
        out.push(RawFeature {
            name,
            lon,
            lat,
            tokens,
        });
    }
    out
}

/// Read ONE parquet file on gatling, returning its features (id-less) in
/// **row-group order**.
///
/// ROOT LAW #0. This was a hand-rolled `std::thread::scope` pool: a "reader"
/// thread that pushed nothing but `0..n_rg` into a `sync_channel`, plus N worker
/// threads self-dispatching off an `Arc<Mutex<Receiver>>`. That is a rayon
/// replacement wearing a doc comment, and the channel it was built around carried
/// no data — gatling's atomic cursor IS that hand-off, without the thread, the
/// mutex or the channel.
///
/// Two behavioural consequences, both improvements:
/// - **Deterministic.** The old code concatenated each worker's private `Vec` in
///   *handle* order, so which features landed in one worker's `Vec` — and hence
///   the dense feature ids `from_raw` assigns, and hence every posting list —
///   depended on how the row groups happened to race across the threads. Two runs
///   over the same parquet could produce different `.idx` files. Results now come
///   back in row-group order, so the index is a pure function of the input.
/// - **LPT-balanced.** Row groups are claimed heaviest-first by compressed byte
///   size, so a fat group cannot be picked up last and leave the tail on one core.
fn gatling_features(path: &Path) -> anyhow::Result<Vec<RawFeature>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(
        File::open(path).with_context(|| format!("open {path:?}"))?,
    )?;
    let meta = builder.metadata().clone();
    let n_rg = meta.num_row_groups();
    if n_rg == 0 {
        return Ok(Vec::new());
    }
    let has_tags = builder.schema().index_of("tags").is_ok();
    let proj_cols: &[&str] = if has_tags {
        &["geometry", "tags"]
    } else {
        &["geometry"]
    };
    let mask = ProjectionMask::columns(builder.parquet_schema(), proj_cols.iter().copied());

    // One unit per row group: open a projected reader over that group alone and
    // decode + tokenise it. LPT by the group's compressed footer size.
    let per_group: Vec<anyhow::Result<Vec<RawFeature>>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            n_rg,
            0,
            1,
            |rg| meta.row_group(rg).compressed_size().max(0) as u64,
            |rg| -> anyhow::Result<Vec<RawFeature>> {
                let arm = ArrowReaderMetadata::try_new(meta.clone(), ArrowReaderOptions::new())?;
                let rdr = ParquetRecordBatchReaderBuilder::new_with_metadata(
                    File::open(path).with_context(|| format!("open {path:?}"))?,
                    arm,
                )
                .with_row_groups(vec![rg])
                .with_projection(mask.clone())
                .with_batch_size(16_384)
                .build()?;
                let mut local = Vec::new();
                for batch in rdr {
                    local.append(&mut process_batch(&batch?));
                }
                Ok(local)
            },
        );

    let mut all = Vec::new();
    for group in per_group {
        all.append(&mut group?);
    }
    Ok(all)
}

/// Resolve an input path to the list of source parquet files. A directory folds
/// in `nodes.parquet` + `ways.parquet` (whichever exist); a file is used as-is.
fn resolve_sources(input: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if input.is_dir() {
        let mut sources = Vec::new();
        for name in ["nodes.parquet", "ways.parquet"] {
            let p = input.join(name);
            if p.exists() {
                sources.push(p);
            }
        }
        anyhow::ensure!(
            !sources.is_empty(),
            "no nodes.parquet / ways.parquet found in {input:?}"
        );
        Ok(sources)
    } else {
        anyhow::ensure!(input.exists(), "input parquet {input:?} does not exist");
        Ok(vec![input.to_path_buf()])
    }
}

impl SearchIndex {
    /// Build an index from a GeoParquet directory (`nodes.parquet` +
    /// `ways.parquet`) or a single `.parquet` file. Runs the 1 → N → 1 gatling
    /// per source, then folds the postings on the assembler thread.
    pub fn build(input: &Path) -> anyhow::Result<Self> {
        let sources = resolve_sources(input)?;
        let mut raws: Vec<RawFeature> = Vec::new();
        for src in &sources {
            raws.append(&mut gatling_features(src)?);
        }
        Ok(Self::from_raw(raws))
    }

    /// Assemble the final index: assign dense ids in worker order and fold each
    /// feature's tokens into the inverted postings (sorted by construction, since
    /// ids are assigned monotonically).
    fn from_raw(raws: Vec<RawFeature>) -> Self {
        let mut features = Vec::with_capacity(raws.len());
        let mut postings: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, raw) in raws.into_iter().enumerate() {
            let id = i as u32;
            for tok in raw.tokens {
                postings.entry(tok).or_default().push(id);
            }
            features.push(Hit {
                id,
                name: raw.name,
                lon: raw.lon,
                lat: raw.lat,
            });
        }
        Self { features, postings }
    }

    /// Number of indexed features.
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// True if no features are indexed.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    /// Number of distinct tokens in the index (diagnostics / tests).
    pub fn token_count(&self) -> usize {
        self.postings.len()
    }

    /// Look up a hit by its dense id.
    pub fn hit(&self, id: u32) -> Option<&Hit> {
        self.features.get(id as usize)
    }

    /// Tokenise a query the way the index was built: a query containing `=` is one
    /// exact-tag token (`key=value`, lowercased); otherwise it is split into
    /// lowercased word tokens (each length ≥ 2).
    fn query_tokens(query: &str) -> Vec<String> {
        let q = query.trim();
        if let Some((k, v)) = q.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_ascii_lowercase();
            if !k.is_empty() && !v.is_empty() {
                return vec![format!("{k}={v}")];
            }
        }
        let mut toks = Vec::new();
        word_tokens(q, &mut toks);
        toks.sort();
        toks.dedup();
        toks
    }

    /// AND-search: every query token must be present. Returns matching hits (in
    /// ascending id order). An empty / unindexed query yields no hits.
    pub fn search(&self, query: &str) -> Vec<&Hit> {
        let tokens = Self::query_tokens(query);
        if tokens.is_empty() {
            return Vec::new();
        }
        // Gather posting lists; a missing token means the AND can't match.
        let mut lists: Vec<&[u32]> = Vec::with_capacity(tokens.len());
        for t in &tokens {
            match self.postings.get(t) {
                Some(p) => lists.push(p),
                None => return Vec::new(),
            }
        }
        // Intersect the sorted lists, smallest first for a cheap linear merge.
        lists.sort_by_key(|l| l.len());
        let mut acc: Vec<u32> = lists[0].to_vec();
        for list in &lists[1..] {
            acc = intersect_sorted(&acc, list);
            if acc.is_empty() {
                break;
            }
        }
        acc.into_iter()
            .filter_map(|id| self.features.get(id as usize))
            .collect()
    }

    /// Like [`search`](Self::search) but caps the result count.
    pub fn search_limit(&self, query: &str, limit: usize) -> Vec<&Hit> {
        let mut hits = self.search(query);
        hits.truncate(limit);
        hits
    }

    /// Persist the index to a JSON `.idx` file (creating parent dirs).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let f = File::create(path).with_context(|| format!("create {path:?}"))?;
        serde_json::to_writer(std::io::BufWriter::new(f), self)
            .with_context(|| format!("write index {path:?}"))?;
        Ok(())
    }

    /// Reload an index previously written by [`save`](Self::save).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let f = File::open(path).with_context(|| format!("open {path:?}"))?;
        let idx = serde_json::from_reader(std::io::BufReader::new(f))
            .with_context(|| format!("parse index {path:?}"))?;
        Ok(idx)
    }
}

/// Intersect two ascending, deduped id lists into a new ascending list.
fn intersect_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Build a tiny in-memory index from `(tags_json, lon, lat)` triples, going
    /// through the SAME assembly path (`from_raw`) the parquet build uses — just
    /// skipping the parquet decode. Each feature gets a real centroid.
    fn index_from(features: &[(&str, f64, f64)]) -> SearchIndex {
        let raws = features
            .iter()
            .filter_map(|(tags, lon, lat)| {
                let (name, tokens) = tags_to_tokens(tags);
                if tokens.is_empty() {
                    return None;
                }
                Some(RawFeature {
                    name,
                    lon: *lon,
                    lat: *lat,
                    tokens,
                })
            })
            .collect();
        SearchIndex::from_raw(raws)
    }

    #[test]
    fn word_tokenizer_splits_and_filters() {
        let mut t = Vec::new();
        word_tokens("Stockholm Central-Station!", &mut t);
        assert_eq!(t, vec!["stockholm", "central", "station"]);

        // length-1 runs are dropped; digits kept if ≥2 long.
        let mut t2 = Vec::new();
        word_tokens("A B12 c", &mut t2);
        assert_eq!(t2, vec!["b12"], "single chars dropped, 'b12' kept");
    }

    #[test]
    fn tags_produce_exact_bare_and_word_tokens() {
        let (name, tokens) = tags_to_tokens(r#"{"amenity":"cafe","name":"Blue Bottle"}"#);
        assert_eq!(name.as_deref(), Some("Blue Bottle"));
        // exact tag tokens + bare keys + value words, all lowercased & deduped.
        for want in [
            "amenity=cafe",
            "amenity",
            "cafe",
            "name=blue bottle",
            "name",
            "blue",
            "bottle",
        ] {
            assert!(
                tokens.contains(&want.to_string()),
                "missing token {want:?} in {tokens:?}"
            );
        }
    }

    #[test]
    fn empty_and_malformed_tags_index_nothing() {
        assert!(tags_to_tokens("").1.is_empty());
        assert!(tags_to_tokens("{}").1.is_empty());
        assert!(tags_to_tokens("not json").1.is_empty());
        // a value that is only "yes" still yields the exact + bare tokens.
        let (_, t) = tags_to_tokens(r#"{"building":"yes"}"#);
        assert!(t.contains(&"building".to_string()));
        assert!(t.contains(&"building=yes".to_string()));
    }

    /// FAIL-ON-BUG: exact-tag AND free-text search over a small synthetic set.
    #[test]
    fn search_exact_and_freetext() {
        let idx = index_from(&[
            (
                r#"{"amenity":"cafe","name":"Stockholm Coffee"}"#,
                18.06,
                59.33,
            ), // 0
            (r#"{"amenity":"cafe","name":"Malmo Coffee"}"#, 13.00, 55.60), // 1
            (
                r#"{"amenity":"restaurant","name":"Stockholm Grill"}"#,
                18.07,
                59.34,
            ), // 2
            (r#"{"highway":"primary","name":"E4"}"#, 17.0, 59.0),          // 3
            (r#"{"building":"yes"}"#, 18.0, 59.0),                         // 4
        ]);
        assert_eq!(idx.len(), 5);

        // exact tag token: only the two cafes, in id order.
        let cafes: Vec<u32> = idx.search("amenity=cafe").iter().map(|h| h.id).collect();
        assert_eq!(
            cafes,
            vec![0, 1],
            "amenity=cafe matches both cafes, in id order"
        );

        // free-text single word.
        let sthlm: Vec<u32> = idx.search("stockholm").iter().map(|h| h.id).collect();
        assert_eq!(
            sthlm,
            vec![0, 2],
            "'stockholm' matches the two Stockholm features"
        );

        // AND semantics: 'stockholm coffee' matches only feature 0 (both words).
        let both: Vec<u32> = idx
            .search("Stockholm Coffee")
            .iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(
            both,
            vec![0],
            "'stockholm coffee' AND-matches only the cafe"
        );

        // bare key.
        assert_eq!(idx.search("building").len(), 1);

        // no match / unknown token → empty (not a panic, not everything).
        assert!(idx.search("reykjavik").is_empty());
        assert!(idx.search("amenity=bank").is_empty());
        assert!(idx.search("").is_empty());

        // the hit carries its centroid + name for the map.
        let h = idx.search("amenity=restaurant");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].name.as_deref(), Some("Stockholm Grill"));
        assert!((h[0].lon - 18.07).abs() < 1e-9 && (h[0].lat - 59.34).abs() < 1e-9);
    }

    #[test]
    fn search_limit_caps_results() {
        let idx = index_from(&[
            (r#"{"amenity":"cafe"}"#, 0.0, 0.0),
            (r#"{"amenity":"cafe"}"#, 1.0, 1.0),
            (r#"{"amenity":"cafe"}"#, 2.0, 2.0),
        ]);
        assert_eq!(idx.search("amenity=cafe").len(), 3);
        assert_eq!(idx.search_limit("amenity=cafe", 2).len(), 2);
    }

    /// WKB centroid: a Point returns itself; a LineString returns the mean of its
    /// vertices — the exact WKB layout the converter writes.
    #[test]
    fn wkb_centroid_point_and_line() {
        // WKB Point (lon=10, lat=20), little-endian, type 1.
        let mut pt = vec![1u8];
        pt.extend_from_slice(&1u32.to_le_bytes());
        pt.extend_from_slice(&10.0f64.to_le_bytes());
        pt.extend_from_slice(&20.0f64.to_le_bytes());
        assert_eq!(wkb_centroid(&pt), Some((10.0, 20.0)));

        // WKB LineString with two points (0,0) and (4,10) → centroid (2,5).
        let mut ls = vec![1u8];
        ls.extend_from_slice(&2u32.to_le_bytes());
        ls.extend_from_slice(&2u32.to_le_bytes()); // num points
        for (x, y) in [(0.0f64, 0.0f64), (4.0, 10.0)] {
            ls.extend_from_slice(&x.to_le_bytes());
            ls.extend_from_slice(&y.to_le_bytes());
        }
        assert_eq!(wkb_centroid(&ls), Some((2.0, 5.0)));

        // garbage WKB → None (feature would be skipped, never mis-placed).
        assert_eq!(wkb_centroid(&[0u8, 1]), None);
    }

    /// FAIL-ON-BUG: save → load round-trips the index; queries behave identically
    /// after a serialize/deserialize cycle.
    #[test]
    fn save_load_roundtrip() {
        let idx = index_from(&[
            (
                r#"{"amenity":"cafe","name":"Stockholm Coffee"}"#,
                18.06,
                59.33,
            ),
            (r#"{"highway":"primary","name":"E4"}"#, 17.0, 59.0),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("search.idx.json");
        idx.save(&path).unwrap();
        assert!(path.exists());
        let back = SearchIndex::load(&path).unwrap();
        assert_eq!(back.len(), idx.len());
        assert_eq!(back.token_count(), idx.token_count());
        let a: Vec<u32> = idx.search("stockholm").iter().map(|h| h.id).collect();
        let b: Vec<u32> = back.search("stockholm").iter().map(|h| h.id).collect();
        assert_eq!(a, b, "queries match before and after a save/load cycle");
        assert_eq!(
            back.hit(0).and_then(|h| h.name.clone()).as_deref(),
            Some("Stockholm Coffee")
        );
    }

    /// FAIL-ON-BUG (end-to-end through parquet): build a real 2-column GeoParquet
    /// with a WKB `geometry` + JSON `tags`, run [`SearchIndex::build`] over it, and
    /// query — proving the gatling read + decode + index path works, not just the
    /// in-memory assembly. Uses the same arrow/parquet writer the pipeline uses.
    #[test]
    fn build_from_real_parquet() {
        use arrow::array::{BinaryBuilder, StringBuilder};
        use arrow::datatypes::{DataType, Field, Schema};
        use arrow::record_batch::RecordBatch;
        use parquet::arrow::ArrowWriter;

        fn wkb_point(lon: f64, lat: f64) -> Vec<u8> {
            let mut b = vec![1u8];
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&lon.to_le_bytes());
            b.extend_from_slice(&lat.to_le_bytes());
            b
        }

        let rows: &[(&str, f64, f64)] = &[
            (
                r#"{"amenity":"cafe","name":"Stockholm Coffee"}"#,
                18.06,
                59.33,
            ),
            (
                r#"{"amenity":"restaurant","name":"Malmo Grill"}"#,
                13.0,
                55.6,
            ),
            (r#"{"building":"yes"}"#, 18.0, 59.0),
        ];
        let mut gb = BinaryBuilder::new();
        let mut tb = StringBuilder::new();
        for (tags, lon, lat) in rows {
            gb.append_value(wkb_point(*lon, *lat));
            tb.append_value(*tags);
        }
        let schema = Arc::new(Schema::new(vec![
            Field::new("geometry", DataType::Binary, true),
            Field::new("tags", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(gb.finish()), Arc::new(tb.finish())],
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let pq = dir.path().join("nodes.parquet");
        {
            let f = File::create(&pq).unwrap();
            let mut w = ArrowWriter::try_new(f, schema, None).unwrap();
            w.write(&batch).unwrap();
            w.close().unwrap();
        }

        // Build from the directory (folds nodes.parquet).
        let idx = SearchIndex::build(dir.path()).unwrap();
        assert_eq!(idx.len(), 3, "three features indexed from parquet");
        let cafe = idx.search("amenity=cafe");
        assert_eq!(cafe.len(), 1);
        assert_eq!(cafe[0].name.as_deref(), Some("Stockholm Coffee"));
        assert!((cafe[0].lon - 18.06).abs() < 1e-9);
        assert_eq!(
            idx.search("grill").len(),
            1,
            "free-text 'grill' finds the restaurant"
        );
        assert_eq!(idx.search("building").len(), 1);

        // Build from the single file path resolves the same way.
        let idx2 = SearchIndex::build(&pq).unwrap();
        assert_eq!(idx2.len(), 3);
    }

    /// RED-WHEN-BROKEN: the index must be a **pure function of the parquet** —
    /// feature ids follow row-group order, and two builds of the same file are
    /// byte-identical.
    ///
    /// Before the gatling conversion, `gatling_features` concatenated each
    /// worker thread's private `Vec` in *handle* order, so the ids (and therefore
    /// every posting list, and therefore the serialised `.idx`) depended on which
    /// thread happened to win which row group. This test builds a file with MANY
    /// small row groups — the case that scrambles — and pins both properties:
    /// re-running must give the identical index, and feature `i` must be the
    /// `i`-th row of the file.
    #[test]
    fn index_is_deterministic_and_in_row_group_order() {
        use arrow::array::{BinaryBuilder, StringBuilder};
        use arrow::datatypes::{DataType, Field, Schema};
        use arrow::record_batch::RecordBatch;
        use parquet::arrow::ArrowWriter;
        use parquet::file::properties::WriterProperties;

        fn wkb_point(lon: f64, lat: f64) -> Vec<u8> {
            let mut b = vec![1u8];
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&lon.to_le_bytes());
            b.extend_from_slice(&lat.to_le_bytes());
            b
        }

        // 600 features, one row group per 10 rows ⇒ 60 row groups over ~32 cores.
        let n = 600usize;
        let mut gb = BinaryBuilder::new();
        let mut tb = StringBuilder::new();
        for i in 0..n {
            gb.append_value(wkb_point(i as f64 * 0.001, 50.0 + i as f64 * 0.001));
            tb.append_value(format!(r#"{{"amenity":"cafe","name":"feat{i:04}"}}"#));
        }
        let schema = Arc::new(Schema::new(vec![
            Field::new("geometry", DataType::Binary, true),
            Field::new("tags", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(gb.finish()), Arc::new(tb.finish())],
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let pq = dir.path().join("nodes.parquet");
        {
            let props = WriterProperties::builder()
                .set_max_row_group_row_count(Some(10))
                .build();
            let f = File::create(&pq).unwrap();
            let mut w = ArrowWriter::try_new(f, schema, Some(props)).unwrap();
            w.write(&batch).unwrap();
            w.close().unwrap();
        }
        {
            let meta = ParquetRecordBatchReaderBuilder::try_new(File::open(&pq).unwrap())
                .unwrap()
                .metadata()
                .clone();
            assert!(
                meta.num_row_groups() > 8,
                "test file must have many row groups, got {}",
                meta.num_row_groups()
            );
        }

        let a = SearchIndex::build(&pq).unwrap();
        let b = SearchIndex::build(&pq).unwrap();
        assert_eq!(a.len(), n, "every feature indexed");

        // Row-group order: feature i is row i of the file.
        for (i, hit) in a.features.iter().enumerate() {
            assert_eq!(hit.id, i as u32);
            assert_eq!(
                hit.name.as_deref(),
                Some(format!("feat{i:04}").as_str()),
                "feature {i} is out of row-group order"
            );
        }

        // Determinism: two builds serialise to the same bytes.
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "two builds of the same parquet must produce the identical index"
        );
    }
}
