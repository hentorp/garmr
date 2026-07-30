//! Protobuf encoder for OSM PBF output — manual varint encoding, zstd blobs.
//!
//! Covers the subset of osmformat.proto needed for nodes/ways/relations
//! without metadata (version/timestamp/user omitted).

#![allow(unsafe_code, reason = "zstd-sys-rs is raw C FFI")]

use std::{collections::HashMap, io::Write};

use anyhow::{Context as _, Result};

// ── Varint / zigzag ───────────────────────────────────────────────────────────

pub fn push_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(b);
            return;
        }
        buf.push(b | 0x80);
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}
pub fn push_sint64(buf: &mut Vec<u8>, v: i64) {
    push_varint(buf, zigzag(v));
}

fn push_tag_varint(buf: &mut Vec<u8>, field: u32, v: u64) {
    push_varint(buf, ((field as u64) << 3) | 0);
    push_varint(buf, v);
}

pub fn push_tag_len(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    push_varint(buf, ((field as u64) << 3) | 2);
    push_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

// ── String table ──────────────────────────────────────────────────────────────

pub struct StringTable {
    map: HashMap<Vec<u8>, u32>,
    count: u32,
}

impl StringTable {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(Vec::new(), 0); // index 0 = empty string delimiter
        Self { map, count: 1 }
    }

    pub fn intern(&mut self, s: &[u8]) -> u32 {
        if let Some(&idx) = self.map.get(s) {
            return idx;
        }
        let idx = self.count;
        self.count += 1;
        self.map.insert(s.to_vec(), idx); // single allocation per unique string
        idx
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut ordered: Vec<(&[u8], u32)> =
            self.map.iter().map(|(k, &v)| (k.as_slice(), v)).collect();
        ordered.sort_unstable_by_key(|&(_, idx)| idx);
        let mut buf = Vec::with_capacity(ordered.len() * 16);
        for (s, _) in ordered {
            push_tag_len(&mut buf, 1, s);
        }
        buf
    }
}

// ── DenseNodes ────────────────────────────────────────────────────────────────

pub struct DenseNodesBuilder {
    ids: Vec<i64>,
    lats: Vec<i64>,
    lons: Vec<i64>,
    keys_vals: Vec<u32>,
    last_id: i64,
    last_lat: i64,
    last_lon: i64,
}

impl DenseNodesBuilder {
    pub fn new() -> Self {
        Self {
            ids: vec![],
            lats: vec![],
            lons: vec![],
            keys_vals: vec![],
            last_id: 0,
            last_lat: 0,
            last_lon: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// `tags` are (key_sid, val_sid) pairs already interned into the StringTable.
    /// lat_e7/lon_e7 are already in PBF granularity-100 units (1e-7 degrees).
    pub fn push(&mut self, id: i64, lat_e7: i32, lon_e7: i32, tags: &[(u32, u32)]) {
        let lat = lat_e7 as i64;
        let lon = lon_e7 as i64;
        self.ids.push(id - self.last_id);
        self.lats.push(lat - self.last_lat);
        self.lons.push(lon - self.last_lon);
        self.last_id = id;
        self.last_lat = lat;
        self.last_lon = lon;
        for &(k, v) in tags {
            self.keys_vals.push(k);
            self.keys_vals.push(v);
        }
        self.keys_vals.push(0);
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut p = Vec::new();

        // ids (field 1, packed sint64)
        for &v in &self.ids {
            push_sint64(&mut p, v);
        }
        push_tag_len(&mut buf, 1, &p);
        p.clear();

        // lats (field 8, packed sint64)
        for &v in &self.lats {
            push_sint64(&mut p, v);
        }
        push_tag_len(&mut buf, 8, &p);
        p.clear();

        // lons (field 9, packed sint64)
        for &v in &self.lons {
            push_sint64(&mut p, v);
        }
        push_tag_len(&mut buf, 9, &p);
        p.clear();

        // keys_vals (field 10, packed int32)
        for &v in &self.keys_vals {
            push_varint(&mut p, v as u64);
        }
        push_tag_len(&mut buf, 10, &p);

        buf
    }
}

// ── Way / Relation encoders ───────────────────────────────────────────────────

pub fn encode_way(id: i64, tags: &[(u32, u32)], refs: &[i64]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_tag_varint(&mut buf, 1, id as u64);
    if !tags.is_empty() {
        let mut p = Vec::new();
        for &(k, _) in tags {
            push_varint(&mut p, k as u64);
        }
        push_tag_len(&mut buf, 2, &p);
        p.clear();
        for &(_, v) in tags {
            push_varint(&mut p, v as u64);
        }
        push_tag_len(&mut buf, 3, &p);
    }
    if !refs.is_empty() {
        let mut p = Vec::new();
        let mut last = 0i64;
        for &r in refs {
            push_sint64(&mut p, r - last);
            last = r;
        }
        push_tag_len(&mut buf, 8, &p);
    }
    buf
}

pub fn encode_relation(
    id: i64,
    tags: &[(u32, u32)],
    members: &[(u8, i64, u32)], // (type 0/1/2, ref_id, role_sid)
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_tag_varint(&mut buf, 1, id as u64);
    if !tags.is_empty() {
        let mut p = Vec::new();
        for &(k, _) in tags {
            push_varint(&mut p, k as u64);
        }
        push_tag_len(&mut buf, 2, &p);
        p.clear();
        for &(_, v) in tags {
            push_varint(&mut p, v as u64);
        }
        push_tag_len(&mut buf, 3, &p);
    }
    if !members.is_empty() {
        let mut p = Vec::new();
        for &(_, _, role) in members {
            push_varint(&mut p, role as u64);
        }
        push_tag_len(&mut buf, 8, &p);
        p.clear();
        let mut last = 0i64;
        for &(_, ref_id, _) in members {
            push_sint64(&mut p, ref_id - last);
            last = ref_id;
        }
        push_tag_len(&mut buf, 9, &p);
        p.clear();
        for &(mt, _, _) in members {
            push_varint(&mut p, mt as u64);
        }
        push_tag_len(&mut buf, 10, &p);
    }
    buf
}

// ── PrimitiveBlock assembler ──────────────────────────────────────────────────

/// Assemble and return the raw (uncompressed) PrimitiveBlock protobuf bytes.
pub fn encode_primitive_block(
    st: &StringTable,
    dense: Option<&DenseNodesBuilder>,
    ways: &[Vec<u8>],
    relations: &[Vec<u8>],
) -> Vec<u8> {
    let mut buf = Vec::new();

    // stringtable (field 1)
    push_tag_len(&mut buf, 1, &st.encode());

    // DenseNodes group (field 2 → PrimitiveGroup.dense = field 2)
    if let Some(dn) = dense {
        if dn.len() > 0 {
            let mut pg = Vec::new();
            push_tag_len(&mut pg, 2, &dn.encode());
            push_tag_len(&mut buf, 2, &pg);
        }
    }

    // Ways group (field 2 → PrimitiveGroup.ways = field 3)
    if !ways.is_empty() {
        let mut pg = Vec::new();
        for w in ways {
            push_tag_len(&mut pg, 3, w);
        }
        push_tag_len(&mut buf, 2, &pg);
    }

    // Relations group (field 2 → PrimitiveGroup.relations = field 4)
    if !relations.is_empty() {
        let mut pg = Vec::new();
        for r in relations {
            push_tag_len(&mut pg, 4, r);
        }
        push_tag_len(&mut buf, 2, &pg);
    }

    // granularity = 100 is the default — no need to encode it explicitly.
    buf
}

// ── zstd compression ──────────────────────────────────────────────────────────

pub fn compress_zstd(src: &[u8]) -> Result<Vec<u8>> {
    let bound = unsafe { zstd_sys_rs::ZSTD_compressBound(src.len()) };
    let mut dst = vec![0u8; bound];
    let n = unsafe {
        zstd_sys_rs::ZSTD_compress(
            dst.as_mut_ptr().cast(),
            dst.len(),
            src.as_ptr().cast(),
            src.len(),
            3,
        )
    };
    if unsafe { zstd_sys_rs::ZSTD_isError(n) } != 0 {
        anyhow::bail!("ZSTD_compress error {n}");
    }
    dst.truncate(n);
    Ok(dst)
}

// ── Blob framing ──────────────────────────────────────────────────────────────

/// Write one framed PBF blob: [4-byte BE header length][BlobHeader][Blob].
pub fn write_blob(
    out: &mut impl Write,
    blob_type: &[u8],
    raw_size: usize,
    zstd: &[u8],
) -> Result<()> {
    // Blob { int32 raw_size=2; bytes zstd_data=7; }
    let mut blob = Vec::new();
    push_tag_varint(&mut blob, 2, raw_size as u64);
    push_tag_len(&mut blob, 7, zstd);

    // BlobHeader { string type=1; int32 datasize=3; }
    let mut hdr = Vec::new();
    push_tag_len(&mut hdr, 1, blob_type);
    push_tag_varint(&mut hdr, 3, blob.len() as u64);

    out.write_all(&(hdr.len() as u32).to_be_bytes())
        .context("write hdr len")?;
    out.write_all(&hdr).context("write BlobHeader")?;
    out.write_all(&blob).context("write Blob")?;
    Ok(())
}

pub fn write_osm_header(out: &mut impl Write) -> Result<()> {
    // HeaderBlock { repeated string required_features=4; string writingprogram=16; }
    let mut hb = Vec::new();
    push_tag_len(&mut hb, 4, b"OsmSchema-V0.6");
    push_tag_len(&mut hb, 4, b"DenseNodes");
    push_tag_len(&mut hb, 16, b"katana-osm");
    let compressed = compress_zstd(&hb)?;
    write_blob(out, b"OSMHeader", hb.len(), &compressed)
}
