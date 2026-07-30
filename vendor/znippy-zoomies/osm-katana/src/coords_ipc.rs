//! Single-batch Arrow IPC writer/reader for the node coordinate store (PR 2c).
//!
//! The node coord payload is written as ONE Arrow IPC file (`node_coords.arrow`)
//! with a single record batch of three fixed-width columns
//! (`id: Int64`, `lat: Float32`, `lon: Float32`). Because the columns are
//! fixed-width primitives there is no `i32` offset buffer, so a single batch can
//! hold all ~9 B planet rows (the 2^31 limit only applies to Utf8/List/Binary).
//!
//! A single batch is exactly what `STree64Mmap` needs: one contiguous stride-8
//! `id` value buffer, mmap'd zero-copy. This module hand-lays the IPC framing so
//! the three body regions are at predictable, 64-byte-aligned offsets that the
//! parallel merge can write into directly — eliminating the redundant
//! `_col_*.bin` write. See DESIGN.md §4.1 for the full reasoning.
//!
//! Layout:
//! ```text
//! [ARROW1 magic + pad to 64]
//! [schema message       (encapsulated, body-less)]
//! [recordbatch message metadata (encapsulated, padded to 64)]
//! [body: id values (count*8) | pad | lat values (count*4) | pad | lon values (count*4) | pad]
//! [EOS continuation (8B)]
//! [footer flatbuffer]
//! [footer_len i32 LE]
//! [ARROW1 magic (6B)]
//! ```
//! Validity buffers are declared with length 0 (the columns are non-nullable, so
//! `null_count == 0` and arrow-rs's reader never reads them).

use std::io::Write;
use std::path::Path;

use anyhow::{Context as _, Result};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::ipc::convert::IpcSchemaEncoder;
use arrow::ipc::writer::{
    DictionaryTracker, EncodedData, IpcDataGenerator, IpcWriteOptions, write_message,
};
use arrow::ipc::{
    Block, Buffer, FieldNode, FooterBuilder, MessageBuilder, MessageHeader, MetadataVersion,
    RecordBatchBuilder, root_as_footer, root_as_message,
};
use flatbuffers::FlatBufferBuilder;
use memmap2::{Mmap, MmapOptions};

const MAGIC: &[u8; 6] = b"ARROW1";
const ALIGN: u64 = 64;

#[inline]
fn align64(x: u64) -> u64 {
    (x + ALIGN - 1) & !(ALIGN - 1)
}

/// Schema for the node coordinates Arrow IPC file.
pub fn coord_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("lat", DataType::Float32, false),
        Field::new("lon", DataType::Float32, false),
    ])
}

fn opts() -> IpcWriteOptions {
    IpcWriteOptions::try_new(64, false, MetadataVersion::V5)
        .expect("64-byte alignment + V5 is valid")
}

/// Absolute byte offsets (from file start) of the three value regions, plus the
/// metadata needed to write the footer.
pub struct IpcLayout {
    /// Absolute file offset of the `id` value buffer (count*8 bytes).
    pub id_abs: u64,
    /// Absolute file offset of the `lat` value buffer (count*4 bytes).
    pub lat_abs: u64,
    /// Absolute file offset of the `lon` value buffer (count*4 bytes).
    pub lon_abs: u64,
    /// First byte of the body (== `id_abs`).
    pub body_start: u64,
    /// Total padded body length.
    pub body_total: u64,
    /// File offset of the record-batch message (Block.offset).
    block_offset: u64,
    /// Framed record-batch metadata length (Block.metaDataLength).
    rb_meta: usize,
}

/// Build the record-batch message flatbuffer (metadata only; the body is written
/// separately into the pre-laid regions).
fn build_rb_message(count: usize, a: u64, b: u64, c4: u64, c8: u64, body_total: u64) -> Vec<u8> {
    let mut fbb = FlatBufferBuilder::new();

    let nodes = [
        FieldNode::new(count as i64, 0),
        FieldNode::new(count as i64, 0),
        FieldNode::new(count as i64, 0),
    ];
    // (offset, length) pairs relative to body start. Validity buffers length 0.
    let buffers = [
        Buffer::new(0, 0),                // id validity
        Buffer::new(0, c8 as i64),        // id values
        Buffer::new(a as i64, 0),         // lat validity
        Buffer::new(a as i64, c4 as i64), // lat values
        Buffer::new(b as i64, 0),         // lon validity
        Buffer::new(b as i64, c4 as i64), // lon values
    ];

    let nodes_v = fbb.create_vector(&nodes);
    let buffers_v = fbb.create_vector(&buffers);

    let rb = {
        let mut bb = RecordBatchBuilder::new(&mut fbb);
        bb.add_length(count as i64);
        bb.add_nodes(nodes_v);
        bb.add_buffers(buffers_v);
        bb.finish()
    };
    let rb_union = rb.as_union_value();

    let msg = {
        let mut mb = MessageBuilder::new(&mut fbb);
        mb.add_version(MetadataVersion::V5);
        mb.add_header_type(MessageHeader::RecordBatch);
        mb.add_bodyLength(body_total as i64);
        mb.add_header(rb_union);
        mb.finish()
    };
    fbb.finish(msg, None);
    fbb.finished_data().to_vec()
}

/// Write magic + schema message + record-batch metadata, returning the layout.
/// After this call the writer is positioned at `body_start`.
pub fn write_prologue<W: Write>(w: &mut W, count: usize) -> Result<IpcLayout> {
    let o = opts();

    // magic + pad to 64
    w.write_all(MAGIC)?;
    let pad = (align64(MAGIC.len() as u64) - MAGIC.len() as u64) as usize;
    w.write_all(&PADDING[..pad])?;
    let header_size = MAGIC.len() as u64 + pad as u64;

    // schema message (reuse arrow-rs to guarantee a valid schema flatbuffer)
    let schema = coord_schema();
    let datagen = IpcDataGenerator::default();
    let mut tracker = DictionaryTracker::new(true);
    let enc = datagen.schema_to_bytes_with_dictionary_tracker(&schema, &mut tracker, &o);
    let (schema_meta, _) = write_message(&mut *w, enc, &o)?;

    let block_offset = header_size + schema_meta as u64;

    // body layout
    let c8 = count as u64 * 8;
    let c4 = count as u64 * 4;
    let a = align64(c8); // lat region offset (relative to body start)
    let b = align64(a + c4); // lon region offset
    let body_total = align64(b + c4);

    // record-batch metadata
    let rb_msg = build_rb_message(count, a, b, c4, c8, body_total);
    let enc_rb = EncodedData {
        ipc_message: rb_msg,
        arrow_data: Vec::new(),
    };
    let (rb_meta, _) = write_message(&mut *w, enc_rb, &o)?;

    let body_start = block_offset + rb_meta as u64;
    Ok(IpcLayout {
        id_abs: body_start,
        lat_abs: body_start + a,
        lon_abs: body_start + b,
        body_start,
        body_total,
        block_offset,
        rb_meta,
    })
}

/// Write the EOS marker + footer + footer length + trailing magic. The writer
/// must be positioned at the end of the body (`body_start + body_total`).
pub fn write_epilogue<W: Write>(w: &mut W, layout: &IpcLayout) -> Result<()> {
    // EOS: continuation marker + 0-length message
    w.write_all(&[0xff, 0xff, 0xff, 0xff])?;
    w.write_all(&0i32.to_le_bytes())?;

    let mut fbb = FlatBufferBuilder::new();
    let schema = coord_schema();
    let mut tracker = DictionaryTracker::new(true);
    let schema_off = IpcSchemaEncoder::new()
        .with_dictionary_tracker(&mut tracker)
        .schema_to_fb_offset(&mut fbb, &schema);

    let blocks = [Block::new(
        layout.block_offset as i64,
        layout.rb_meta as i32,
        layout.body_total as i64,
    )];
    let rb_v = fbb.create_vector(&blocks);
    let empty: [Block; 0] = [];
    let dict_v = fbb.create_vector(&empty);

    let footer = {
        let mut fb = FooterBuilder::new(&mut fbb);
        fb.add_version(MetadataVersion::V5);
        fb.add_schema(schema_off);
        fb.add_dictionaries(dict_v);
        fb.add_recordBatches(rb_v);
        fb.finish()
    };
    fbb.finish(footer, None);
    let footer_data = fbb.finished_data();

    w.write_all(footer_data)?;
    w.write_all(&(footer_data.len() as i32).to_le_bytes())?;
    w.write_all(MAGIC)?;
    w.flush()?;
    Ok(())
}

/// Zero-copy mmap reader. Parses the IPC footer to find the (single) record
/// batch and returns the mmap plus absolute byte offsets of the id/lat/lon value
/// buffers. Works for any file produced by this module (and by arrow-rs for a
/// single-batch file with this schema).
pub struct MappedCoords {
    pub mmap: Mmap,
    pub id_off: usize,
    pub lat_off: usize,
    pub lon_off: usize,
    pub count: usize,
}

pub fn open_mmap(path: &Path) -> Result<MappedCoords> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let n = mmap.len();
    anyhow::ensure!(n >= 10 + 6, "file too small to be Arrow IPC: {n} bytes");

    let footer_len = i32::from_le_bytes(mmap[n - 10..n - 6].try_into().unwrap()) as usize;
    anyhow::ensure!(
        n >= 10 + footer_len,
        "footer_len {footer_len} exceeds file size {n}"
    );
    let footer = root_as_footer(&mmap[n - 10 - footer_len..n - 10])
        .map_err(|e| anyhow::anyhow!("parse Arrow IPC footer: {e}"))?;

    let rbs = footer
        .recordBatches()
        .context("Arrow IPC footer has no record batches")?;
    if rbs.is_empty() {
        // Empty file (count == 0).
        return Ok(MappedCoords {
            mmap,
            id_off: 0,
            lat_off: 0,
            lon_off: 0,
            count: 0,
        });
    }
    anyhow::ensure!(
        rbs.len() == 1,
        "expected a single record batch, found {} (PR 2c requires single-batch layout)",
        rbs.len()
    );
    let blk = rbs.get(0);
    let off = blk.offset() as usize;
    let meta = blk.metaDataLength() as usize;
    let body_start = off + meta;

    // Encapsulated message: [continuation 0xFFFFFFFF][msg_size i32][flatbuffer][pad]
    let msg_size = i32::from_le_bytes(mmap[off + 4..off + 8].try_into().unwrap()) as usize;
    let msg = root_as_message(&mmap[off + 8..off + 8 + msg_size])
        .map_err(|e| anyhow::anyhow!("parse Arrow IPC record-batch message: {e}"))?;
    let rb = msg
        .header_as_record_batch()
        .context("IPC message is not a RecordBatch")?;
    let nodes = rb.nodes().context("record batch has no field nodes")?;
    let bufs = rb.buffers().context("record batch has no buffers")?;
    anyhow::ensure!(nodes.len() == 3, "expected 3 columns, got {}", nodes.len());
    anyhow::ensure!(bufs.len() == 6, "expected 6 buffers, got {}", bufs.len());

    let count = nodes.get(0).length() as usize;
    // buffers: [id_validity, id_values, lat_validity, lat_values, lon_validity, lon_values]
    let id_buf = bufs.get(1);
    let lat_buf = bufs.get(3);
    let lon_buf = bufs.get(5);

    let id_off = body_start + id_buf.offset() as usize;
    let lat_off = body_start + lat_buf.offset() as usize;
    let lon_off = body_start + lon_buf.offset() as usize;

    anyhow::ensure!(
        id_buf.length() as usize == count * 8,
        "id buffer length {} != count*8 {}",
        id_buf.length(),
        count * 8
    );
    anyhow::ensure!(
        lat_buf.length() as usize == count * 4 && lon_buf.length() as usize == count * 4,
        "lat/lon buffer length mismatch"
    );
    anyhow::ensure!(id_off + count * 8 <= n, "id buffer out of bounds");
    anyhow::ensure!(
        lat_off + count * 4 <= n && lon_off + count * 4 <= n,
        "coord buffer out of bounds"
    );
    // 8-byte alignment for i64 id reads.
    anyhow::ensure!(id_off % 8 == 0, "id buffer not 8-byte aligned ({id_off})");

    Ok(MappedCoords {
        mmap,
        id_off,
        lat_off,
        lon_off,
        count,
    })
}

// Static zero padding (max alignment we ever pad by in the prologue is < 64).
static PADDING: [u8; 64] = [0u8; 64];
