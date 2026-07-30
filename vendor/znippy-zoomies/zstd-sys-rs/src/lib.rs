// src/lib.rs
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod safe;
pub use safe::{
    Decompressor, Error, Result, compress, compress_bound, decompress, decompress_into,
    frame_content_size,
};
