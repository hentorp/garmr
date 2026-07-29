//! ZIP Central Directory parser — thin re-export of the shared `zip_core` crate.
//!
//! The EOCD / ZIP64 walk and the in-memory + streaming CD readers are
//! byte-for-byte identical to ljar's (a JAR is a ZIP), so the parser lives once
//! in [`zip_core::central_dir`] (reuse-law, task #19) and lzip-parallel consumes
//! it here.  The historical `lzip_parallel::central_dir::{EntryLocation,
//! read_central_directory, read_central_directory_from}` paths are preserved.
//!
//! The parser's own error is [`zip_core::ScanError`]; it converts into
//! [`crate::entry::ZipError`] via a `From` impl so lzip's error surface is
//! unchanged.

pub use zip_core::EntryLocation;
pub use zip_core::central_dir::{read_central_directory, read_central_directory_from};
