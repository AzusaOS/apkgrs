//! The `.apkg` package file format.
//!
//! | off | field |
//! |----:|-------|
//! |   0 | magic `APKG` |
//! |   4 | format version (1) |
//! |   8 | flags u64 |
//! |  16 | created: unix seconds u64, nanoseconds u64 |
//! |  32 | metadata offset u32, length u32, sha256 |
//! |  72 | hash table offset u32, length u32, sha256 |
//! | 112 | signature offset u32 |
//! | 116 | data (squashfs) offset u32 |
//! | 120 | data block size u32 |
//!
//! The 124-byte header is signed; its sha256 identifies the package. The
//! hash table holds one sha256 per `block size` bytes of the squashfs image,
//! which lets every downloaded block be verified independently.

use crate::error::{Error, Result};
use crate::sig::{self, Cursor};

/// Length of the package header.
pub const HEADER_LEN: usize = 124;

/// Decoded package header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub flags: u64,
    pub created: i64,
    pub created_nsec: u64,
    pub meta_offset: u32,
    pub meta_len: u32,
    pub meta_hash: [u8; 32],
    pub table_offset: u32,
    pub table_len: u32,
    pub table_hash: [u8; 32],
    pub sig_offset: u32,
    pub data_offset: u32,
    pub block_size: u32,
}

impl Header {
    /// Decode a raw header. No signature check.
    pub fn parse(raw: &[u8]) -> Result<Header> {
        if raw.len() != HEADER_LEN || &raw[..4] != b"APKG" {
            return Err(Error::Format("not a APKG file".into()));
        }
        let mut c = Cursor::new(&raw[4..]);
        if c.u32_be()? != 1 {
            return Err(Error::Format("unsupported file version".into()));
        }
        let flags = c.u64_be()?;
        let created = c.u64_be()? as i64;
        let created_nsec = c.u64_be()?;
        let meta_offset = c.u32_be()?;
        let meta_len = c.u32_be()?;
        let meta_hash = c.take(32)?.try_into().unwrap();
        let table_offset = c.u32_be()?;
        let table_len = c.u32_be()?;
        let table_hash = c.take(32)?.try_into().unwrap();
        let sig_offset = c.u32_be()?;
        let data_offset = c.u32_be()?;
        let block_size = c.u32_be()?;
        if block_size == 0 || table_len % 32 != 0 {
            return Err(Error::Format("invalid block size or hash table".into()));
        }
        Ok(Header {
            flags,
            created,
            created_nsec,
            meta_offset,
            meta_len,
            meta_hash,
            table_offset,
            table_len,
            table_hash,
            sig_offset,
            data_offset,
            block_size,
        })
    }

    /// Check that `raw` hashes to `expected`, has a valid trusted signature,
    /// and decode it.
    pub fn verify(raw: &[u8], signature: &[u8], expected: &[u8; 32]) -> Result<Header> {
        if &sig::sha256(raw) != expected {
            return Err(Error::Integrity("header invalid or corrupted".into()));
        }
        sig::verify_pkg(raw, signature)?;
        Header::parse(raw)
    }
}
