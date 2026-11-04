//! The signed database format (`APDB`) published at
//! `<prefix>db/<name>/<os>/<arch>/<version>.bin`.
//!
//! Layout (big endian):
//!
//! | off | field |
//! |----:|-------|
//! |   0 | magic `APDB` |
//! |   4 | format version (1) |
//! |   8 | flags u64 |
//! |  16 | created: unix seconds u64, nanoseconds u64 |
//! |  32 | os u32, arch u32, package count u32 |
//! |  44 | database name, 32 bytes NUL padded |
//! |  76 | data offset u32, data length u32, data sha256 |
//! | 116 | id index (offset, length, sha256) — reserved |
//! | 156 | name index (offset, length, sha256) — reserved |
//! | 196 | signature of bytes 0..196 |
//!
//! The data area is a sequence of [`PackageRecord`]s.

use crate::error::{Error, Result};
use crate::sig::{self, Cursor, SIGNATURE_SIZE};

/// Length of the signed header.
pub const HEADER_LEN: usize = 196;

/// A package entry of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord {
    /// sha256 of the package's 124-byte header; identifies the package.
    pub hash: [u8; 32],
    /// Size of the `.apkg` file.
    pub size: u64,
    /// Number of inodes in the package's squashfs image.
    pub inodes: u32,
    /// Full package name, e.g. `sys-libs.zlib.libs.1.3.1.linux.amd64`.
    pub name: String,
    /// Path of the `.apkg` relative to `<prefix>dist/<db>/`.
    pub path: String,
    /// Raw 124-byte package header.
    pub header: Vec<u8>,
    /// Raw signature blob of the header.
    pub sig: Vec<u8>,
    /// Raw JSON metadata.
    pub meta: Vec<u8>,
}

impl PackageRecord {
    /// Decode one record.
    pub fn read(c: &mut Cursor<'_>) -> Result<PackageRecord> {
        let t = c.u8()?;
        if t != 0 {
            return Err(Error::Format(format!(
                "invalid data in db (invalid package type {t})"
            )));
        }
        let hash: [u8; 32] = c.take(32)?.try_into().unwrap();
        let size = c.u64_be()?;
        let inodes = c.u32_be()?;
        let name = utf8(c.varblob(256)?, "name")?;
        let path = utf8(c.varblob(256)?, "path")?;
        let header = c.varblob(256)?.to_vec();
        let sig = c.varblob(SIGNATURE_SIZE as u64)?.to_vec();
        let meta = c.varblob(1024 * 1024)?.to_vec();
        Ok(PackageRecord {
            hash,
            size,
            inodes,
            name,
            path,
            header,
            sig,
            meta,
        })
    }

    /// Encode this record (same encoding as in APDB files).
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.inodes.to_be_bytes());
        sig::put_varblob(out, self.name.as_bytes());
        sig::put_varblob(out, self.path.as_bytes());
        sig::put_varblob(out, &self.header);
        sig::put_varblob(out, &self.sig);
        sig::put_varblob(out, &self.meta);
    }
}

fn utf8(b: &[u8], what: &str) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| Error::Format(format!("non utf-8 package {what}")))
}

/// A parsed and verified database file.
#[derive(Debug)]
pub struct Database {
    pub flags: u64,
    /// Creation time (unix seconds).
    pub created: i64,
    pub created_nsec: u64,
    pub os: u32,
    pub arch: u32,
    pub name: String,
    /// Owner of the key that signed this database.
    pub signer: &'static str,
    pub packages: Vec<PackageRecord>,
}

/// Parse an APDB file, checking the data hash and the header signature
/// against the trusted database keys.
pub fn parse(data: &[u8]) -> Result<Database> {
    if data.len() < HEADER_LEN + SIGNATURE_SIZE || &data[..4] != b"APDB" {
        return Err(Error::Format("not an apkgdb file".into()));
    }
    let mut c = Cursor::new(&data[4..HEADER_LEN]);
    if c.u32_be()? != 1 {
        return Err(Error::Format("unsupported db version".into()));
    }
    let flags = c.u64_be()?;
    let created = c.u64_be()? as i64;
    let created_nsec = c.u64_be()?;
    let os = c.u32_be()?;
    let arch = c.u32_be()?;
    let count = c.u32_be()?;
    let name = c.take(32)?;
    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(32)];
    let name = utf8(name, "database name")?;
    let data_loc = c.u32_be()? as usize;
    let data_len = c.u32_be()? as usize;
    let data_hash = c.take(32)?;

    let end = data_loc
        .checked_add(data_len)
        .filter(|&e| e <= data.len() && data_loc >= HEADER_LEN)
        .ok_or_else(|| Error::Format("data area out of bounds".into()))?;
    if sig::sha256(&data[data_loc..end]) != data_hash {
        return Err(Error::Integrity("invalid data hash".into()));
    }
    let signer = sig::verify_db(&data[..HEADER_LEN], &data[HEADER_LEN..])?.name;

    let mut c = Cursor::new(&data[data_loc..end]);
    let mut packages = Vec::with_capacity(count.min(1 << 20) as usize);
    for _ in 0..count {
        packages.push(PackageRecord::read(&mut c)?);
    }
    Ok(Database {
        flags,
        created,
        created_nsec,
        os,
        arch,
        name,
        signer,
        packages,
    })
}
