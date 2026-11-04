//! A package file backed by a local sparse cache and fetched over HTTP on
//! demand, one verified block at a time.
//!
//! Every block of the squashfs image is checked against the package's hash
//! table (whose own hash is in the signed header) before it is served, so
//! the transport does not need to be trusted and a damaged or partial local
//! cache heals itself.

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::http;
use crate::pkgfile::{HEADER_LEN, Header};
use crate::sig;

/// Largest single range request, in bytes.
const MAX_RUN_BYTES: u64 = 16 << 20;
/// Read-ahead after a random miss, in bytes.
const MIN_READAHEAD: u64 = 512 << 10;
/// Read-ahead ceiling; it doubles on each sequential miss up to this.
const MAX_READAHEAD: u64 = 8 << 20;

struct Blocks {
    /// One flag per block: verified present in the local file.
    verified: Vec<bool>,
    /// Block right after the last fetched run (sequential detection).
    next_seq: usize,
    /// Current read-ahead window, bytes.
    readahead: u64,
}

#[cfg(any(unix, target_os = "fullrust"))]
mod pio {
    use std::fs::File;
    use std::io::Result;
    use std::os::unix::fs::FileExt;

    pub(super) struct PFile(File);
    impl PFile {
        pub(super) fn new(f: File) -> Self {
            PFile(f)
        }
        pub(super) fn read_at(&self, buf: &mut [u8], off: u64) -> Result<usize> {
            let mut done = 0;
            while done < buf.len() {
                match self.0.read_at(&mut buf[done..], off + done as u64)? {
                    0 => break,
                    n => done += n,
                }
            }
            Ok(done)
        }
        pub(super) fn write_at(&self, buf: &[u8], off: u64) -> Result<()> {
            self.0.write_all_at(buf, off)
        }
    }
}

#[cfg(not(any(unix, target_os = "fullrust")))]
mod pio {
    use std::fs::File;
    use std::io::{Read, Result, Seek, SeekFrom, Write};
    use std::sync::Mutex;

    pub(super) struct PFile(Mutex<File>);
    impl PFile {
        pub(super) fn new(f: File) -> Self {
            PFile(Mutex::new(f))
        }
        pub(super) fn read_at(&self, buf: &mut [u8], off: u64) -> Result<usize> {
            let mut f = self.0.lock().unwrap();
            f.seek(SeekFrom::Start(off))?;
            let mut done = 0;
            while done < buf.len() {
                match f.read(&mut buf[done..])? {
                    0 => break,
                    n => done += n,
                }
            }
            Ok(done)
        }
        pub(super) fn write_at(&self, buf: &[u8], off: u64) -> Result<()> {
            let mut f = self.0.lock().unwrap();
            f.seek(SeekFrom::Start(off))?;
            f.write_all(buf)
        }
    }
}

/// Lazily fetched, verified package file.
pub struct RemoteFile {
    url: String,
    file: pio::PFile,
    header: Header,
    /// Length of the squashfs image.
    data_len: u64,
    hashes: Vec<[u8; 32]>,
    blocks: Mutex<Blocks>,
}

impl std::fmt::Debug for RemoteFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteFile")
            .field("url", &self.url)
            .field("data_len", &self.data_len)
            .finish()
    }
}

impl RemoteFile {
    /// Open (creating if needed) the local cache at `local` for the package
    /// at `url`. `raw_header`, `signature` and `meta` come from the signed
    /// database; `hash` is the package id and `size` the `.apkg` file size.
    pub fn open(
        url: &str,
        local: &Path,
        raw_header: &[u8],
        signature: &[u8],
        meta: Option<&[u8]>,
        hash: &[u8; 32],
        size: u64,
    ) -> Result<RemoteFile> {
        let header = Header::verify(raw_header, signature, hash)?;
        let data_off = u64::from(header.data_offset);
        if data_off > size || (header.table_offset as u64 + header.table_len as u64) > data_off {
            return Err(Error::Format("package layout out of bounds".into()));
        }
        let data_len = size - data_off;
        let blocks = data_len.div_ceil(u64::from(header.block_size)) as usize;
        if header.table_len as usize != blocks * 32 {
            return Err(Error::Format(format!(
                "hash table has {} entries, image needs {blocks}",
                header.table_len / 32
            )));
        }

        if let Some(dir) = local.parent() {
            fs::create_dir_all(dir)?;
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(local)?;
        if f.metadata()?.len() != size {
            f.set_len(size)?;
        }
        let file = pio::PFile::new(f);

        // Keep the local copy a complete, valid .apkg: header, metadata,
        // signature and hash table are written up front.
        file.write_at(raw_header, 0)?;
        if let Some(meta) = meta
            && meta.len() == header.meta_len as usize
            && sig::sha256(meta) == header.meta_hash
        {
            file.write_at(meta, u64::from(header.meta_offset))?;
        }
        if (header.sig_offset as usize) >= HEADER_LEN
            && u64::from(header.sig_offset) + signature.len() as u64 <= data_off
        {
            file.write_at(signature, u64::from(header.sig_offset))?;
        }

        let mut table = vec![0u8; header.table_len as usize];
        let n = file.read_at(&mut table, u64::from(header.table_offset))?;
        if n != table.len() || sig::sha256(&table) != header.table_hash {
            table = http::get_range(
                url,
                u64::from(header.table_offset),
                u64::from(header.table_len),
            )?;
            if sig::sha256(&table) != header.table_hash {
                return Err(Error::Integrity("corrupted hash table".into()));
            }
            file.write_at(&table, u64::from(header.table_offset))?;
        }
        let hashes = table.as_chunks::<32>().0.to_vec();

        Ok(RemoteFile {
            url: url.to_string(),
            file,
            header,
            data_len,
            hashes,
            blocks: Mutex::new(Blocks {
                verified: vec![false; blocks],
                next_seq: usize::MAX,
                readahead: MIN_READAHEAD,
            }),
        })
    }

    /// Decoded package header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Size of the squashfs image.
    pub fn data_len(&self) -> u64 {
        self.data_len
    }

    fn block_range(&self, i: usize) -> (u64, usize) {
        let bs = u64::from(self.header.block_size);
        let start = i as u64 * bs;
        (start, (self.data_len - start).min(bs) as usize)
    }

    /// Check block `i` of the local file against the hash table.
    fn local_ok(&self, i: usize, buf: &mut Vec<u8>) -> Result<bool> {
        let (start, len) = self.block_range(i);
        buf.resize(len, 0);
        let n = self
            .file
            .read_at(buf, u64::from(self.header.data_offset) + start)?;
        Ok(n == len && sig::sha256(buf) == self.hashes[i])
    }

    fn blocks_in(&self, bytes: u64) -> usize {
        (bytes / u64::from(self.header.block_size)).max(1) as usize
    }

    /// Make blocks `first..=last` present and verified.
    fn ensure(&self, first: usize, last: usize) -> Result<()> {
        let mut st = self.blocks.lock().unwrap();
        if st.verified[first..=last].iter().all(|&v| v) {
            return Ok(());
        }
        let mut buf = Vec::new();
        let mut i = first;
        while i <= last {
            if st.verified[i] {
                i += 1;
                continue;
            }
            if self.local_ok(i, &mut buf)? {
                st.verified[i] = true;
                i += 1;
                continue;
            }
            // block i is missing: fetch a run of missing blocks starting
            // here, extended past `last` by the read-ahead window, which
            // grows while access stays sequential.
            st.readahead = if i == st.next_seq {
                (st.readahead * 2).min(MAX_READAHEAD)
            } else {
                MIN_READAHEAD
            };
            let limit = (last + self.blocks_in(st.readahead))
                .min(self.hashes.len() - 1)
                .min(i + self.blocks_in(MAX_RUN_BYTES) - 1);
            let mut end = i;
            while end < limit {
                let next = end + 1;
                if st.verified[next] {
                    break;
                }
                if self.local_ok(next, &mut buf)? {
                    st.verified[next] = true;
                    break;
                }
                end = next;
            }
            self.fetch(i, end, &mut st.verified)?;
            st.next_seq = end + 1;
            i = end + 1;
        }
        Ok(())
    }

    fn fetch(&self, first: usize, last: usize, verified: &mut [bool]) -> Result<()> {
        let (start, _) = self.block_range(first);
        let (lstart, llen) = self.block_range(last);
        let len = lstart + llen as u64 - start;
        let off = u64::from(self.header.data_offset) + start;
        let data = http::get_range(&self.url, off, len)?;
        let bs = self.header.block_size as usize;
        for (k, chunk) in data.chunks(bs).enumerate() {
            let i = first + k;
            if sig::sha256(chunk) != self.hashes[i] {
                return Err(Error::Integrity(format!(
                    "block {i} of {} failed verification",
                    self.url
                )));
            }
        }
        self.file.write_at(&data, off)?;
        for v in &mut verified[first..=last] {
            *v = true;
        }
        Ok(())
    }

    /// Read squashfs image bytes at `offset`; returns bytes read (short only
    /// at end of image).
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.data_len || buf.is_empty() {
            return Ok(0);
        }
        let len = (buf.len() as u64).min(self.data_len - offset) as usize;
        let bs = u64::from(self.header.block_size);
        let first = (offset / bs) as usize;
        let last = ((offset + len as u64 - 1) / bs) as usize;
        self.ensure(first, last)?;
        let n = self
            .file
            .read_at(&mut buf[..len], u64::from(self.header.data_offset) + offset)?;
        if n != len {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read from cache",
            )));
        }
        Ok(len)
    }

    /// Fetch and verify the whole image (e.g. to pre-cache a package).
    pub fn fetch_all(&self) -> Result<()> {
        let n = self.hashes.len();
        let mut i = 0;
        while i < n {
            let last = (i + self.blocks_in(MAX_RUN_BYTES) - 1).min(n - 1);
            self.ensure(i, last)?;
            i = last + 1;
        }
        Ok(())
    }
}
