//! A single package: lazily downloaded, verified, and browsable through its
//! squashfs image (read with `fstool`).
//!
//! Two APIs are offered:
//!
//! * a path API (`stat`, `read_dir`, `read_link`, `read_at`, `read_file`)
//!   for library users, and
//! * a node API keyed by *local inode numbers* (`1` is the package root),
//!   used by the FUSE layer. Local numbers are squashfs inode numbers with
//!   the root swapped to `1`, exactly as the Go implementation numbered them.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fstool::block::BlockDevice;
use fstool::fs::EntryKind;
use fstool::fs::squashfs::Squashfs;

use crate::error::{Error, Result};
use crate::json::Value;
use crate::remote::RemoteFile;

/// How long a failed download is remembered before retrying.
const RETRY_AFTER: Duration = Duration::from_secs(10);

/// Kind of a filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl FileKind {
    fn from_entry(k: EntryKind) -> FileKind {
        match k {
            EntryKind::Dir => FileKind::Dir,
            EntryKind::Symlink => FileKind::Symlink,
            EntryKind::Char => FileKind::CharDevice,
            EntryKind::Block => FileKind::BlockDevice,
            EntryKind::Fifo => FileKind::Fifo,
            EntryKind::Socket => FileKind::Socket,
            _ => FileKind::File,
        }
    }

    /// `S_IFMT` bits for this kind.
    pub fn mode_bits(self) -> u32 {
        match self {
            FileKind::Fifo => 0o010000,
            FileKind::CharDevice => 0o020000,
            FileKind::Dir => 0o040000,
            FileKind::BlockDevice => 0o060000,
            FileKind::File => 0o100000,
            FileKind::Symlink => 0o120000,
            FileKind::Socket => 0o140000,
        }
    }

    /// `DT_*` value for directory listings.
    pub fn dirent_type(self) -> u32 {
        self.mode_bits() >> 12
    }
}

/// Attributes of a node inside a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// Local inode number (1 = package root).
    pub ino: u32,
    pub kind: FileKind,
    /// Permission bits (including setuid/setgid/sticky).
    pub perm: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub size: u64,
}

impl Attr {
    /// Full `st_mode`.
    pub fn mode(&self) -> u32 {
        self.kind.mode_bits() | u32::from(self.perm & 0o7777)
    }
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    /// Local inode number.
    pub ino: u32,
    pub kind: FileKind,
}

/// `fstool` block device over the verified remote file.
struct PkgDevice {
    remote: Arc<RemoteFile>,
    pos: u64,
}

impl Read for PkgDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.remote.read_at(self.pos, buf).map_err(io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for PkgDevice {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "read-only package"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for PkgDevice {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.remote.data_len() as i128;
        let p = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
            SeekFrom::End(d) => len + d as i128,
        };
        if p < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

impl BlockDevice for PkgDevice {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.remote.data_len()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> fstool::Result<()> {
        let n = self.remote.read_at(offset, buf).map_err(|e| fstool::Error::Io(io::Error::other(e)))?;
        if n != buf.len() {
            return Err(fstool::Error::OutOfBounds { offset, len: buf.len() as u64, size: self.remote.data_len() });
        }
        Ok(())
    }
}

#[derive(Default)]
struct Nodes {
    paths: HashMap<u32, String>,
    attrs: HashMap<u32, Attr>,
    dirs: HashMap<u32, Arc<Vec<DirEntry>>>,
}

/// An opened (downloaded header + hash table, mounted squashfs) package.
struct Opened {
    remote: Arc<RemoteFile>,
    sq: Mutex<Squashfs>,
    /// squashfs inode number of the root directory
    root_n: u32,
    nodes: Mutex<Nodes>,
}

enum State {
    Closed,
    Open(Arc<Opened>),
    Failed(Instant, String),
}

/// A package of a database.
pub struct Package {
    name: String,
    hash: [u8; 32],
    size: u64,
    inodes: u32,
    rel_path: String,
    url: String,
    local: PathBuf,
    header: Vec<u8>,
    sig: Vec<u8>,
    meta: Vec<u8>,
    start_ino: AtomicU64,
    state: Mutex<State>,
}

impl std::fmt::Debug for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Package").field("name", &self.name).field("path", &self.rel_path).finish()
    }
}

fn not_found_or(e: fstool::Error) -> Error {
    match &e {
        fstool::Error::InvalidArgument(m) if m.contains("no such entry") => Error::NotFound,
        _ => Error::from(e),
    }
}

impl Package {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: String,
        hash: [u8; 32],
        size: u64,
        inodes: u32,
        rel_path: String,
        url: String,
        local: PathBuf,
        header: Vec<u8>,
        sig: Vec<u8>,
        meta: Vec<u8>,
    ) -> Package {
        Package {
            name,
            hash,
            size,
            inodes,
            rel_path,
            url,
            local,
            header,
            sig,
            meta,
            start_ino: AtomicU64::new(0),
            state: Mutex::new(State::Closed),
        }
    }

    /// Full package name, e.g. `sys-libs.zlib.libs.1.3.1.linux.amd64`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Package id: sha256 of its signed header.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Size of the `.apkg` file.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Number of inodes in the package image.
    pub fn inode_count(&self) -> u32 {
        self.inodes
    }

    /// Path relative to the repository's `dist/<db>/`.
    pub fn repo_path(&self) -> &str {
        &self.rel_path
    }

    /// Download URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Location of the local cache file.
    pub fn local_path(&self) -> &std::path::Path {
        &self.local
    }

    /// Raw JSON metadata (from the signed database).
    pub fn meta_raw(&self) -> &[u8] {
        &self.meta
    }

    /// Parsed metadata.
    pub fn meta(&self) -> Result<Value> {
        Value::parse(&self.meta).map_err(Error::Format)
    }

    pub(crate) fn start_ino(&self) -> u64 {
        self.start_ino.load(Ordering::Acquire)
    }

    pub(crate) fn set_start_ino(&self, v: u64) {
        self.start_ino.store(v, Ordering::Release);
    }

    fn opened(&self) -> Result<Arc<Opened>> {
        let mut st = self.state.lock().unwrap();
        match &*st {
            State::Open(o) => return Ok(o.clone()),
            State::Failed(when, msg) if when.elapsed() < RETRY_AFTER => {
                return Err(Error::Io(io::Error::other(msg.clone())));
            }
            _ => {}
        }
        match self.do_open() {
            Ok(o) => {
                let o = Arc::new(o);
                *st = State::Open(o.clone());
                Ok(o)
            }
            Err(e) => {
                crate::log!("apkgdb: failed to open package {}: {e}", self.name);
                *st = State::Failed(Instant::now(), e.to_string());
                Err(e)
            }
        }
    }

    fn do_open(&self) -> Result<Opened> {
        let remote = Arc::new(RemoteFile::open(
            &self.url,
            &self.local,
            &self.header,
            &self.sig,
            Some(&self.meta),
            &self.hash,
            self.size,
        )?);
        let mut dev = PkgDevice { remote: remote.clone(), pos: 0 };
        let sq = Squashfs::open(&mut dev)?;
        let root = sq.inode_meta(&mut dev, "/")?;
        let opened = Opened { remote, sq: Mutex::new(sq), root_n: root.inode_number, nodes: Mutex::new(Nodes::default()) };
        opened.nodes.lock().unwrap().paths.insert(1, "/".to_string());
        Ok(opened)
    }

    /// Download and verify the whole package into the local cache.
    pub fn fetch_all(&self) -> Result<()> {
        self.opened()?.remote.fetch_all()
    }

    // ---- path API -------------------------------------------------------

    fn norm(path: &str) -> String {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        format!("/{}", parts.join("/"))
    }

    /// Attributes of the node at `path`.
    pub fn stat(&self, path: &str) -> Result<Attr> {
        let o = self.opened()?;
        let p = Self::norm(path);
        o.attr_of_path(&p)
    }

    /// List the directory at `path` (without `.`/`..`).
    pub fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let o = self.opened()?;
        let a = o.attr_of_path(&Self::norm(path))?;
        o.node_readdir(a.ino).map(|v| v.as_ref().clone())
    }

    /// Target of the symlink at `path`.
    pub fn read_link(&self, path: &str) -> Result<String> {
        let o = self.opened()?;
        let mut dev = o.dev();
        o.sq.lock().unwrap().read_symlink(&mut dev, &Self::norm(path)).map_err(not_found_or)
    }

    /// Read from the regular file at `path`.
    pub fn read_at(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let o = self.opened()?;
        o.read_path(&Self::norm(path), offset, buf)
    }

    /// Read a whole regular file.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let a = self.stat(path)?;
        if a.kind != FileKind::File {
            return Err(Error::Invalid(format!("{path} is not a regular file")));
        }
        let mut buf = vec![0u8; a.size as usize];
        let n = self.read_at(path, 0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    // ---- node API (local inode numbers) ----------------------------------

    /// Attributes of local node `ino`.
    pub fn node_attr(&self, ino: u32) -> Result<Attr> {
        self.opened()?.node_attr(ino)
    }

    /// Look `name` up in directory node `parent`.
    pub fn node_lookup(&self, parent: u32, name: &str) -> Result<Attr> {
        self.opened()?.node_lookup(parent, name)
    }

    /// Entries of directory node `ino`.
    pub fn node_readdir(&self, ino: u32) -> Result<Arc<Vec<DirEntry>>> {
        self.opened()?.node_readdir(ino)
    }

    /// Symlink target of node `ino`.
    pub fn node_readlink(&self, ino: u32) -> Result<String> {
        let o = self.opened()?;
        let p = o.path_of(ino)?;
        let mut dev = o.dev();
        o.sq.lock().unwrap().read_symlink(&mut dev, &p).map_err(not_found_or)
    }

    /// Read file node `ino`.
    pub fn node_read(&self, ino: u32, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let o = self.opened()?;
        let p = o.path_of(ino)?;
        o.read_path(&p, offset, buf)
    }
}

impl Opened {
    fn dev(&self) -> PkgDevice {
        PkgDevice { remote: self.remote.clone(), pos: 0 }
    }

    fn to_local(&self, n: u32) -> u32 {
        if n == self.root_n {
            1
        } else if n == 1 {
            self.root_n
        } else {
            n
        }
    }

    fn path_of(&self, ino: u32) -> Result<String> {
        self.nodes.lock().unwrap().paths.get(&ino).cloned().ok_or(Error::NotFound)
    }

    fn attr_of_path(&self, path: &str) -> Result<Attr> {
        let mut dev = self.dev();
        let m = self.sq.lock().unwrap().inode_meta(&mut dev, path).map_err(not_found_or)?;
        let ino = self.to_local(m.inode_number);
        let a = Attr {
            ino,
            kind: FileKind::from_entry(m.kind),
            perm: m.mode,
            uid: m.uid,
            gid: m.gid,
            mtime: m.mtime,
            size: m.file_size,
        };
        let mut nodes = self.nodes.lock().unwrap();
        nodes.paths.entry(ino).or_insert_with(|| path.to_string());
        nodes.attrs.insert(ino, a.clone());
        Ok(a)
    }

    fn node_attr(&self, ino: u32) -> Result<Attr> {
        if let Some(a) = self.nodes.lock().unwrap().attrs.get(&ino) {
            return Ok(a.clone());
        }
        let p = self.path_of(ino)?;
        self.attr_of_path(&p)
    }

    fn node_readdir(&self, ino: u32) -> Result<Arc<Vec<DirEntry>>> {
        if let Some(d) = self.nodes.lock().unwrap().dirs.get(&ino) {
            return Ok(d.clone());
        }
        let p = self.path_of(ino)?;
        let mut dev = self.dev();
        let raw = self.sq.lock().unwrap().list_path(&mut dev, &p).map_err(not_found_or)?;
        let list: Vec<DirEntry> = raw
            .into_iter()
            .map(|e| DirEntry { ino: self.to_local(e.inode), kind: FileKind::from_entry(e.kind), name: e.name })
            .collect();
        let list = Arc::new(list);
        let mut nodes = self.nodes.lock().unwrap();
        for e in list.iter() {
            nodes.paths.entry(e.ino).or_insert_with(|| if p == "/" { format!("/{}", e.name) } else { format!("{p}/{}", e.name) });
        }
        nodes.dirs.insert(ino, list.clone());
        Ok(list)
    }

    fn node_lookup(&self, parent: u32, name: &str) -> Result<Attr> {
        let list = self.node_readdir(parent)?;
        let e = list.iter().find(|e| e.name == name).ok_or(Error::NotFound)?;
        self.node_attr(e.ino)
    }

    fn read_path(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut dev = self.dev();
        let sq = self.sq.lock().unwrap();
        let mut h = sq.open_file_read_handle(&mut dev, path).map_err(not_found_or)?;
        h.seek(SeekFrom::Start(offset))?;
        let mut done = 0;
        while done < buf.len() {
            match h.read(&mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }
}
