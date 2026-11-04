//! FUSE server exposing a [`Db`] as a read-only filesystem, speaking the
//! kernel protocol on `/dev/fuse` directly (no libfuse).
//!
//! Layout of the mount (e.g. `/pkg/main`):
//!
//! * the root is not listable; looking up a name resolves a package:
//!   an exact full name is the package directory, a partial name is a
//!   symlink to the latest matching full name;
//! * names may carry a `.os.arch` suffix to reach another platform's
//!   database;
//! * `ld.so.cache` is the merged loader cache of every library package.

pub mod abi;

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use abi::{FileAttr, InHeader, Out, u32_at, u64_at};

use crate::db::{self, Db, Node};
use crate::error::Error;
use crate::package::FileKind;
use crate::sys;

const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EACCES: i32 = 13;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const EPERM: i32 = 1;
const EROFS: i32 = 30;
const ENOSYS: i32 = 38;
const EPROTO: i32 = 71;
const ENODEV: i32 = 19;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;

/// Largest read/write payload we negotiate.
const MAX_IO: u32 = 128 * 1024;
/// Request buffer: payload plus generous room for headers.
const BUF_SIZE: usize = MAX_IO as usize + 64 * 1024;
/// Entry and attribute cache timeout, seconds.
const TTL: u64 = 30;

/// How the filesystem was mounted (decides how to unmount).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountKind {
    Direct,
    Fusermount,
}

/// Mount options.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Let other users access the mount (`allow_other`).
    pub allow_other: bool,
    /// Value shown as the mount source.
    pub fsname: String,
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            allow_other: sys::geteuid() == 0,
            fsname: "apkg".into(),
        }
    }
}

/// An active mount: the `/dev/fuse` channel and its mountpoint.
pub struct Mount {
    dev: Arc<File>,
    mountpoint: PathBuf,
    kind: MountKind,
    unmounted: AtomicBool,
}

impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mount")
            .field("mountpoint", &self.mountpoint)
            .field("kind", &self.kind)
            .finish()
    }
}

fn path_str(p: &Path) -> io::Result<&str> {
    p.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mountpoint is not valid UTF-8"))
}

impl Mount {
    /// Mount a FUSE filesystem on `mountpoint`. As root the kernel mount is
    /// done directly; otherwise `fusermount3` (or `fusermount`) is used.
    pub fn new(mountpoint: &Path, opts: &MountOptions) -> io::Result<Mount> {
        std::fs::create_dir_all(mountpoint)?;
        if sys::geteuid() == 0 {
            Self::mount_direct(mountpoint, opts)
        } else {
            Self::mount_fusermount(mountpoint, opts)
        }
    }

    fn mount_direct(mountpoint: &Path, opts: &MountOptions) -> io::Result<Mount> {
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")?;
        let mut data = format!(
            "fd={},rootmode=40000,user_id={},group_id={},max_read={MAX_IO}",
            dev.as_raw_fd(),
            sys::getuid(),
            sys::getgid()
        );
        if opts.allow_other {
            data.push_str(",allow_other");
        }
        let flags = sys::MS_RDONLY | sys::MS_NOSUID | sys::MS_NODEV | sys::MS_NOATIME;
        sys::mount(
            &opts.fsname,
            path_str(mountpoint)?,
            "fuse.apkg",
            flags,
            &data,
        )?;
        Ok(Mount {
            dev: Arc::new(dev),
            mountpoint: mountpoint.to_path_buf(),
            kind: MountKind::Direct,
            unmounted: AtomicBool::new(false),
        })
    }

    fn mount_fusermount(mountpoint: &Path, opts: &MountOptions) -> io::Result<Mount> {
        use std::os::unix::net::UnixStream;
        let mut o = format!(
            "ro,nosuid,nodev,noatime,fsname={},subtype=apkg,max_read={MAX_IO}",
            opts.fsname
        );
        if opts.allow_other {
            o.push_str(",allow_other");
        }
        let mut last = io::Error::new(io::ErrorKind::NotFound, "fusermount not found");
        for bin in ["fusermount3", "fusermount"] {
            let (ours, theirs) = UnixStream::pair()?;
            sys::clear_cloexec(theirs.as_raw_fd())?;
            let child = Command::new(bin)
                .arg("-o")
                .arg(&o)
                .arg("--")
                .arg(mountpoint)
                .env("_FUSE_COMMFD", theirs.as_raw_fd().to_string())
                .spawn();
            drop(theirs);
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let fd = sys::recv_fd(ours.as_raw_fd());
            let status = child.wait()?;
            let fd = match fd {
                Ok(fd) => fd,
                Err(e) => {
                    return Err(io::Error::other(format!("{bin} failed ({status}): {e}")));
                }
            };
            use std::os::fd::FromRawFd;
            let dev = unsafe { File::from_raw_fd(fd) };
            return Ok(Mount {
                dev: Arc::new(dev),
                mountpoint: mountpoint.to_path_buf(),
                kind: MountKind::Fusermount,
                unmounted: AtomicBool::new(false),
            });
        }
        Err(last)
    }

    /// Adopt a FUSE connection inherited from a previous process (see
    /// [`Server::graceful_exec`] and [`Handoff::from_env`]). The kernel
    /// mount already exists; unmounting later works as for a fresh mount.
    pub fn inherited(handoff: &Handoff) -> io::Result<Mount> {
        use std::os::fd::FromRawFd;
        if handoff.fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad inherited fd",
            ));
        }
        let dev = unsafe { File::from_raw_fd(handoff.fd) };
        // keep it from leaking into children again
        sys::set_cloexec(handoff.fd)?;
        Ok(Mount {
            dev: Arc::new(dev),
            mountpoint: handoff.mountpoint.clone(),
            kind: if sys::geteuid() == 0 {
                MountKind::Direct
            } else {
                MountKind::Fusermount
            },
            unmounted: AtomicBool::new(false),
        })
    }

    /// Mountpoint path.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Detach the filesystem. Safe to call more than once.
    pub fn unmount(&self) -> io::Result<()> {
        if self.unmounted.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        match self.kind {
            MountKind::Direct => sys::umount(path_str(&self.mountpoint)?, sys::MNT_DETACH),
            MountKind::Fusermount => {
                for bin in ["fusermount3", "fusermount"] {
                    if let Ok(s) = Command::new(bin)
                        .arg("-u")
                        .arg("-z")
                        .arg("--")
                        .arg(&self.mountpoint)
                        .status()
                        && s.success()
                    {
                        return Ok(());
                    }
                }
                Err(io::Error::other("fusermount -u failed"))
            }
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

/// Serves a [`Db`] on a [`Mount`].
pub struct Server {
    db: Db,
    mount: Arc<Mount>,
    minor: AtomicU32,
    initialized: AtomicBool,
    /// Held (shared) while a request read from the kernel is being
    /// answered; taken exclusively before handing the connection over.
    gate: RwLock<()>,
}

/// Environment variables carrying a live mount to a new process. The fd
/// and mountpoint names match the Go daemon's.
pub const ENV_FD: &str = "APKG_FUSE_FD";
pub const ENV_MOUNTPOINT: &str = "APKG_MOUNT_POINT";
pub const ENV_STATE: &str = "APKG_FUSE_STATE";
pub const ENV_MINOR: &str = "APKG_FUSE_MINOR";

/// A FUSE connection handed over by a previous process.
#[derive(Debug, Clone)]
pub struct Handoff {
    pub fd: i32,
    pub mountpoint: PathBuf,
    /// Inode allocation state file written by the previous process.
    pub state: Option<PathBuf>,
    /// Protocol minor negotiated by the previous process, if known.
    pub minor: Option<u32>,
}

impl Handoff {
    /// Read (and remove from the environment) a handoff left by
    /// [`Server::graceful_exec`] or by the Go daemon's graceful restart.
    ///
    /// # Safety
    /// Modifies the process environment: call before spawning threads.
    pub unsafe fn from_env() -> Option<Handoff> {
        let fd = std::env::var(ENV_FD).ok();
        let mp = std::env::var_os(ENV_MOUNTPOINT);
        let state = std::env::var_os(ENV_STATE).map(PathBuf::from);
        let minor = std::env::var(ENV_MINOR).ok().and_then(|m| m.parse().ok());
        for k in [ENV_FD, ENV_MOUNTPOINT, ENV_STATE, ENV_MINOR] {
            unsafe { std::env::remove_var(k) };
        }
        let fd: i32 = fd?.parse().ok()?;
        Some(Handoff {
            fd,
            mountpoint: PathBuf::from(mp?),
            state,
            minor,
        })
    }
}

impl Server {
    /// Prepare a server; call [`Server::run`] to process requests.
    pub fn new(db: Db, mount: Mount) -> Arc<Server> {
        let s = Arc::new(Server {
            db,
            mount: Arc::new(mount),
            minor: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
            gate: RwLock::new(()),
        });
        // push ld.so.cache changes into the kernel page cache
        let weak = Arc::downgrade(&s);
        s.db.set_notify(Box::new(move |ino, off, data| {
            if let Some(s) = weak.upgrade() {
                s.notify_store(ino, off, data);
            }
        }));
        s
    }

    /// Serve a connection inherited from a previous process: the kernel
    /// handshake (INIT) already happened, so requests are served at once.
    pub fn new_inherited(db: Db, mount: Mount, minor: Option<u32>) -> Arc<Server> {
        let s = Self::new(db, mount);
        s.minor.store(minor.unwrap_or(28), Ordering::Release);
        s.initialized.store(true, Ordering::Release);
        s
    }

    /// Replace this process with `exe`, handing it the live connection:
    /// in-flight requests are answered first, the inode allocation is saved
    /// to `state_file`, and the new process picks the mount up through the
    /// environment (see [`Handoff::from_env`]). Returns only on failure.
    pub fn graceful_exec(&self, exe: &Path, state_file: &Path) -> io::Error {
        use std::os::unix::process::CommandExt;
        if let Err(e) = std::fs::write(state_file, self.db.inode_state().encode()) {
            return e;
        }
        let fd = self.mount.dev.as_raw_fd();
        // stop answering: wait for every request being processed
        let _gate = self.gate.write().unwrap();
        if let Err(e) = sys::clear_cloexec(fd) {
            return e;
        }
        crate::log!(
            "apkgfs: graceful exec to {} (fd={fd}, mount={})",
            exe.display(),
            self.mount.mountpoint.display()
        );
        let err = Command::new(exe)
            .args(std::env::args_os().skip(1))
            .env(ENV_FD, fd.to_string())
            .env(ENV_MOUNTPOINT, &self.mount.mountpoint)
            .env(ENV_STATE, state_file)
            .env(ENV_MINOR, self.minor.load(Ordering::Acquire).to_string())
            .exec();
        let _ = sys::set_cloexec(fd);
        err
    }

    /// The underlying mount.
    pub fn mount(&self) -> &Mount {
        &self.mount
    }

    /// Unmount; [`Server::run`] returns once the kernel closes the channel.
    pub fn unmount(&self) -> io::Result<()> {
        self.mount.unmount()
    }

    /// Process requests with `threads` workers until the filesystem is
    /// unmounted.
    pub fn run(self: &Arc<Self>, threads: usize) {
        let mut handles = Vec::new();
        for i in 1..threads.max(1) {
            let s = self.clone();
            if let Ok(h) = std::thread::Builder::new()
                .name(format!("fuse-{i}"))
                .spawn(move || s.worker())
            {
                handles.push(h);
            }
        }
        self.worker();
        for h in handles {
            let _ = h.join();
        }
    }

    fn worker(&self) {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = match (&*self.mount.dev).read(&mut buf) {
                Ok(n) => n,
                Err(e) => match e.raw_os_error() {
                    Some(ENOENT) | Some(EINTR) | Some(EAGAIN) => continue,
                    Some(ENODEV) => return,
                    _ => {
                        crate::log!("apkgfs: read from /dev/fuse failed: {e}");
                        return;
                    }
                },
            };
            let _gate = self.gate.read().unwrap();
            let req = &buf[..n];
            let Some(h) = InHeader::parse(req) else {
                continue;
            };
            let body = &req[abi::IN_HEADER_LEN.min(req.len())..];
            if let Some(reply) = self.dispatch(&h, body) {
                self.send(&reply);
            }
            if h.opcode == abi::DESTROY {
                return;
            }
        }
    }

    fn send(&self, msg: &[u8]) {
        if let Err(e) = (&*self.mount.dev).write(msg) {
            // ENOENT: the request was interrupted meanwhile
            if e.raw_os_error() != Some(ENOENT) {
                crate::log!("apkgfs: write to /dev/fuse failed: {e}");
            }
        }
    }

    fn notify_store(&self, ino: u64, off: u64, data: &[u8]) {
        if !self.initialized.load(Ordering::Acquire) {
            return;
        }
        // invalidate attributes (new size) and cached pages, then push data
        let mut inval = Out::new();
        inval.u64(ino).u64(0).u64(0);
        let _ = (&*self.mount.dev).write(&abi::reply(0, abi::NOTIFY_INVAL_INODE, &inval.0));
        let mut store = Out::new();
        store
            .u64(ino)
            .u64(off)
            .u32(data.len() as u32)
            .u32(0)
            .bytes(data);
        let _ = (&*self.mount.dev).write(&abi::reply(0, abi::NOTIFY_STORE, &store.0));
    }

    fn ok(h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        Some(abi::reply(h.unique, 0, body))
    }

    fn err(h: &InHeader, errno: i32) -> Option<Vec<u8>> {
        Some(abi::reply(h.unique, -errno, &[]))
    }

    fn dispatch(&self, h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        match h.opcode {
            abi::INIT => self.init(h, body),
            abi::DESTROY => Self::ok(h, &[]),
            abi::FORGET | abi::BATCH_FORGET | abi::INTERRUPT => None,
            _ if !self.initialized.load(Ordering::Acquire) => Self::err(h, EPROTO),
            abi::LOOKUP => self.lookup(h, body),
            abi::GETATTR => self.getattr(h),
            abi::READLINK => self.readlink(h),
            abi::OPEN => self.open(h, body),
            abi::READ => self.read(h, body),
            abi::OPENDIR => self.opendir(h),
            abi::READDIR => self.readdir(h, body, false),
            abi::READDIRPLUS => self.readdir(h, body, true),
            abi::RELEASE | abi::RELEASEDIR | abi::FLUSH | abi::FSYNC | abi::FSYNCDIR => {
                Self::ok(h, &[])
            }
            abi::STATFS => self.statfs(h),
            abi::ACCESS => self.access(h, body),
            abi::SETATTR
            | abi::SYMLINK
            | abi::MKNOD
            | abi::MKDIR
            | abi::UNLINK
            | abi::RMDIR
            | abi::RENAME
            | abi::RENAME2
            | abi::LINK
            | abi::WRITE
            | abi::CREATE
            | abi::SETXATTR
            | abi::REMOVEXATTR
            | abi::FALLOCATE
            | abi::COPY_FILE_RANGE => Self::err(h, EROFS),
            _ => Self::err(h, ENOSYS),
        }
    }

    fn init(&self, h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        let (Some(major), Some(minor), Some(readahead), Some(flags)) = (
            u32_at(body, 0),
            u32_at(body, 4),
            u32_at(body, 8),
            u32_at(body, 12),
        ) else {
            return Self::err(h, EINVAL);
        };
        if major < abi::KERNEL_VERSION {
            crate::log!("apkgfs: unsupported kernel FUSE protocol {major}.{minor}");
            return Self::err(h, EPROTO);
        }
        let mut out = Out::new();
        if major > abi::KERNEL_VERSION {
            // ask the kernel to retry with our major version
            out.u32(abi::KERNEL_VERSION)
                .u32(abi::KERNEL_MINOR_VERSION)
                .u32(0)
                .u32(0);
            out.0.resize(24, 0);
            return Self::ok(h, &out.0);
        }
        let minor = minor.min(abi::KERNEL_MINOR_VERSION);
        self.minor.store(minor, Ordering::Release);
        let want = abi::ASYNC_READ
            | abi::BIG_WRITES
            | abi::DO_READDIRPLUS
            | abi::READDIRPLUS_AUTO
            | abi::PARALLEL_DIROPS
            | abi::MAX_PAGES
            | abi::CACHE_SYMLINKS;
        out.u32(abi::KERNEL_VERSION)
            .u32(minor)
            .u32(readahead)
            .u32(flags & want);
        out.u16(16).u16(12); // max_background, congestion_threshold
        out.u32(MAX_IO); // max_write
        out.u32(1); // time_gran
        out.u16((MAX_IO / 4096) as u16).u16(0); // max_pages, map_alignment
        out.0.resize(64, 0);
        if minor < 23 {
            out.0.truncate(24);
        }
        self.initialized.store(true, Ordering::Release);
        Self::ok(h, &out.0)
    }

    fn node_attr(&self, ino: u64, node: &Node) -> Result<FileAttr, Error> {
        Ok(match node {
            Node::Root => FileAttr {
                ino,
                size: 4096,
                blocks: 1,
                mode: 0o040555,
                nlink: 1,
                blksize: 4096,
                ..Default::default()
            },
            Node::LdsoCache => {
                let n = self.db.ldso_cache().len() as u64;
                FileAttr {
                    ino,
                    size: n,
                    blocks: n.div_ceil(512),
                    mode: 0o100444,
                    nlink: 1,
                    blksize: 4096,
                    ..Default::default()
                }
            }
            Node::PackageLink(p) => FileAttr {
                ino,
                size: p.name().len() as u64,
                blocks: 1,
                mode: 0o120777,
                nlink: 1,
                blksize: 4096,
                ..Default::default()
            },
            Node::PackageNode(p, local) => {
                let a = p.node_attr(*local)?;
                FileAttr {
                    ino,
                    size: a.size,
                    blocks: a.size.div_ceil(512),
                    mtime: u64::from(a.mtime),
                    mode: a.mode(),
                    nlink: if a.kind == FileKind::Dir { 2 } else { 1 },
                    uid: a.uid,
                    gid: a.gid,
                    rdev: 0,
                    blksize: 4096,
                }
            }
        })
    }

    fn errno(e: &Error) -> i32 {
        match e.errno() {
            0 => EIO,
            n => n,
        }
    }

    fn lookup(&self, h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        let name = cstr(body);
        let Ok(name) = std::str::from_utf8(name) else {
            return Self::err(h, ENOENT);
        };
        let res = match self.db.node(h.nodeid) {
            Ok(Node::Root) => self.db.lookup(name).map(|l| Db::lookup_ino(&l)),
            Ok(Node::PackageNode(p, local)) => p.node_lookup(local, name).map(|a| p_ino(&p, a.ino)),
            Ok(_) => return Self::err(h, ENOTDIR),
            Err(e) => Err(e),
        };
        let ino = match res {
            Ok(i) => i,
            Err(e) => return Self::err(h, Self::errno(&e)),
        };
        match self.db.node(ino).and_then(|n| self.node_attr(ino, &n)) {
            Ok(a) => {
                let mut out = Out::new();
                out.entry(ino, &a, TTL, TTL);
                Self::ok(h, &out.0)
            }
            Err(e) => Self::err(h, Self::errno(&e)),
        }
    }

    fn getattr(&self, h: &InHeader) -> Option<Vec<u8>> {
        match self
            .db
            .node(h.nodeid)
            .and_then(|n| self.node_attr(h.nodeid, &n))
        {
            Ok(a) => {
                let mut out = Out::new();
                out.u64(TTL).u32(0).u32(0).attr(&a);
                Self::ok(h, &out.0)
            }
            Err(e) => Self::err(h, Self::errno(&e)),
        }
    }

    fn readlink(&self, h: &InHeader) -> Option<Vec<u8>> {
        match self.db.node(h.nodeid) {
            Ok(Node::PackageLink(p)) => Self::ok(h, p.name().as_bytes()),
            Ok(Node::PackageNode(p, local)) => match p.node_readlink(local) {
                Ok(t) => Self::ok(h, t.as_bytes()),
                Err(e) => Self::err(h, Self::errno(&e)),
            },
            Ok(_) => Self::err(h, EINVAL),
            Err(e) => Self::err(h, Self::errno(&e)),
        }
    }

    fn open(&self, h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        const O_ACCMODE: u32 = 3;
        if u32_at(body, 0).unwrap_or(0) & O_ACCMODE != 0 {
            return Self::err(h, EROFS);
        }
        let ok = match self.db.node(h.nodeid) {
            Ok(Node::LdsoCache) => true,
            Ok(Node::PackageNode(p, local)) => match p.node_attr(local) {
                Ok(a) => a.kind == FileKind::File,
                Err(e) => return Self::err(h, Self::errno(&e)),
            },
            Ok(_) => false,
            Err(e) => return Self::err(h, Self::errno(&e)),
        };
        if !ok {
            return Self::err(h, EINVAL);
        }
        // contents never change: let the kernel keep its page cache
        let mut out = Out::new();
        out.u64(0).u32(abi::FOPEN_KEEP_CACHE).u32(0);
        Self::ok(h, &out.0)
    }

    fn read(&self, h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        let (Some(off), Some(size)) = (u64_at(body, 8), u32_at(body, 16)) else {
            return Self::err(h, EINVAL);
        };
        let size = size.min(MAX_IO) as usize;
        match self.db.node(h.nodeid) {
            Ok(Node::LdsoCache) => {
                let d = self.db.ldso_cache();
                let start = (off as usize).min(d.len());
                let end = start.saturating_add(size).min(d.len());
                Self::ok(h, &d[start..end])
            }
            Ok(Node::PackageNode(p, local)) => {
                let mut buf = vec![0u8; size];
                match p.node_read(local, off, &mut buf) {
                    Ok(n) => Self::ok(h, &buf[..n]),
                    Err(e) => Self::err(h, Self::errno(&e)),
                }
            }
            Ok(_) => Self::err(h, EINVAL),
            Err(e) => Self::err(h, Self::errno(&e)),
        }
    }

    fn opendir(&self, h: &InHeader) -> Option<Vec<u8>> {
        match self.db.node(h.nodeid) {
            // the package root cannot be listed
            Ok(Node::Root) => Self::err(h, EPERM),
            Ok(Node::PackageNode(p, local)) => match p.node_attr(local) {
                Ok(a) if a.kind == FileKind::Dir => {
                    let mut out = Out::new();
                    out.u64(0)
                        .u32(abi::FOPEN_KEEP_CACHE | abi::FOPEN_CACHE_DIR)
                        .u32(0);
                    Self::ok(h, &out.0)
                }
                Ok(_) => Self::err(h, ENOTDIR),
                Err(e) => Self::err(h, Self::errno(&e)),
            },
            Ok(_) => Self::err(h, ENOTDIR),
            Err(e) => Self::err(h, Self::errno(&e)),
        }
    }

    fn readdir(&self, h: &InHeader, body: &[u8], plus: bool) -> Option<Vec<u8>> {
        let (Some(offset), Some(size)) = (u64_at(body, 8), u32_at(body, 16)) else {
            return Self::err(h, EINVAL);
        };
        let (p, local) = match self.db.node(h.nodeid) {
            Ok(Node::PackageNode(p, local)) => (p, local),
            Ok(Node::Root) => return Self::err(h, EPERM),
            Ok(_) => return Self::err(h, ENOTDIR),
            Err(e) => return Self::err(h, Self::errno(&e)),
        };
        let list = match p.node_readdir(local) {
            Ok(l) => l,
            Err(e) => return Self::err(h, Self::errno(&e)),
        };
        let size = size as usize;
        let mut out = Out::new();
        // entries: 0 = ".", 1 = "..", then the listing; `off` is the index
        // of the next entry
        let total = list.len() + 2;
        let mut idx = offset as usize;
        while idx < total {
            let (name, ino, typ): (&[u8], u64, u32) = match idx {
                0 => (b".", h.nodeid, FileKind::Dir.dirent_type()),
                1 => (b"..", 0, FileKind::Dir.dirent_type()),
                i => {
                    let e = &list[i - 2];
                    (e.name.as_bytes(), p_ino(&p, e.ino), e.kind.dirent_type())
                }
            };
            let need = if plus {
                abi::direntplus_size(name.len())
            } else {
                abi::dirent_size(name.len())
            };
            if out.0.len() + need > size {
                break;
            }
            if plus {
                if idx < 2 {
                    // no entry for . and ..: the kernel skips nodeid 0
                    out.entry(0, &FileAttr::default(), 0, 0);
                } else {
                    let a = match self.db.node(ino).and_then(|n| self.node_attr(ino, &n)) {
                        Ok(a) => a,
                        Err(e) => return Self::err(h, Self::errno(&e)),
                    };
                    out.entry(ino, &a, TTL, TTL);
                }
            }
            out.dirent(if idx == 1 { 1 } else { ino }, idx as u64 + 1, typ, name);
            idx += 1;
        }
        Self::ok(h, &out.0)
    }

    fn statfs(&self, h: &InHeader) -> Option<Vec<u8>> {
        let mut out = Out::new();
        let files = self.db.inodes_allocated();
        out.u64(files).u64(0).u64(0).u64(files).u64(0); // blocks, bfree, bavail, files, ffree
        out.u32(4096).u32(255).u32(4096).u32(0); // bsize, namelen, frsize, padding
        out.0.resize(80, 0);
        Self::ok(h, &out.0)
    }

    fn access(&self, h: &InHeader, body: &[u8]) -> Option<Vec<u8>> {
        const W_OK: u32 = 2;
        const X_OK: u32 = 1;
        let mask = u32_at(body, 0).unwrap_or(0);
        if mask & W_OK != 0 {
            return Self::err(h, EROFS);
        }
        if h.uid == 0 {
            return Self::ok(h, &[]);
        }
        match self
            .db
            .node(h.nodeid)
            .and_then(|n| self.node_attr(h.nodeid, &n))
        {
            Ok(a) if mask & X_OK != 0 && a.mode & 0o111 == 0 => Self::err(h, EACCES),
            Ok(_) => Self::ok(h, &[]),
            Err(e) => Self::err(h, Self::errno(&e)),
        }
    }
}

fn p_ino(p: &crate::package::Package, local: u32) -> u64 {
    p.start_ino() + u64::from(local)
}

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// Inode of the database root, re-exported for callers building on [`Server`].
pub const ROOT_INO: u64 = db::ROOT_INO;
