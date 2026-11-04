//! FUSE kernel protocol (`<linux/fuse.h>`) constants and encoders.
//! Everything is native-endian, little-endian on every target we build.

pub const KERNEL_VERSION: u32 = 7;
/// Highest minor version we speak.
pub const KERNEL_MINOR_VERSION: u32 = 31;

pub const IN_HEADER_LEN: usize = 40;
pub const OUT_HEADER_LEN: usize = 16;

// opcodes
pub const LOOKUP: u32 = 1;
pub const FORGET: u32 = 2;
pub const GETATTR: u32 = 3;
pub const SETATTR: u32 = 4;
pub const READLINK: u32 = 5;
pub const SYMLINK: u32 = 6;
pub const MKNOD: u32 = 8;
pub const MKDIR: u32 = 9;
pub const UNLINK: u32 = 10;
pub const RMDIR: u32 = 11;
pub const RENAME: u32 = 12;
pub const LINK: u32 = 13;
pub const OPEN: u32 = 14;
pub const READ: u32 = 15;
pub const WRITE: u32 = 16;
pub const STATFS: u32 = 17;
pub const RELEASE: u32 = 18;
pub const FSYNC: u32 = 20;
pub const SETXATTR: u32 = 21;
pub const GETXATTR: u32 = 22;
pub const LISTXATTR: u32 = 23;
pub const REMOVEXATTR: u32 = 24;
pub const FLUSH: u32 = 25;
pub const INIT: u32 = 26;
pub const OPENDIR: u32 = 27;
pub const READDIR: u32 = 28;
pub const RELEASEDIR: u32 = 29;
pub const FSYNCDIR: u32 = 30;
pub const ACCESS: u32 = 34;
pub const CREATE: u32 = 35;
pub const INTERRUPT: u32 = 36;
pub const DESTROY: u32 = 38;
pub const BATCH_FORGET: u32 = 42;
pub const FALLOCATE: u32 = 43;
pub const READDIRPLUS: u32 = 44;
pub const RENAME2: u32 = 45;
pub const COPY_FILE_RANGE: u32 = 47;

// INIT flags
pub const ASYNC_READ: u32 = 1 << 0;
pub const BIG_WRITES: u32 = 1 << 5;
pub const DO_READDIRPLUS: u32 = 1 << 13;
pub const READDIRPLUS_AUTO: u32 = 1 << 14;
pub const PARALLEL_DIROPS: u32 = 1 << 18;
pub const MAX_PAGES: u32 = 1 << 22;
pub const CACHE_SYMLINKS: u32 = 1 << 23;

// open reply flags
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
pub const FOPEN_CACHE_DIR: u32 = 1 << 3;

// notifications
pub const NOTIFY_INVAL_INODE: i32 = 2;
pub const NOTIFY_STORE: i32 = 4;

/// Parsed request header.
#[derive(Debug, Clone, Copy)]
pub struct InHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

pub fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

impl InHeader {
    pub fn parse(b: &[u8]) -> Option<InHeader> {
        Some(InHeader {
            len: u32_at(b, 0)?,
            opcode: u32_at(b, 4)?,
            unique: u64_at(b, 8)?,
            nodeid: u64_at(b, 16)?,
            uid: u32_at(b, 24)?,
            gid: u32_at(b, 28)?,
            pid: u32_at(b, 32)?,
        })
    }
}

/// `struct fuse_attr` contents.
#[derive(Debug, Clone, Default)]
pub struct FileAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub mtime: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
}

/// Little builder for reply bodies.
#[derive(Default)]
pub struct Out(pub Vec<u8>);

impl Out {
    pub fn new() -> Out {
        Out(Vec::with_capacity(256))
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_ne_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_ne_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_ne_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    pub fn pad8(&mut self) -> &mut Self {
        while self.0.len() % 8 != 0 {
            self.0.push(0);
        }
        self
    }

    /// `struct fuse_attr` (88 bytes).
    pub fn attr(&mut self, a: &FileAttr) -> &mut Self {
        self.u64(a.ino).u64(a.size).u64(a.blocks);
        self.u64(a.mtime).u64(a.mtime).u64(a.mtime); // atime, mtime, ctime
        self.u32(0).u32(0).u32(0); // nsecs
        self.u32(a.mode)
            .u32(a.nlink)
            .u32(a.uid)
            .u32(a.gid)
            .u32(a.rdev)
            .u32(a.blksize);
        self.u32(0) // flags
    }

    /// `struct fuse_entry_out` (128 bytes).
    pub fn entry(
        &mut self,
        nodeid: u64,
        a: &FileAttr,
        entry_valid: u64,
        attr_valid: u64,
    ) -> &mut Self {
        self.u64(nodeid)
            .u64(0)
            .u64(entry_valid)
            .u64(attr_valid)
            .u32(0)
            .u32(0);
        self.attr(a)
    }

    /// `struct fuse_dirent` + name, padded.
    pub fn dirent(&mut self, ino: u64, off: u64, typ: u32, name: &[u8]) -> &mut Self {
        self.u64(ino)
            .u64(off)
            .u32(name.len() as u32)
            .u32(typ)
            .bytes(name)
            .pad8()
    }
}

/// Size of a `fuse_dirent` record for `namelen`.
pub fn dirent_size(namelen: usize) -> usize {
    (24 + namelen).div_ceil(8) * 8
}

/// Size of a `fuse_direntplus` record for `namelen`.
pub fn direntplus_size(namelen: usize) -> usize {
    128 + dirent_size(namelen)
}

/// Frame a reply.
pub fn reply(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(OUT_HEADER_LEN + body.len());
    v.extend_from_slice(&((OUT_HEADER_LEN + body.len()) as u32).to_ne_bytes());
    v.extend_from_slice(&error.to_ne_bytes());
    v.extend_from_slice(&unique.to_ne_bytes());
    v.extend_from_slice(body);
    v
}
