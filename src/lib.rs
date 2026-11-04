//! # apkg — AzusaOS packages
//!
//! Access the signed AzusaOS package repository from Rust: keep a local,
//! signature-verified index of a package database, resolve package names
//! (with version-aware "latest" matching), and read files from packages,
//! which are downloaded on demand block by block, each block checked
//! against the package's signed hash table.
//!
//! ```no_run
//! use apkg::{Config, Db};
//!
//! let db = Db::open(Config::new("main", "/tmp/apkg-cache"))?;
//! let zlib = db.find("sys-libs.zlib.libs")?;
//! println!("{} -> {}", zlib.name(), zlib.repo_path());
//! for e in zlib.read_dir("/")? {
//!     println!("  {} ({:?})", e.name, e.kind);
//! }
//! # Ok::<(), apkg::Error>(())
//! ```
//!
//! With the `fuse` feature, [`fuse`] serves a database as a FUSE filesystem
//! (the `/pkg/main` tree of AzusaOS); the `bin` feature builds the `apkg`
//! daemon. Everything is pure Rust with no C dependency, and builds for the
//! libc-free `x86_64-unknown-linux-fullrust` target.

pub mod apdb;
pub mod base64;
pub mod collate;
pub mod db;
mod error;
pub mod http;
pub mod json;
pub mod jwt;
pub mod ldcache;
pub mod osarch;
pub mod package;
pub mod pkgfile;
pub mod remote;
pub mod sig;
pub mod store;
pub mod timefmt;

#[cfg(feature = "fuse")]
pub mod fuse;
#[cfg(any(feature = "fuse", feature = "tools"))]
pub mod sys;

#[cfg(feature = "tools")]
pub mod convert;
#[cfg(feature = "tools")]
pub mod index;
#[cfg(feature = "tools")]
pub mod sign;

pub use db::{Config, Db, Lookup, Node};
pub use error::{Error, Result};
pub use osarch::{Arch, ArchOs, Os};
pub use package::{Attr, DirEntry, FileKind, Package};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Silence (or re-enable) the crate's log output on stderr.
pub fn set_quiet(q: bool) {
    QUIET.store(q, std::sync::atomic::Ordering::Relaxed);
}

#[doc(hidden)]
pub fn log_line(args: std::fmt::Arguments<'_>) {
    if QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    use std::io::Write;
    let t = timefmt::now();
    let stamp = timefmt::stamp(t);
    let line = format!(
        "{}/{}/{} {}:{}:{} {}\n",
        &stamp[0..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[8..10],
        &stamp[10..12],
        &stamp[12..14],
        args
    );
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// Log a line to stderr, Go `log.Printf` style.
#[macro_export]
macro_rules! log {
    ($($t:tt)*) => { $crate::log_line(format_args!($($t)*)) };
}
