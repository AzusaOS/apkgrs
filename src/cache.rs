//! Local package cache maintenance.
//!
//! Package images are cached as sparse `.apkg` files under
//! `<path>/<db name>/`, mirroring the repository layout. Nothing is evicted
//! automatically; [`crate::Db::clean_cache`] removes files that were not
//! used for a while.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Outcome of [`crate::Db::clean_cache`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheCleanup {
    /// Package files removed.
    pub removed: usize,
    /// Disk space released, in bytes (allocated blocks, not apparent size).
    pub freed: u64,
    /// Package files kept because they were used recently.
    pub kept: usize,
    /// Disk space still used by the kept files, in bytes.
    pub kept_bytes: u64,
}

/// Space allocated on disk for a (sparse) file.
pub(crate) fn disk_usage(m: &fs::Metadata) -> u64 {
    #[cfg(any(unix, target_os = "fullrust"))]
    {
        use std::os::unix::fs::MetadataExt;
        m.blocks() * 512
    }
    #[cfg(not(any(unix, target_os = "fullrust")))]
    {
        m.len()
    }
}

/// Every `.apkg` file below `dir`.
pub(crate) fn package_files(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for e in rd {
        let e = e?;
        let t = e.file_type()?;
        if t.is_dir() {
            package_files(&e.path(), out)?;
        } else if t.is_file() && e.file_name().to_string_lossy().ends_with(".apkg") {
            out.push(e.path());
        }
    }
    Ok(())
}

/// Remove `path` if it is a file not modified since `cutoff`. Returns the
/// space freed, or `None` if it was kept (with its size).
pub(crate) fn remove_if_older(path: &Path, cutoff: SystemTime) -> io::Result<Result<u64, u64>> {
    let m = fs::symlink_metadata(path)?;
    if m.modified()? >= cutoff {
        return Ok(Err(disk_usage(&m)));
    }
    fs::remove_file(path)?;
    Ok(Ok(disk_usage(&m)))
}

/// Remove empty directories below `dir` (not `dir` itself).
pub(crate) fn prune_empty_dirs(dir: &Path) -> io::Result<bool> {
    let mut empty = true;
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    for e in rd {
        let e = e?;
        if e.file_type()?.is_dir() {
            let p = e.path();
            if prune_empty_dirs(&p)? && fs::remove_dir(&p).is_ok() {
                continue;
            }
        }
        empty = false;
    }
    Ok(empty)
}
