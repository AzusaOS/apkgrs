//! Error type shared by every module of the crate.

use std::fmt;
use std::io;

/// Errors returned by apkg.
#[derive(Debug)]
pub enum Error {
    /// Local I/O failure.
    Io(io::Error),
    /// The requested package, file or database does not exist.
    NotFound,
    /// The operation is not valid for this object (e.g. reading a directory).
    Invalid(String),
    /// A signature, hash or format check failed. Data is never served when
    /// this is returned.
    Integrity(String),
    /// A malformed file or response was received.
    Format(String),
    /// A network/HTTP failure.
    Http(String),
    /// Error from the squashfs layer.
    Squashfs(String),
    /// The operation is not supported on this platform/build.
    Unsupported(String),
}

/// Shorthand result type.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::NotFound => f.write_str("not found"),
            Error::Invalid(s) => write!(f, "invalid: {s}"),
            Error::Integrity(s) => write!(f, "integrity check failed: {s}"),
            Error::Format(s) => write!(f, "bad format: {s}"),
            Error::Http(s) => write!(f, "http: {s}"),
            Error::Squashfs(s) => write!(f, "squashfs: {s}"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            // keep the io error: callers matching NotFound should use `is_not_found`
            return Error::Io(e);
        }
        Error::Io(e)
    }
}

impl From<fstool::Error> for Error {
    fn from(e: fstool::Error) -> Self {
        match e {
            fstool::Error::Io(e) => Error::Io(e),
            other => Error::Squashfs(other.to_string()),
        }
    }
}

impl From<rsurl::Error> for Error {
    fn from(e: rsurl::Error) -> Self {
        Error::Http(e.to_string())
    }
}

impl Error {
    /// True when the error means "does not exist".
    pub fn is_not_found(&self) -> bool {
        match self {
            Error::NotFound => true,
            Error::Io(e) => e.kind() == io::ErrorKind::NotFound,
            _ => false,
        }
    }

    /// Best-effort mapping to a Linux errno value (positive).
    pub fn errno(&self) -> i32 {
        const ENOENT: i32 = 2;
        const EIO: i32 = 5;
        const EINVAL: i32 = 22;
        const ENOSYS: i32 = 38;
        match self {
            Error::NotFound => ENOENT,
            Error::Io(e) => e.raw_os_error().unwrap_or(if e.kind() == io::ErrorKind::NotFound {
                ENOENT
            } else {
                EIO
            }),
            Error::Invalid(_) => EINVAL,
            Error::Unsupported(_) => ENOSYS,
            _ => EIO,
        }
    }
}
