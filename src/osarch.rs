//! Operating system / architecture identifiers, using Go naming
//! (`linux`, `amd64`, `386`, ...) as the package repository does.

use std::fmt;

/// Operating system of a package database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Os {
    Any,
    Linux,
    Darwin,
    Windows,
}

/// CPU architecture of a package database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Arch {
    Any,
    X86,
    Amd64,
    Arm,
    Arm64,
    RiscV64,
}

impl Os {
    pub fn parse(s: &str) -> Option<Os> {
        Some(match s {
            "any" => Os::Any,
            "linux" => Os::Linux,
            "darwin" => Os::Darwin,
            "windows" => Os::Windows,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Os::Any => "any",
            Os::Linux => "linux",
            Os::Darwin => "darwin",
            Os::Windows => "windows",
        }
    }

    /// Numeric id used in database headers.
    pub fn id(self) -> u32 {
        self as u32
    }

    /// The OS this binary runs on (`fullrust` is Linux).
    pub fn current() -> Os {
        match std::env::consts::OS {
            "macos" => Os::Darwin,
            "windows" => Os::Windows,
            _ => Os::Linux,
        }
    }
}

impl Arch {
    pub fn parse(s: &str) -> Option<Arch> {
        Some(match s {
            "any" => Arch::Any,
            "386" => Arch::X86,
            "amd64" => Arch::Amd64,
            "arm" => Arch::Arm,
            "arm64" => Arch::Arm64,
            "riscv64" => Arch::RiscV64,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arch::Any => "any",
            Arch::X86 => "386",
            Arch::Amd64 => "amd64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::RiscV64 => "riscv64",
        }
    }

    pub fn id(self) -> u32 {
        self as u32
    }

    /// The architecture this binary was built for.
    pub fn current() -> Arch {
        match std::env::consts::ARCH {
            "x86" => Arch::X86,
            "arm" => Arch::Arm,
            "aarch64" => Arch::Arm64,
            "riscv64" => Arch::RiscV64,
            _ => Arch::Amd64,
        }
    }
}

/// An OS + architecture pair, written `linux.amd64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArchOs {
    pub os: Os,
    pub arch: Arch,
}

impl ArchOs {
    pub fn new(os: Os, arch: Arch) -> Self {
        Self { os, arch }
    }

    /// Parse `os.arch`, e.g. `linux.amd64`.
    pub fn parse(s: &str) -> Option<ArchOs> {
        let (o, a) = s.split_once('.')?;
        Some(ArchOs {
            os: Os::parse(o)?,
            arch: Arch::parse(a)?,
        })
    }

    /// Host platform, overridable through `APKG_OS`/`APKG_ARCH` (or the Go
    /// era `GOOS`/`GOARCH`) environment variables.
    pub fn host() -> ArchOs {
        let env = |a: &str, b: &str| std::env::var(a).or_else(|_| std::env::var(b)).ok();
        let os = env("APKG_OS", "GOOS")
            .and_then(|v| Os::parse(&v))
            .unwrap_or_else(Os::current);
        let arch = env("APKG_ARCH", "GOARCH")
            .and_then(|v| Arch::parse(&v))
            .unwrap_or_else(Arch::current);
        ArchOs { os, arch }
    }

    /// Split a trailing `.os.arch` suffix from a package name, returning the
    /// bare name and the parsed pair.
    pub fn split_suffix(name: &str) -> Option<(&str, ArchOs)> {
        let (rest, arch) = name.rsplit_once('.')?;
        let arch = Arch::parse(arch)?;
        let (bare, os) = rest.rsplit_once('.')?;
        let os = Os::parse(os)?;
        Some((bare, ArchOs { os, arch }))
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for ArchOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.os, self.arch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_suffix() {
        assert_eq!(
            ArchOs::parse("linux.amd64"),
            Some(ArchOs::new(Os::Linux, Arch::Amd64))
        );
        assert_eq!(ArchOs::parse("linux"), None);
        let (bare, ao) =
            ArchOs::split_suffix("azusa.symlinks.core.0.0.3.20210216.linux.amd64").unwrap();
        assert_eq!(bare, "azusa.symlinks.core.0.0.3.20210216");
        assert_eq!(ao.to_string(), "linux.amd64");
        assert!(ArchOs::split_suffix("sys-libs.zlib").is_none());
    }
}
