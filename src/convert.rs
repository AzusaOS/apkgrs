//! Turn a squashfs image into a signed `.apkg` package (`apkg-convert`).
//!
//! The image file name carries the package identity:
//! `category.name.subcat.version….os.arch.squashfs`. The output is
//! `<out>/<category>/<name>/<subcat>/<full name>-<hash7>.apkg`, where
//! `hash7` is the start of the hex sha256 of the package header.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::squashfs::Squashfs;

use crate::base64;
use crate::error::{Error, Result};
use crate::json::write_str;
use crate::package::FileKind;
use crate::pkgfile::HEADER_LEN;
use crate::sig::{self, SIGNATURE_SIZE};
use crate::sign::{self, Signer};

/// Metadata larger than this is refused.
pub const MAX_META: usize = 1024 * 1024;

/// Parts of a package file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageName {
    pub category: String,
    pub name: String,
    pub subcat: String,
    pub version: Vec<String>,
    pub os: String,
    pub arch: String,
}

impl PackageName {
    /// Parse `cat.name.subcat.version….os.arch` (at least five parts).
    pub fn parse(full: &str) -> Result<PackageName> {
        let p: Vec<&str> = full.split('.').collect();
        if p.len() < 5 {
            return Err(Error::Invalid(format!(
                "invalid filename format {full:?}: expected at least cat.name.subcat.version.os.arch"
            )));
        }
        let n = p.len();
        Ok(PackageName {
            category: p[0].into(),
            name: p[1].into(),
            subcat: p[2].into(),
            version: p[3..n - 2].iter().map(|s| s.to_string()).collect(),
            os: p[n - 2].into(),
            arch: p[n - 1].into(),
        })
    }

    /// `cat.name.subcat`
    pub fn base(&self) -> String {
        format!("{}.{}.{}", self.category, self.name, self.subcat)
    }

    /// Every name the package answers to: the base name, then the base name
    /// with each successive version component appended.
    pub fn names(&self) -> Vec<String> {
        let mut cur = self.base();
        let mut v = vec![cur.clone()];
        for part in &self.version {
            cur = format!("{cur}.{part}");
            v.push(cur.clone());
        }
        v
    }
}

/// Go's `fs.FileMode` encoding of a mode (type bits are Go's own).
fn go_file_mode(kind: FileKind, perm: u16) -> u32 {
    let mut m = u32::from(perm & 0o777);
    if perm & 0o4000 != 0 {
        m |= 1 << 23;
    }
    if perm & 0o2000 != 0 {
        m |= 1 << 22;
    }
    if perm & 0o1000 != 0 {
        m |= 1 << 20;
    }
    m | match kind {
        FileKind::Dir => 1 << 31,
        FileKind::Symlink => 1 << 27,
        FileKind::BlockDevice => 1 << 26,
        FileKind::CharDevice => (1 << 26) | (1 << 21),
        FileKind::Fifo => 1 << 25,
        FileKind::Socket => 1 << 24,
        FileKind::File => 0,
    }
}

fn kind_of(k: fstool::fs::EntryKind) -> FileKind {
    use fstool::fs::EntryKind as E;
    match k {
        E::Dir => FileKind::Dir,
        E::Symlink => FileKind::Symlink,
        E::Char => FileKind::CharDevice,
        E::Block => FileKind::BlockDevice,
        E::Fifo => FileKind::Fifo,
        E::Socket => FileKind::Socket,
        _ => FileKind::File,
    }
}

/// Match one path segment against a glob segment (`*` and `?`).
fn seg_match(pat: &[u8], s: &[u8]) -> bool {
    match pat.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| seg_match(rest, &s[i..])),
        Some((b'?', rest)) => !s.is_empty() && seg_match(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && seg_match(rest, &s[1..]),
    }
}

/// Read access to the image being converted.
struct Image {
    sq: Squashfs,
    dev: FileBackend,
}

impl Image {
    fn list(&mut self, dir: &str) -> Vec<(String, FileKind)> {
        self.sq
            .list_path(&mut self.dev, dir)
            .map(|l| l.into_iter().map(|e| (e.name, kind_of(e.kind))).collect())
            .unwrap_or_default()
    }

    /// `fs.Glob` over the image (relative patterns, no escapes).
    fn glob(&mut self, pattern: &str) -> Vec<String> {
        let mut cur = vec![String::new()];
        let segs: Vec<&str> = pattern.split('/').collect();
        for (i, seg) in segs.iter().enumerate() {
            let last = i == segs.len() - 1;
            let mut next = Vec::new();
            for base in &cur {
                let dir = if base.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{base}")
                };
                let mut entries = self.list(&dir);
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                for (name, kind) in entries {
                    if !seg_match(seg.as_bytes(), name.as_bytes())
                        || (!last && kind != FileKind::Dir)
                    {
                        continue;
                    }
                    next.push(if base.is_empty() {
                        name
                    } else {
                        format!("{base}/{name}")
                    });
                }
            }
            cur = next;
        }
        cur
    }

    fn read_file(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let mut r = match self.sq.open_file_reader(&mut self.dev, path) {
            Ok(r) => r,
            Err(fstool::Error::InvalidArgument(m)) if m.contains("no such entry") => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        let mut v = Vec::new();
        r.read_to_end(&mut v)?;
        Ok(Some(v))
    }
}

/// Outcome of a conversion.
#[derive(Debug)]
pub struct Converted {
    pub path: PathBuf,
    pub full_name: String,
    pub header_hash: [u8; 32],
}

/// Convert `input` (a squashfs image) into a signed package under `out_dir`.
pub fn convert(signer: &dyn Signer, input: &Path, out_dir: &Path) -> Result<Converted> {
    let file_name = input
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| Error::Invalid("bad file name".into()))?;
    let full = file_name
        .strip_suffix(".squashfs")
        .unwrap_or(file_name)
        .to_string();
    let pn = PackageName::parse(&full)?;
    crate::log!("preparing {} ...", input.display());

    let mut dev = FileBackend::open_read_only(input)?;
    let file_size = dev.total_size();
    let sq = Squashfs::open(&mut dev)?;
    let inodes = sq.superblock().inode_count;
    let created = i64::from(sq.superblock().mkfs_time);
    let mut img = Image { sq, dev };

    // hash table: one sha256 per block, ~1500 blocks, 4 KiB..128 KiB
    let mut block_size: u64 = 4096;
    while file_size / block_size > 1500 && block_size < 131072 {
        block_size <<= 1;
    }
    let mut table = Vec::new();
    let mut blocks = 0u64;
    {
        let mut f = File::open(input)?;
        let mut buf = vec![0u8; block_size as usize];
        loop {
            let mut n = 0;
            while n < buf.len() {
                match f.read(&mut buf[n..])? {
                    0 => break,
                    k => n += k,
                }
            }
            if n == 0 {
                break;
            }
            table.extend_from_slice(&sig::sha256(&buf[..n]));
            blocks += 1;
            if n < buf.len() {
                break;
            }
        }
    }
    let table_hash = sig::sha256(&table);
    let table_hex: String = table_hash.iter().map(|b| format!("{b:02x}")).collect();
    crate::log!("table len = {} bytes ({blocks} blocks)", table.len());

    // .virtual/<module>/<link> → ../../<target>
    let mut virtual_: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (pkg, kind) in img.list("/.virtual") {
        if kind != FileKind::Dir {
            continue;
        }
        let mut sub = BTreeMap::new();
        for (sym, _) in img.list(&format!("/.virtual/{pkg}")) {
            if let Ok(t) = img
                .sq
                .read_symlink(&mut img.dev, &format!("/.virtual/{pkg}/{sym}"))
                && let Some(t) = t.strip_prefix("../../")
            {
                crate::log!("provides virtual: {pkg} {sym} → {t}");
                sub.insert(sym, t.to_string());
            }
        }
        if !sub.is_empty() {
            virtual_.insert(pkg, sub);
        }
    }

    let mut ldso = None;
    let globs: Vec<&str> = match pn.subcat.as_str() {
        "core" => vec!["bin/*", "sbin/*", "udev/*"],
        "libs" => {
            ldso = img.read_file("/.ld.so.cache")?;
            if pn.arch == "amd64" {
                vec!["lib32/*", "lib64/*"]
            } else {
                vec!["lib/*"]
            }
        }
        "dev" => vec!["pkgconfig/*.pc", "cmake/*", "bin/*", "sbin/*"],
        "mod" => vec![
            "pkgconfig/*.pc",
            "cmake/*",
            "bin/*",
            "sbin/*",
            "lib/python*/site-packages/*",
        ],
        "doc" => vec!["man/man*/*", "man/*/man*/*", "info/*"],
        _ => vec![],
    };

    // provides: path → JSON object
    let mut provides: BTreeMap<String, String> = BTreeMap::new();
    for g in globs {
        for m in img.glob(g) {
            if provides.contains_key(&m) {
                continue;
            }
            let Ok(meta) = img.sq.inode_meta(&mut img.dev, &format!("/{m}")) else {
                continue;
            };
            let kind = kind_of(meta.kind);
            if kind == FileKind::Symlink {
                if let Ok(t) = img.sq.read_symlink(&mut img.dev, &format!("/{m}"))
                    && !t.contains('/')
                {
                    let mut o = String::from("{\"symlink\":");
                    write_str(&mut o, &t);
                    o.push('}');
                    provides.insert(m, o);
                }
            } else {
                let mode = go_file_mode(kind, meta.mode);
                let mut o = format!("{{\"mode\":{mode}");
                if meta.file_size > 0 {
                    o.push_str(&format!(",\"size\":{}", meta.file_size));
                }
                o.push('}');
                provides.insert(m, o);
            }
        }
    }

    // metadata JSON, keys in alphabetical order like published packages
    let mut j = String::from("{");
    let field = |j: &mut String, k: &str, v: &str| {
        if j.len() > 1 {
            j.push(',');
        }
        write_str(j, k);
        j.push(':');
        j.push_str(v);
    };
    let s = |v: &str| {
        let mut o = String::new();
        write_str(&mut o, v);
        o
    };
    field(&mut j, "arch", &s(&pn.arch));
    field(&mut j, "base_name", &s(&pn.name));
    field(&mut j, "block_size", &block_size.to_string());
    field(&mut j, "blocks", &blocks.to_string());
    field(&mut j, "category", &s(&pn.category));
    field(&mut j, "created", &format!("[{created},0]"));
    field(&mut j, "full_name", &s(&full));
    field(&mut j, "hash", &s(&table_hex));
    field(&mut j, "inodes", &inodes.to_string());
    if let Some(l) = &ldso {
        field(&mut j, "ld.so.cache", &s(&base64::encode_std(l)));
    }
    field(&mut j, "name", &s(&pn.base()));
    field(
        &mut j,
        "names",
        &format!(
            "[{}]",
            pn.names()
                .iter()
                .map(|n| s(n))
                .collect::<Vec<_>>()
                .join(",")
        ),
    );
    field(&mut j, "os", &s(&pn.os));
    let prov: Vec<String> = provides
        .iter()
        .map(|(k, v)| format!("{}:{v}", s(k)))
        .collect();
    field(&mut j, "provides", &format!("{{{}}}", prov.join(",")));
    field(&mut j, "size", &file_size.to_string());
    field(&mut j, "subcat", &s(&pn.subcat));
    field(&mut j, "version", &s(&pn.version.join(".")));
    if !virtual_.is_empty() {
        let v: Vec<String> = virtual_
            .iter()
            .map(|(k, m)| {
                let inner: Vec<String> = m
                    .iter()
                    .map(|(a, b)| format!("{}:{}", s(a), s(b)))
                    .collect();
                format!("{}:{{{}}}", s(k), inner.join(","))
            })
            .collect();
        field(&mut j, "virtual", &format!("{{{}}}", v.join(",")));
    }
    j.push('}');
    let meta = j.into_bytes();
    if meta.len() > MAX_META {
        return Err(Error::Invalid(
            "metadata too long, should be below 1MB".into(),
        ));
    }
    crate::log!(
        "provides {} files, metadata {} bytes",
        provides.len(),
        meta.len()
    );

    // layout: header | meta | table | signature (padded to 512) | squashfs
    let sign_offset = HEADER_LEN + meta.len() + table.len();
    let mut padding = 512 - (sign_offset % 512);
    if padding < SIGNATURE_SIZE {
        padding += 512;
    }
    let data_offset = sign_offset + padding;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(b"APKG");
    header.extend_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&0u64.to_be_bytes());
    header.extend_from_slice(&(created as u64).to_be_bytes());
    header.extend_from_slice(&0u64.to_be_bytes());
    header.extend_from_slice(&(HEADER_LEN as u32).to_be_bytes());
    header.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    header.extend_from_slice(&sig::sha256(&meta));
    header.extend_from_slice(&((HEADER_LEN + meta.len()) as u32).to_be_bytes());
    header.extend_from_slice(&(table.len() as u32).to_be_bytes());
    header.extend_from_slice(&table_hash);
    header.extend_from_slice(&(sign_offset as u32).to_be_bytes());
    header.extend_from_slice(&(data_offset as u32).to_be_bytes());
    header.extend_from_slice(&(block_size as u32).to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);

    let blob = sign::signature_blob(signer, &header)?;
    let mut sigbuf = vec![0u8; padding];
    sigbuf[..blob.len()].copy_from_slice(&blob);
    let header_hash = sig::sha256(&header);
    let hex: String = header_hash.iter().map(|b| format!("{b:02x}")).collect();

    let out = out_dir
        .join(&pn.category)
        .join(&pn.name)
        .join(&pn.subcat)
        .join(format!("{full}-{}.apkg", &hex[..7]));
    crate::log!("out filename = {}", out.display());
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = out.with_extension("apkg.tmp");
    {
        let mut o = std::io::BufWriter::new(File::create(&tmp)?);
        o.write_all(&header)?;
        o.write_all(&meta)?;
        o.write_all(&table)?;
        o.write_all(&sigbuf)?;
        std::io::copy(&mut File::open(input)?, &mut o)?;
        o.flush()?;
    }
    std::fs::rename(&tmp, &out)?;
    Ok(Converted {
        path: out,
        full_name: full,
        header_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names() {
        let p = PackageName::parse("core.foobar.libs.1.2.3.linux.amd64").unwrap();
        assert_eq!(
            (p.category.as_str(), p.name.as_str(), p.subcat.as_str()),
            ("core", "foobar", "libs")
        );
        assert_eq!(p.version, ["1", "2", "3"]);
        assert_eq!((p.os.as_str(), p.arch.as_str()), ("linux", "amd64"));
        assert_eq!(
            p.names(),
            [
                "core.foobar.libs",
                "core.foobar.libs.1",
                "core.foobar.libs.1.2",
                "core.foobar.libs.1.2.3"
            ]
        );
        let p = PackageName::parse("azusa.apkg.core.linux.amd64").unwrap();
        assert!(p.version.is_empty());
        for bad in ["a.b.c.d", "a.b.c", "noperiods"] {
            assert!(PackageName::parse(bad).is_err());
        }
    }

    #[test]
    fn globbing() {
        assert!(seg_match(b"*", b"anything"));
        assert!(seg_match(b"*.pc", b"zlib.pc"));
        assert!(!seg_match(b"*.pc", b"zlib.pcx"));
        assert!(seg_match(b"python*", b"python3.12"));
        assert!(seg_match(b"man?", b"man1"));
        assert!(!seg_match(b"man?", b"man"));
    }

    #[test]
    fn go_modes() {
        assert_eq!(go_file_mode(FileKind::File, 0o755), 0o755);
        assert_eq!(go_file_mode(FileKind::Dir, 0o755), (1 << 31) | 0o755);
        assert_eq!(go_file_mode(FileKind::File, 0o4755), (1 << 23) | 0o755);
    }
}
