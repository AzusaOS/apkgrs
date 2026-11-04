//! Local persistent index of a package database (replaces the Go
//! implementation's bolt database).
//!
//! File layout:
//!
//! ```text
//! "APKGRSDB" | u32 format (1) | varblob version
//! u32 record count | records (APDB record encoding)
//! u32 ldso count   | ldso entries (i32 flags, u32 os_version, u64 hwcap, varblob key, varblob value)
//! sha256 of everything above
//! ```
//!
//! The file is rewritten atomically (temp file + rename) on every update.
//! Metadata JSON is not kept in memory: records remember where it lives in
//! the file and [`Store::read_meta`] fetches it on demand.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::apdb::PackageRecord;
use crate::collate::collated_version;
use crate::error::{Error, Result};
use crate::json::Value;
use crate::ldcache;
use crate::sig::{self, Cursor};

const MAGIC: &[u8; 8] = b"APKGRSDB";
const FORMAT: u32 = 1;

/// In-memory view of a stored package (metadata stays on disk).
#[derive(Debug, Clone)]
pub struct StoredPackage {
    pub hash: [u8; 32],
    pub size: u64,
    pub inodes: u32,
    pub name: String,
    pub path: String,
    pub header: Vec<u8>,
    pub sig: Vec<u8>,
    meta_off: u64,
    meta_len: u32,
}

/// Loaded index of one database (one name/os/arch).
#[derive(Debug, Default)]
pub struct Store {
    file: PathBuf,
    /// Version stamp (`YYYYMMDDhhmmss`) of the last applied database; empty
    /// when nothing was ever downloaded.
    pub version: String,
    packages: Vec<StoredPackage>,
    /// collated name → index in `packages`
    by_name: BTreeMap<Vec<u8>, usize>,
    by_hash: HashMap<[u8; 32], usize>,
    /// target path → ld.so.cache entry
    ldso: BTreeMap<String, ldcache::Entry>,
}

fn rd_ldso(c: &mut Cursor<'_>) -> Result<ldcache::Entry> {
    let flags = c.u32_be()? as i32;
    let os_version = c.u32_be()?;
    let hwcap = c.u64_be()?;
    let key = String::from_utf8_lossy(c.varblob(4096)?).into_owned();
    let value = String::from_utf8_lossy(c.varblob(4096)?).into_owned();
    Ok(ldcache::Entry {
        flags,
        key,
        value,
        os_version,
        hwcap,
    })
}

impl Store {
    /// Empty store that will be saved to `file`.
    pub fn empty(file: PathBuf) -> Store {
        Store {
            file,
            ..Default::default()
        }
    }

    /// Load `file`, or return an empty store if it does not exist or is
    /// damaged (it will simply be downloaded again).
    pub fn load(file: PathBuf) -> Store {
        match Self::try_load(&file) {
            Ok(s) => s,
            Err(e) => {
                if !e.is_not_found() {
                    crate::log!("apkgdb: ignoring damaged index {}: {e}", file.display());
                }
                Store::empty(file)
            }
        }
    }

    fn try_load(file: &Path) -> Result<Store> {
        let data = fs::read(file)?;
        if data.len() < MAGIC.len() + 32 || &data[..8] != MAGIC {
            return Err(Error::Format("bad index magic".into()));
        }
        let (body, sum) = data.split_at(data.len() - 32);
        if sig::sha256(body) != sum {
            return Err(Error::Integrity("index checksum mismatch".into()));
        }
        let mut c = Cursor::new(&body[8..]);
        if c.u32_be()? != FORMAT {
            return Err(Error::Format("unsupported index format".into()));
        }
        let version = String::from_utf8_lossy(c.varblob(64)?).into_owned();
        let mut st = Store {
            file: file.to_path_buf(),
            version,
            ..Default::default()
        };
        let count = c.u32_be()?;
        for _ in 0..count {
            let r = PackageRecord::read(&mut c)?;
            // meta is the last field of the record: it ends at the cursor
            let meta_off = (8 + c.position() - r.meta.len()) as u64;
            st.insert(StoredPackage {
                hash: r.hash,
                size: r.size,
                inodes: r.inodes,
                name: r.name,
                path: r.path,
                header: r.header,
                sig: r.sig,
                meta_off,
                meta_len: r.meta.len() as u32,
            });
        }
        let n = c.u32_be()?;
        for _ in 0..n {
            let e = rd_ldso(&mut c)?;
            st.ldso.insert(e.value.clone(), e);
        }
        Ok(st)
    }

    fn insert(&mut self, p: StoredPackage) {
        let key = collated_version(&p.name);
        let idx = self.packages.len();
        self.by_hash.insert(p.hash, idx);
        self.by_name.insert(key, idx);
        self.packages.push(p);
    }

    /// Number of packages reachable by name.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Exact lookup by full name.
    pub fn get(&self, name: &str) -> Option<&StoredPackage> {
        self.by_name
            .get(&collated_version(name))
            .map(|&i| &self.packages[i])
    }

    /// Lookup by header hash.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&StoredPackage> {
        self.by_hash.get(hash).map(|&i| &self.packages[i])
    }

    /// Latest package whose name starts with `prefix + "."`, using version
    /// collation (so `foo.1.10` beats `foo.1.9`).
    pub fn latest_with_prefix(&self, prefix: &str) -> Option<&StoredPackage> {
        let mut bound = collated_version(prefix);
        bound.push(0xff);
        let (_, &i) = self.by_name.range(..bound).next_back()?;
        let p = &self.packages[i];
        let rest = p.name.strip_prefix(prefix)?;
        rest.starts_with('.').then_some(p)
    }

    /// All package names in collation order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name
            .values()
            .map(|&i| self.packages[i].name.as_str())
    }

    /// Read a package's raw JSON metadata from disk.
    pub fn read_meta(&self, p: &StoredPackage) -> Result<Vec<u8>> {
        let mut f = File::open(&self.file)?;
        let mut buf = vec![0u8; p.meta_len as usize];
        read_exact_at(&mut f, p.meta_off, &mut buf)?;
        Ok(buf)
    }

    /// ld.so.cache entries collected from every library package.
    pub fn ldso_entries(&self) -> impl Iterator<Item = &ldcache::Entry> {
        self.ldso.values()
    }

    /// Merge `records` into this store under `version`, then rewrite the
    /// file. Packages already known (same header hash) are skipped; a new
    /// package with an existing name replaces the old name mapping.
    /// Returns the number of new packages.
    pub fn merge_and_save(&mut self, version: &str, records: Vec<PackageRecord>) -> Result<usize> {
        // Load every existing metadata blob before the file is replaced.
        let mut f = File::open(&self.file).ok();
        let mut all: Vec<PackageRecord> = Vec::with_capacity(self.by_name.len() + records.len());
        for &i in self.by_name.values() {
            let p = &self.packages[i];
            let mut meta = vec![0u8; p.meta_len as usize];
            if let Some(f) = f.as_mut() {
                read_exact_at(f, p.meta_off, &mut meta)?;
            } else if p.meta_len > 0 {
                return Err(Error::Invalid("index file vanished".into()));
            }
            all.push(PackageRecord {
                hash: p.hash,
                size: p.size,
                inodes: p.inodes,
                name: p.name.clone(),
                path: p.path.clone(),
                header: p.header.clone(),
                sig: p.sig.clone(),
                meta,
            });
        }
        drop(f);

        let mut name_pos: HashMap<Vec<u8>, usize> = all
            .iter()
            .enumerate()
            .map(|(i, r)| (collated_version(&r.name), i))
            .collect();
        let mut ldso = self.ldso.clone();
        let mut known: std::collections::HashSet<[u8; 32]> = self.by_hash.keys().copied().collect();
        let mut added = 0;
        for r in records {
            if !known.insert(r.hash) {
                continue;
            }
            added += 1;
            if let Ok(meta) = Value::parse(&r.meta) {
                if let Some(raw) = meta.get("ld.so.cache").and_then(Value::as_str) {
                    match crate::base64::decode(raw.as_bytes())
                        .ok_or_else(|| Error::Format("bad base64".into()))
                        .and_then(|b| ldcache::parse(&b))
                    {
                        Ok(entries) => {
                            for e in entries {
                                ldso.insert(e.value.clone(), e);
                            }
                        }
                        Err(e) => {
                            crate::log!("apkgdb: {}: failed to parse ld.so.cache: {e}", r.name)
                        }
                    }
                }
            } else {
                crate::log!("apkgdb: {}: failed to parse metadata", r.name);
            }
            // a newer package of the same name replaces the old mapping
            let key = collated_version(&r.name);
            if let Some(&pos) = name_pos.get(&key) {
                all[pos] = r;
            } else {
                name_pos.insert(key, all.len());
                all.push(r);
            }
        }

        // serialize
        let mut out = Vec::with_capacity(1 << 20);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT.to_be_bytes());
        sig::put_varblob(&mut out, version.as_bytes());
        out.extend_from_slice(&(all.len() as u32).to_be_bytes());
        for r in &all {
            r.write(&mut out);
        }
        out.extend_from_slice(&(ldso.len() as u32).to_be_bytes());
        for e in ldso.values() {
            out.extend_from_slice(&(e.flags as u32).to_be_bytes());
            out.extend_from_slice(&e.os_version.to_be_bytes());
            out.extend_from_slice(&e.hwcap.to_be_bytes());
            sig::put_varblob(&mut out, e.key.as_bytes());
            sig::put_varblob(&mut out, e.value.as_bytes());
        }
        let sum = sig::sha256(&out);
        out.extend_from_slice(&sum);

        if let Some(dir) = self.file.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.file.with_extension("tmp");
        {
            let mut t = File::create(&tmp)?;
            t.write_all(&out)?;
            t.sync_all()?;
        }
        fs::rename(&tmp, &self.file)?;

        *self = Self::try_load(&self.file)?;
        Ok(added)
    }
}

/// Positional read that works on every target (seek + read).
pub(crate) fn read_exact_at(f: &mut File, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(off))?;
    f.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, h: u8) -> PackageRecord {
        PackageRecord {
            hash: [h; 32],
            size: 100,
            inodes: 3,
            name: name.into(),
            path: format!("x/{name}.apkg"),
            header: vec![1, 2, 3],
            sig: vec![4, 5],
            meta: format!("{{\"full_name\":\"{name}\"}}").into_bytes(),
        }
    }

    #[test]
    fn merge_load_lookup() {
        let dir = std::env::temp_dir().join(format!("apkg-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("main.linux.amd64.apkgdb");
        let mut s = Store::load(file.clone());
        assert!(s.is_empty());
        let n = s
            .merge_and_save(
                "20200101000000",
                vec![
                    rec("a.b.core.1.9.linux.amd64", 1),
                    rec("a.b.core.1.10.linux.amd64", 2),
                ],
            )
            .unwrap();
        assert_eq!(n, 2);
        // duplicate hash skipped
        assert_eq!(
            s.merge_and_save("20200102000000", vec![rec("a.b.core.1.9.linux.amd64", 1)])
                .unwrap(),
            0
        );
        let s = Store::load(file);
        assert_eq!(s.version, "20200102000000");
        assert_eq!(s.len(), 2);
        let p = s.latest_with_prefix("a.b.core").unwrap();
        assert_eq!(p.name, "a.b.core.1.10.linux.amd64");
        assert_eq!(
            s.latest_with_prefix("a.b.core.1").unwrap().name,
            "a.b.core.1.10.linux.amd64"
        );
        assert!(s.latest_with_prefix("a.b.cor").is_none());
        assert_eq!(
            s.read_meta(p).unwrap(),
            b"{\"full_name\":\"a.b.core.1.10.linux.amd64\"}"
        );
        assert!(s.get("a.b.core.1.9.linux.amd64").is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
