//! Package databases.
//!
//! A [`Db`] is one named repository (e.g. `main`) for the host platform,
//! plus lazily created sub-databases for other platforms (reached with a
//! `.os.arch` name suffix). It keeps a local signed index in sync with the
//! repository, resolves package names, and hands out [`Package`]s.
//!
//! Inode numbers are allocated here for the FUSE layer: `1` is the database
//! root, `2` is the merged `ld.so.cache`, and each package that gets looked
//! up receives `inodes + 1` consecutive numbers starting at 1000 (the first
//! one being the "name → full name" symlink).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use crate::apdb;
use crate::error::{Error, Result};
use crate::http;
use crate::json::Value;
use crate::jwt;
use crate::ldcache;
use crate::osarch::ArchOs;
use crate::package::Package;
use crate::store::Store;
use crate::timefmt;

/// Default repository URL prefix.
pub const DEFAULT_PREFIX: &str = "https://data.apkg.net/";

/// Inode of the database root directory.
pub const ROOT_INO: u64 = 1;
/// Inode of the merged `ld.so.cache`.
pub const LDSO_INO: u64 = 2;
/// First inode handed to packages.
pub const FIRST_PKG_INO: u64 = 1000;

/// Database configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Repository URL prefix, ending in `/`.
    pub prefix: String,
    /// Database name (`main`).
    pub name: String,
    /// Local data directory (index files and package cache).
    pub path: PathBuf,
    /// Platform of the primary database.
    pub archos: ArchOs,
}

impl Config {
    /// Configuration for database `name` stored under `path`, for the host
    /// platform, using the default repository.
    pub fn new(name: &str, path: impl Into<PathBuf>) -> Config {
        Config { prefix: DEFAULT_PREFIX.to_string(), name: name.to_string(), path: path.into(), archos: ArchOs::host() }
    }
}

/// Callback receiving `(inode, offset, data)` when a virtual file changes
/// (used to push the new `ld.so.cache` into the kernel page cache).
pub type NotifyFn = Box<dyn Fn(u64, u64, &[u8]) + Send + Sync>;

/// Result of resolving a name in the database root.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// The merged `ld.so.cache` file.
    LdsoCache,
    /// A package's root directory (exact full name match).
    PackageRoot(Arc<Package>),
    /// A symlink from a partial name to the latest matching package.
    PackageLink(Arc<Package>),
}

/// Something that owns an inode number.
#[derive(Debug, Clone)]
pub enum Node {
    Root,
    LdsoCache,
    /// Package symlink (`name → full name`).
    PackageLink(Arc<Package>),
    /// Node inside a package; the `u32` is the package-local inode number.
    PackageNode(Arc<Package>, u32),
}

struct Shared {
    cfg: Config,
    next_ino: Mutex<u64>,
    /// start inode → package
    by_ino: RwLock<BTreeMap<u64, Arc<Package>>>,
    /// package hash → package (instantiated packages, all platforms)
    packages: Mutex<HashMap<[u8; 32], Arc<Package>>>,
    subs: RwLock<HashMap<ArchOs, Arc<SubDb>>>,
    sub_create: Mutex<()>,
    notify: RwLock<Option<NotifyFn>>,
}

/// The database of one platform.
pub struct SubDb {
    archos: ArchOs,
    store: RwLock<Store>,
    ldso: RwLock<Arc<Vec<u8>>>,
    update_lock: Mutex<()>,
}

/// A package database, cheap to clone (shared handle).
#[derive(Clone)]
pub struct Db {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").field("cfg", &self.shared.cfg).finish()
    }
}

impl Db {
    /// Open the database, downloading the index first if there is no local
    /// copy yet.
    pub fn open(cfg: Config) -> Result<Db> {
        std::fs::create_dir_all(&cfg.path)?;
        let db = Db {
            shared: Arc::new(Shared {
                cfg,
                next_ino: Mutex::new(FIRST_PKG_INO),
                by_ino: RwLock::new(BTreeMap::new()),
                packages: Mutex::new(HashMap::new()),
                subs: RwLock::new(HashMap::new()),
                sub_create: Mutex::new(()),
                notify: RwLock::new(None),
            }),
        };
        let primary = db.shared.cfg.archos;
        db.sub(primary)?;
        Ok(db)
    }

    /// Configuration in use.
    pub fn config(&self) -> &Config {
        &self.shared.cfg
    }

    /// Database name.
    pub fn name(&self) -> &str {
        &self.shared.cfg.name
    }

    /// Platform of the primary database.
    pub fn archos(&self) -> ArchOs {
        self.shared.cfg.archos
    }

    /// Set the virtual-file change callback.
    pub fn set_notify(&self, f: NotifyFn) {
        *self.shared.notify.write().unwrap() = Some(f);
    }

    fn store_path(&self, ao: ArchOs) -> PathBuf {
        let c = &self.shared.cfg;
        c.path.join(format!("{}.{}.{}.apkgdb", c.name, ao.os, ao.arch))
    }

    /// Database for platform `ao`, created (and downloaded) on first use.
    pub fn sub(&self, ao: ArchOs) -> Result<Arc<SubDb>> {
        if let Some(s) = self.shared.subs.read().unwrap().get(&ao) {
            return Ok(s.clone());
        }
        let _g = self.shared.sub_create.lock().unwrap();
        if let Some(s) = self.shared.subs.read().unwrap().get(&ao) {
            return Ok(s.clone());
        }
        let sub = Arc::new(SubDb {
            archos: ao,
            store: RwLock::new(Store::load(self.store_path(ao))),
            ldso: RwLock::new(Arc::new(Vec::new())),
            update_lock: Mutex::new(()),
        });
        if sub.version().is_empty() {
            // nothing local yet: this must succeed
            self.update_sub(&sub)?;
        } else {
            self.build_ldso(&sub);
        }
        self.shared.subs.write().unwrap().insert(ao, sub.clone());
        Ok(sub)
    }

    /// The primary (host platform) database.
    pub fn primary(&self) -> Arc<SubDb> {
        self.sub(self.shared.cfg.archos).expect("primary database is created at open")
    }

    /// Platforms with an opened database.
    pub fn subs(&self) -> Vec<ArchOs> {
        let mut v: Vec<ArchOs> = self.shared.subs.read().unwrap().keys().copied().collect();
        v.sort();
        v
    }

    /// Version stamp of the primary database.
    pub fn version(&self) -> String {
        self.primary().version()
    }

    /// Check every opened database for updates. Returns true if anything
    /// changed.
    pub fn update(&self) -> Result<bool> {
        let subs: Vec<Arc<SubDb>> = self.shared.subs.read().unwrap().values().cloned().collect();
        let mut changed = false;
        let mut err = None;
        for s in subs {
            match self.update_sub(&s) {
                Ok(c) => changed |= c,
                Err(e) => {
                    crate::log!("apkgdb: update of {}/{} failed: {e}", self.name(), s.archos);
                    err = Some(e);
                }
            }
        }
        match err {
            Some(e) if !changed => Err(e),
            _ => Ok(changed),
        }
    }

    fn db_url(&self, ao: ArchOs, file: &str) -> String {
        let c = &self.shared.cfg;
        format!("{}db/{}/{}/{}/{}", c.prefix, c.name, ao.os, ao.arch, file)
    }

    fn update_sub(&self, sub: &SubDb) -> Result<bool> {
        let _g = sub.update_lock.lock().unwrap();
        let ao = sub.archos;
        let current = sub.version();

        let token = http::get_ok(&self.db_url(ao, "LATEST.jwt"))?;
        let token = String::from_utf8_lossy(&token).trim().to_string();
        if token == "NEW" {
            // repository exists but has no database yet
            return Ok(false);
        }
        let t = jwt::verify_db_token(&token)?;
        let version = t
            .payload
            .get("ver")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
            .ok_or_else(|| Error::Integrity("invalid version in signed jwt".into()))?
            .to_string();
        if version == current {
            return Ok(false);
        }

        let mut data = None;
        if !current.is_empty() {
            crate::log!("apkgdb: Downloading {} database delta to version {version} ...", self.name());
            match http::get(&self.db_url(ao, &format!("{current}-{version}.bin"))) {
                Ok((200, body)) => data = Some(body),
                Ok((status, _)) => {
                    crate::log!("apkgdb: Delta download failed with status {status}, will download full database")
                }
                Err(e) => crate::log!("apkgdb: Delta download failed ({e}), will download full database"),
            }
        }
        let data = match data {
            Some(d) => d,
            None => {
                crate::log!("apkgdb: Downloading {} database version {version} ...", self.name());
                http::get_ok(&self.db_url(ao, &format!("{version}.bin")))?
            }
        };

        let parsed = apdb::parse(&data)?;
        drop(data);
        if parsed.name != self.name() {
            return Err(Error::Integrity(format!(
                "invalid database, was expecting {} but downloaded database was for {}",
                self.name(),
                parsed.name
            )));
        }
        crate::log!(
            "apkgdb: reading database generated on {} ({} packages, signed by {})",
            timefmt::human(parsed.created),
            parsed.packages.len(),
            parsed.signer
        );
        let stamp = timefmt::stamp(parsed.created);
        let added = sub.store.write().unwrap().merge_and_save(&stamp, parsed.packages)?;
        crate::log!("apkgdb: {}/{} now at version {stamp} ({added} new packages)", self.name(), ao);
        self.build_ldso(sub);
        Ok(true)
    }

    fn build_ldso(&self, sub: &SubDb) {
        let data = {
            let store = sub.store.read().unwrap();
            // one entry per (soname, flags); entries are visited in target
            // path order and the last one wins
            let mut uniq: BTreeMap<(String, i32), ldcache::Entry> = BTreeMap::new();
            for e in store.ldso_entries() {
                uniq.insert((e.key.clone(), e.flags), e.clone());
            }
            let mut entries: Vec<ldcache::Entry> = uniq.into_values().collect();
            ldcache::sort(&mut entries);
            crate::log!("apkgdb: built ld.so.cache containing {} libs", entries.len());
            ldcache::build(&entries)
        };
        *sub.ldso.write().unwrap() = Arc::new(data.clone());
        if sub.archos == self.shared.cfg.archos {
            if let Some(n) = self.shared.notify.read().unwrap().as_ref() {
                n(LDSO_INO, 0, &data);
            }
        }
    }

    /// The merged `ld.so.cache` of the primary database.
    pub fn ldso_cache(&self) -> Arc<Vec<u8>> {
        self.primary().ldso.read().unwrap().clone()
    }

    /// All package names of the primary database, in natural order.
    pub fn list(&self) -> Vec<String> {
        self.primary().list()
    }

    // ---- name resolution ------------------------------------------------

    /// Resolve `name` as found in the database root (`/pkg/main/<name>`).
    pub fn lookup(&self, name: &str) -> Result<Lookup> {
        if name == "ld.so.cache" {
            return Ok(Lookup::LdsoCache);
        }
        if !name.contains('.') {
            return Err(Error::NotFound);
        }
        let primary = self.shared.cfg.archos;
        let (sub, bare) = match ArchOs::split_suffix(name) {
            Some((bare, ao)) if ao == primary => (self.primary(), Some(bare)),
            Some((bare, ao)) => (self.sub(ao)?, Some(bare)),
            None => (self.primary(), None),
        };
        match self.lookup_in(&sub, name) {
            Err(e) if e.is_not_found() && bare.is_some() => self.lookup_in(&sub, bare.unwrap()),
            r => r,
        }
    }

    fn lookup_in(&self, sub: &SubDb, name: &str) -> Result<Lookup> {
        if !name.contains('.') {
            return Err(Error::NotFound);
        }
        let store = sub.store.read().unwrap();
        if let Some(p) = store.get(name) {
            return Ok(Lookup::PackageRoot(self.instantiate(&store, p)?));
        }
        let p = store.latest_with_prefix(name).ok_or(Error::NotFound)?;
        Ok(Lookup::PackageLink(self.instantiate(&store, p)?))
    }

    /// Find a package by (partial) name and return it. Partial names resolve
    /// to the latest matching version.
    pub fn find(&self, name: &str) -> Result<Arc<Package>> {
        match self.lookup(name)? {
            Lookup::PackageRoot(p) | Lookup::PackageLink(p) => Ok(p),
            Lookup::LdsoCache => Err(Error::NotFound),
        }
    }

    fn instantiate(&self, store: &Store, p: &crate::store::StoredPackage) -> Result<Arc<Package>> {
        let mut pkgs = self.shared.packages.lock().unwrap();
        if let Some(pkg) = pkgs.get(&p.hash) {
            return Ok(pkg.clone());
        }
        let c = &self.shared.cfg;
        let meta = store.read_meta(p)?;
        let pkg = Arc::new(Package::new(
            p.name.clone(),
            p.hash,
            p.size,
            p.inodes,
            p.path.clone(),
            format!("{}dist/{}/{}", c.prefix, c.name, http::escape_path(&p.path)),
            local_path(&c.path, &c.name, &p.path),
            p.header.clone(),
            p.sig.clone(),
            meta,
        ));
        // allocate inodes: one for the symlink, then the image's inodes
        let start = {
            let mut next = self.shared.next_ino.lock().unwrap();
            let s = *next;
            *next += u64::from(p.inodes) + 1;
            s
        };
        pkg.set_start_ino(start);
        self.shared.by_ino.write().unwrap().insert(start, pkg.clone());
        pkgs.insert(p.hash, pkg.clone());
        crate::log!("apkgdb: spawned package {} (inode {start})", pkg.name());
        Ok(pkg)
    }

    /// Inode number for a lookup result.
    pub fn lookup_ino(l: &Lookup) -> u64 {
        match l {
            Lookup::LdsoCache => LDSO_INO,
            Lookup::PackageLink(p) => p.start_ino(),
            Lookup::PackageRoot(p) => p.start_ino() + 1,
        }
    }

    /// Who owns inode `ino`.
    pub fn node(&self, ino: u64) -> Result<Node> {
        match ino {
            ROOT_INO => return Ok(Node::Root),
            LDSO_INO => return Ok(Node::LdsoCache),
            _ => {}
        }
        let map = self.shared.by_ino.read().unwrap();
        let (&start, pkg) = map.range(..=ino).next_back().ok_or(Error::NotFound)?;
        let local = ino - start;
        if local == 0 {
            return Ok(Node::PackageLink(pkg.clone()));
        }
        if local > u64::from(pkg.inode_count()) {
            return Err(Error::NotFound);
        }
        Ok(Node::PackageNode(pkg.clone(), local as u32))
    }

    /// Total number of inodes handed out so far (for statfs).
    pub fn inodes_allocated(&self) -> u64 {
        *self.shared.next_ino.lock().unwrap()
    }
}

fn local_path(base: &Path, name: &str, rel: &str) -> PathBuf {
    let mut p = base.join(name);
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        p.push(part);
    }
    p
}

impl SubDb {
    /// Platform of this database.
    pub fn archos(&self) -> ArchOs {
        self.archos
    }

    /// Version stamp, empty if never downloaded.
    pub fn version(&self) -> String {
        self.store.read().unwrap().version.clone()
    }

    /// Number of packages.
    pub fn len(&self) -> usize {
        self.store.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All package names in natural order.
    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = self.store.read().unwrap().names().map(String::from).collect();
        crate::collate::natural_sort(&mut v);
        v
    }
}
