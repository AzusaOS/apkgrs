//! Build the boot files for the QEMU integration test (`tests/vm/run.sh`).
//!
//! ```text
//! cargo run --release --example vm_image -- <cache dir> <out dir> <apkg binary> <tests/vm dir>
//! ```
//!
//! Everything comes from the AzusaOS repository through this crate: the
//! kernel (`sys-kernel.linux.core`), the virtio-net modules
//! (`sys-kernel.linux.modules`) and a static busybox. The output directory
//! receives `bzImage` and `initramfs.cpio`, an uncompressed newc archive
//! with busybox, the modules, the apkg binary as `/sbin/apkg`, the test
//! scripts, and `/test/expected.sha256`: hashes of files read through the
//! library, to be compared with the same files read through the mount.

use std::collections::BTreeMap;
use std::path::Path;

use apkg::{Db, FileKind, Package};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Packages whose files are hashed for the read-back check, with an upper
/// bound on the bytes hashed per package (largest files are skipped first).
const CHECKED: &[(&str, u64)] = &[
    ("sys-libs.zlib.libs", u64::MAX),
    ("sys-apps.busybox.core", u64::MAX),
    ("dev-lang.python.core", 96 << 20),
];

/// Modules loaded at boot (with their dependencies).
const MODULES: &[&str] = &["virtio_net.ko"];

struct Cpio {
    out: Vec<u8>,
    ino: u32,
}

impl Cpio {
    fn new() -> Cpio {
        Cpio {
            out: Vec::new(),
            ino: 1,
        }
    }

    fn entry(&mut self, name: &str, mode: u32, rdev: (u32, u32), data: &[u8]) {
        let name = name.trim_start_matches('/');
        let fields = [
            self.ino,
            mode,
            0,
            0,
            if mode & 0o170000 == 0o040000 { 2 } else { 1 },
            0,
            data.len() as u32,
            0,
            0,
            rdev.0,
            rdev.1,
            name.len() as u32 + 1,
            0,
        ];
        self.ino += 1;
        self.out.extend_from_slice(b"070701");
        for f in fields {
            self.out.extend_from_slice(format!("{f:08x}").as_bytes());
        }
        self.out.extend_from_slice(name.as_bytes());
        self.out.push(0);
        self.pad();
        self.out.extend_from_slice(data);
        self.pad();
    }

    fn pad(&mut self) {
        while !self.out.len().is_multiple_of(4) {
            self.out.push(0);
        }
    }

    fn dir(&mut self, name: &str) {
        self.entry(name, 0o040755, (0, 0), &[]);
    }
    fn file(&mut self, name: &str, perm: u32, data: &[u8]) {
        self.entry(name, 0o100000 | perm, (0, 0), data);
    }
    fn symlink(&mut self, name: &str, target: &str) {
        self.entry(name, 0o120777, (0, 0), target.as_bytes());
    }
    fn chardev(&mut self, name: &str, major: u32, minor: u32) {
        self.entry(name, 0o020600, (major, minor), &[]);
    }

    fn finish(mut self) -> Vec<u8> {
        self.entry("TRAILER!!!", 0, (0, 0), &[]);
        self.out
    }
}

/// Copy the tree under `src` of `pkg` into the archive at `dst`.
fn copy_tree(cpio: &mut Cpio, pkg: &Package, src: &str, dst: &str) -> Res<()> {
    for e in pkg.read_dir(src)? {
        let s = format!("{}/{}", src.trim_end_matches('/'), e.name);
        let d = format!("{dst}/{}", e.name);
        let a = pkg.stat(&s)?;
        match e.kind {
            FileKind::Dir => {
                cpio.dir(&d);
                copy_tree(cpio, pkg, &s, &d)?;
            }
            FileKind::Symlink => cpio.symlink(&d, &pkg.read_link(&s)?),
            FileKind::File => cpio.file(&d, u32::from(a.perm), &pkg.read_file(&s)?),
            _ => {}
        }
    }
    Ok(())
}

/// Regular files of `pkg` with their size.
fn files(pkg: &Package, dir: &str, out: &mut Vec<(String, u64)>) -> Res<()> {
    for e in pkg.read_dir(dir)? {
        let p = format!("{}/{}", dir.trim_end_matches('/'), e.name);
        match e.kind {
            FileKind::Dir => files(pkg, &p, out)?,
            FileKind::File => out.push((p.clone(), pkg.stat(&p)?.size)),
            _ => {}
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `name.<version>.linux.amd64` → `<version>`.
fn version_of<'a>(full: &'a str, prefix: &str) -> &'a str {
    let rest = full.strip_prefix(prefix).unwrap_or(full);
    let rest = rest.trim_start_matches('.');
    rest.rsplitn(3, '.').last().unwrap_or(rest)
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <cache dir> <out dir> <apkg binary> <tests/vm dir>",
            args[0]
        );
        std::process::exit(2);
    }
    let (cache, out, apkg_bin, vmdir) = (
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
        Path::new(&args[4]),
    );
    std::fs::create_dir_all(out)?;
    let db = Db::open(apkg::Config::new("main", cache))?;
    let mut cpio = Cpio::new();
    for d in [
        "/bin",
        "/sbin",
        "/dev",
        "/proc",
        "/sys",
        "/tmp",
        "/etc",
        "/root",
        "/home",
        "/var",
        "/var/lib",
        "/lib",
        "/lib/modules",
        "/test",
        "/pkg",
        "/usr",
        "/usr/bin",
    ] {
        cpio.dir(d);
    }
    cpio.chardev("/dev/console", 5, 1);
    cpio.chardev("/dev/null", 1, 3);

    // kernel and modules of the same version
    let kpkg = db.find("sys-kernel.linux.core")?;
    let kver = version_of(kpkg.name(), "sys-kernel.linux.core");
    let img = kpkg
        .read_dir("/")?
        .into_iter()
        .find(|e| e.name.ends_with(".img"))
        .ok_or("no kernel image in package")?;
    std::fs::write(
        out.join("bzImage"),
        kpkg.read_file(&format!("/{}", img.name))?,
    )?;
    let mpkg = db.find(&format!("sys-kernel.linux.modules.{kver}"))?;
    let mdir = mpkg
        .read_dir("/lib/modules")?
        .into_iter()
        .next()
        .ok_or("no modules directory")?
        .name;
    let mbase = format!("/lib/modules/{mdir}");
    let dep = String::from_utf8(mpkg.read_file(&format!("{mbase}/modules.dep"))?)?;
    let deps: BTreeMap<&str, Vec<&str>> = dep
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(m, d)| (m, d.split_whitespace().collect()))
        .collect();
    let mut order: Vec<&str> = Vec::new();
    fn add<'a>(m: &'a str, deps: &BTreeMap<&'a str, Vec<&'a str>>, order: &mut Vec<&'a str>) {
        if order.contains(&m) {
            return;
        }
        for d in deps.get(m).into_iter().flatten() {
            add(d, deps, order);
        }
        order.push(m);
    }
    for want in MODULES {
        let m = deps
            .keys()
            .find(|k| k.rsplit('/').next() == Some(want))
            .ok_or_else(|| format!("module {want} not found"))?;
        add(m, &deps, &mut order);
    }
    let mut load = String::new();
    for m in &order {
        let base = m.rsplit('/').next().unwrap();
        cpio.file(
            &format!("/lib/modules/{base}"),
            0o644,
            &mpkg.read_file(&format!("{mbase}/{m}"))?,
        );
        load.push_str(base);
        load.push('\n');
    }
    cpio.file("/lib/modules/load", 0o644, load.as_bytes());

    // busybox
    let bb = db.find("sys-apps.busybox.core")?;
    copy_tree(&mut cpio, &bb, "/bin", "/bin")?;
    copy_tree(&mut cpio, &bb, "/sbin", "/sbin")?;

    // apkg and the test scripts
    cpio.file("/sbin/apkg", 0o755, &std::fs::read(apkg_bin)?);
    cpio.file("/init", 0o755, &std::fs::read(vmdir.join("init.sh"))?);
    cpio.file(
        "/test/tests.sh",
        0o755,
        &std::fs::read(vmdir.join("tests.sh"))?,
    );

    // expected contents, and facts the tests need
    let mut sums = String::new();
    let mut env = String::new();
    for (i, (name, budget)) in CHECKED.iter().enumerate() {
        let p = db.find(name)?;
        let mut list = Vec::new();
        files(&p, "/", &mut list)?;
        list.sort_by_key(|(_, s)| *s);
        let mut used = 0u64;
        for (f, size) in list {
            if used + size > *budget {
                break;
            }
            used += size;
            let h = apkg::sig::sha256(&p.read_file(&f)?);
            sums.push_str(&format!("{}  /pkg/main/{}{f}\n", hex(&h), p.name()));
        }
        env.push_str(&format!(
            "PKG{i}={}\nPKG{i}_SHORT={name}\nPKG{i}_CACHE={}\n",
            p.name(),
            p.repo_path()
        ));
    }
    cpio.file("/test/expected.sha256", 0o644, sums.as_bytes());
    let fuse = db.find("sys-fs.fuse.core")?;
    env.push_str(&format!(
        "FUSE_PKG={}\nKERNEL={}\n",
        fuse.name(),
        kpkg.name()
    ));
    cpio.file("/test/env", 0o644, env.as_bytes());

    std::fs::write(out.join("initramfs.cpio"), cpio.finish())?;
    eprintln!(
        "vm image: kernel {}, {} modules, {} checked files",
        kpkg.name(),
        order.len(),
        sums.lines().count()
    );
    Ok(())
}
