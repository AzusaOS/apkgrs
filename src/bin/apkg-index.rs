//! `apkg-index`: publish package databases.
//!
//! Walks the repository's `dist/<db>` tree, adds every `.apkg` found to the
//! currently published database of its platform (an empty `.apkg` file
//! removes that package), applies pin changes, then writes and uploads a
//! new signed database with its `LATEST.txt`/`LATEST.jwt`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use apkg::index::{Index, Trust, read_package};
use apkg::sign::{DB_KEY_LABEL, KeySource};
use apkg::{ArchOs, Config, Db, log, sig};

struct Opts {
    db: String,
    dir: Option<PathBuf>,
    out: Option<PathBuf>,
    prefix: String,
    upload: bool,
    s3: String,
    profile: String,
    trust: Trust,
    platforms: Vec<ArchOs>,
    pins: Vec<(String, String, Option<String>)>,
}

fn usage() -> ! {
    eprintln!(
        "usage: apkg-index [options]\n\
         \n\
         options:\n  \
           -db <name>             database name (default: main)\n  \
           -dir <dir>             package tree (default: ~/projects/apkg-tools/repo/apkg/dist/<db>)\n  \
           -out <dir>             keep the generated files here (default: temporary, removed)\n  \
           -prefix <url>          repository to start from (default: {})\n  \
           -platform <os.arch>    also export this platform even without package changes\n  \
           -pin <ch>:<prefix>=<v> set a release-channel pin (repeatable)\n  \
           -unpin <ch>:<prefix>   remove a pin (repeatable)\n  \
           -no_upload             only write the files, do not upload\n  \
           -s3 <url>              upload destination (default: s3://azusa/db)\n  \
           -aws_profile <name>    aws cli profile (default: cf)\n  \
           -allow_untrusted       accept keys clients do not trust (testing; implies -no_upload)\n\
         \n\
         Key ({DB_KEY_LABEL}): HSM=yubihsm2 or HSM=file:<ed25519 seed file>.",
        apkg::db::DEFAULT_PREFIX
    );
    std::process::exit(2)
}

fn parse_pin(s: &str, with_version: bool) -> (String, String, Option<String>) {
    let (target, version) = if with_version {
        let (t, v) = s.split_once('=').unwrap_or_else(|| usage());
        (t, Some(v.to_string()))
    } else {
        (s, None)
    };
    let (ch, prefix) = target.split_once(':').unwrap_or_else(|| usage());
    if ch.is_empty() || prefix.is_empty() {
        usage();
    }
    (ch.to_string(), prefix.to_string(), version)
}

fn parse_args() -> Opts {
    let mut o = Opts {
        db: "main".into(),
        dir: None,
        out: None,
        prefix: apkg::db::DEFAULT_PREFIX.into(),
        upload: true,
        s3: "s3://azusa/db".into(),
        profile: "cf".into(),
        trust: Trust::Required,
        platforms: Vec::new(),
        pins: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let Some(flag) = a.strip_prefix('-') else {
            usage()
        };
        let flag = flag.trim_start_matches('-');
        let mut val = || args.next().unwrap_or_else(|| usage());
        match flag {
            "db" => o.db = val(),
            "dir" => o.dir = Some(val().into()),
            "out" => o.out = Some(val().into()),
            "prefix" => {
                let p = val();
                o.prefix = if p.ends_with('/') { p } else { format!("{p}/") };
            }
            "platform" => o
                .platforms
                .push(ArchOs::parse(&val()).unwrap_or_else(|| usage())),
            "pin" => o.pins.push(parse_pin(&val(), true)),
            "unpin" => o.pins.push(parse_pin(&val(), false)),
            "no_upload" => o.upload = false,
            "s3" => o.s3 = val().trim_end_matches('/').to_string(),
            "aws_profile" => o.profile = val(),
            "allow_untrusted" => o.trust = Trust::AnyKey,
            _ => usage(),
        }
    }
    if o.trust == Trust::AnyKey {
        o.upload = false;
    }
    o
}

/// `<full name>-<7 hex>.apkg` → full name and platform.
fn removal_target(rel: &str) -> Option<(String, ArchOs)> {
    let base = rel.rsplit('/').next()?.strip_suffix(".apkg")?;
    let (name, hash) = base.rsplit_once('-')?;
    if hash.len() != 7 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let (_, ao) = ArchOs::split_suffix(name)?;
    Some((name.to_string(), ao))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let t = e.file_type()?;
        if t.is_dir() {
            walk(&e.path(), out)?;
        } else if t.is_file() && e.file_name().to_string_lossy().ends_with(".apkg") {
            out.push(e.path());
        }
    }
    Ok(())
}

struct Indexes<'a> {
    opts: &'a Opts,
    tmp: PathBuf,
    map: BTreeMap<ArchOs, Index>,
}

impl Indexes<'_> {
    /// The index of `ao`, starting from the currently published database.
    fn get(&mut self, ao: ArchOs) -> apkg::Result<&mut Index> {
        if !self.map.contains_key(&ao) {
            let mut cfg = Config::new(&self.opts.db, self.tmp.join(ao.to_string()));
            cfg.prefix = self.opts.prefix.clone();
            cfg.archos = ao;
            let db = Db::open(cfg)?;
            let sub = db.primary();
            let ix = Index::new(&self.opts.db, ao, sub.records()?, sub.all_pins());
            log!("apkgdb: loaded {} database: {} packages", ao, ix.len());
            self.map.insert(ao, ix);
        }
        Ok(self.map.get_mut(&ao).unwrap())
    }
}

fn run(opts: &Opts) -> apkg::Result<()> {
    let src = KeySource::from_env()?;
    let key = src.key(DB_KEY_LABEL)?;
    let kid = key.key_id()?;
    log!("found APDB key: {}", key.describe());
    log!("Public key: {kid}");
    if opts.trust == Trust::Required && sig::db_key_name(&kid).is_none() {
        return Err(apkg::Error::Invalid(
            "this key is not trusted by apkg clients; use -allow_untrusted for tests".into(),
        ));
    }

    let dir = opts.dir.clone().unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("projects/apkg-tools/repo/apkg/dist")
            .join(&opts.db)
    });
    let tmp = std::env::temp_dir().join(format!("apkgidx-{}", std::process::id()));
    let mut ix = Indexes {
        opts,
        tmp: tmp.clone(),
        map: BTreeMap::new(),
    };
    let res = (|| -> apkg::Result<()> {
        for ao in &opts.platforms {
            ix.get(*ao)?;
        }
        let mut files = Vec::new();
        if dir.is_dir() {
            walk(&dir, &mut files)?;
        } else if opts.platforms.is_empty() && opts.pins.is_empty() {
            return Err(apkg::Error::Invalid(format!(
                "{}: not a directory",
                dir.display()
            )));
        }
        for f in files {
            let rel = f
                .strip_prefix(&dir)
                .unwrap_or(&f)
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string();
            if std::fs::metadata(&f)?.len() == 0 {
                log!("Removing: {rel}");
                match removal_target(&rel) {
                    Some((name, ao)) => {
                        if !ix.get(ao)?.remove(&name) {
                            log!("apkgdb: {name} was not in the database");
                        }
                    }
                    None => log!("apkgdb: cannot tell which package {rel} removes, skipped"),
                }
                continue;
            }
            log!("Indexing: {rel}");
            let (rec, ao) = read_package(&f, &rel, opts.trust)?;
            if let Err(e) = ix.get(ao)?.add(rec) {
                log!("failed to index package: {e}");
            }
        }
        if !opts.pins.is_empty() {
            if ix.map.is_empty() {
                ix.get(ArchOs::host())?;
            }
            for i in ix.map.values_mut() {
                for (ch, prefix, v) in &opts.pins {
                    i.set_pin(ch, prefix, v.as_deref());
                }
            }
        }
        for (ao, i) in &ix.map {
            let out = opts
                .out
                .clone()
                .unwrap_or_else(|| tmp.join("out"))
                .join(ao.to_string());
            let e = i.export(key.as_ref(), &out, opts.trust)?;
            log!(
                "apkgdb: exported {ao} version {} ({} packages) to {}",
                e.version,
                e.count,
                out.display()
            );
            if opts.upload {
                let dest = format!("{}/{}/{}/{}", opts.s3, opts.db, ao.os, ao.arch);
                upload(
                    opts,
                    &e.bin,
                    &format!("{dest}/{}.bin", e.version),
                    "max-age=31536000",
                    None,
                )?;
                upload(
                    opts,
                    &e.latest_txt,
                    &format!("{dest}/LATEST.txt"),
                    "max-age=60",
                    None,
                )?;
                upload(
                    opts,
                    &e.latest_jwt,
                    &format!("{dest}/LATEST.jwt"),
                    "max-age=60",
                    Some("text/plain"),
                )?;
                log!("apkgdb: uploaded {ao}");
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

fn upload(
    opts: &Opts,
    file: &Path,
    dest: &str,
    cache: &str,
    ctype: Option<&str>,
) -> apkg::Result<()> {
    let mut c = Command::new("aws");
    c.args([
        "s3",
        "--profile",
        &opts.profile,
        "cp",
        "--cache-control",
        cache,
    ]);
    if let Some(t) = ctype {
        c.args(["--content-type", t]);
    }
    c.arg(file).arg(dest);
    let st = c.status()?;
    if !st.success() {
        return Err(apkg::Error::Http(format!(
            "aws s3 cp to {dest} failed ({st})"
        )));
    }
    Ok(())
}

fn main() {
    let opts = parse_args();
    if let Err(e) = run(&opts) {
        log!("failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_names() {
        let (n, ao) =
            removal_target("core/symlinks/core.symlinks.0.0.2.linux.amd64-5d569d7.apkg").unwrap();
        assert_eq!(n, "core.symlinks.0.0.2.linux.amd64");
        assert_eq!(ao.to_string(), "linux.amd64");
        assert!(removal_target("x/foo.linux.amd64-zzzzzzz.apkg").is_none());
        assert!(removal_target("x/foo.apkg").is_none());
    }
}
