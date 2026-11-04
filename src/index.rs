//! Publishing package databases (`apkg-index`): add or remove packages
//! starting from the current published database, then write a new signed
//! `APDB` file and its `LATEST.txt`/`LATEST.jwt` descriptors.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::apdb::{self, PackageRecord, Pin};
use crate::collate::collated_version;
use crate::error::{Error, Result};
use crate::json::{Value, write_str};
use crate::osarch::{Arch, ArchOs, Os};
use crate::pkgfile::{HEADER_LEN, Header};
use crate::sig::{self, SIGNATURE_SIZE};
use crate::sign::{self, Signer};
use crate::timefmt;

/// Whether signatures must come from the built-in trusted keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Production: only keys clients trust are accepted.
    Required,
    /// Testing: any key with a valid signature is accepted.
    AnyKey,
}

fn check_sig(data: &[u8], blob: &[u8], db: bool, trust: Trust) -> Result<()> {
    let r = if db {
        sig::verify_db(data, blob)
    } else {
        sig::verify_pkg(data, blob)
    };
    match r {
        Ok(_) => Ok(()),
        Err(e) if trust == Trust::AnyKey && e.to_string().contains("non trusted") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read a local `.apkg` into a database record (Go: `OpenPackage`),
/// checking its signature, metadata and hash table. `rel_path` is its path
/// relative to the repository's `dist/<db>/`.
pub fn read_package(path: &Path, rel_path: &str, trust: Trust) -> Result<(PackageRecord, ArchOs)> {
    let mut f = File::open(path)?;
    let size = f.metadata()?.len();
    let mut raw = vec![0u8; HEADER_LEN];
    f.read_exact(&mut raw)?;
    let h = Header::parse(&raw)?;
    let mut rest = Vec::new();
    // header, meta, table and signature all precede the data
    (&mut f)
        .take(u64::from(h.data_offset).saturating_sub(HEADER_LEN as u64))
        .read_to_end(&mut rest)?;
    let at = |off: u32, len: usize| -> Result<&[u8]> {
        let s = (off as usize)
            .checked_sub(HEADER_LEN)
            .ok_or_else(|| Error::Format("bad offset".into()))?;
        rest.get(s..s + len)
            .ok_or_else(|| Error::Format("truncated package".into()))
    };
    let sig_blob = at(h.sig_offset, SIGNATURE_SIZE)?.to_vec();
    check_sig(&raw, &sig_blob, false, trust)?;
    let meta = at(h.meta_offset, h.meta_len as usize)?.to_vec();
    if sig::sha256(&meta) != h.meta_hash {
        return Err(Error::Integrity("corrupted metadata".into()));
    }
    let table = at(h.table_offset, h.table_len as usize)?;
    if sig::sha256(table) != h.table_hash {
        return Err(Error::Integrity("corrupted hash table".into()));
    }
    let m = Value::parse(&meta).map_err(Error::Format)?;
    let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let name = s("full_name");
    let ao = ArchOs::new(
        Os::parse(&s("os")).ok_or_else(|| Error::Format(format!("{name}: bad os")))?,
        Arch::parse(&s("arch")).ok_or_else(|| Error::Format(format!("{name}: bad arch")))?,
    );
    let inodes = m.get("inodes").and_then(Value::as_u64).unwrap_or(0) as u32;
    let rec = PackageRecord {
        hash: sig::sha256(&raw),
        size,
        inodes,
        name,
        path: rel_path.to_string(),
        header: raw,
        sig: sig_blob,
        meta,
    };
    Ok((rec, ao))
}

/// One platform's database being edited.
#[derive(Debug, Default)]
pub struct Index {
    pub name: String,
    pub archos: Option<ArchOs>,
    /// collated name → record (export order)
    packages: BTreeMap<Vec<u8>, PackageRecord>,
    pins: BTreeMap<(String, String), String>,
}

/// Files written by [`Index::export`].
#[derive(Debug)]
pub struct Exported {
    pub version: String,
    pub bin: PathBuf,
    pub latest_txt: PathBuf,
    pub latest_jwt: PathBuf,
    pub count: usize,
}

impl Index {
    /// Start from the given records and pins (e.g. the current database).
    pub fn new(name: &str, archos: ArchOs, records: Vec<PackageRecord>, pins: Vec<Pin>) -> Index {
        let mut ix = Index {
            name: name.to_string(),
            archos: Some(archos),
            ..Default::default()
        };
        for r in records {
            ix.packages.insert(collated_version(&r.name), r);
        }
        for p in pins {
            ix.pins.insert((p.channel, p.prefix), p.version);
        }
        ix
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Add a package; refused if the same package (header hash) is already
    /// present. A package with the same name is replaced.
    pub fn add(&mut self, rec: PackageRecord) -> Result<()> {
        if self.packages.values().any(|r| r.hash == rec.hash) {
            return Err(Error::Invalid("package already in database".into()));
        }
        self.packages.insert(collated_version(&rec.name), rec);
        Ok(())
    }

    /// Remove a package by full name; returns whether it was present.
    pub fn remove(&mut self, name: &str) -> bool {
        self.packages.remove(&collated_version(name)).is_some()
    }

    /// Set (`Some`) or delete (`None`) a pin.
    pub fn set_pin(&mut self, channel: &str, prefix: &str, version: Option<&str>) {
        let k = (channel.to_string(), prefix.to_string());
        match version {
            Some(v) => {
                self.pins.insert(k, v.to_string());
            }
            None => {
                self.pins.remove(&k);
            }
        }
    }

    /// Pins as (channel, prefix, version).
    pub fn pins(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.pins
            .iter()
            .map(|((c, p), v)| (c.as_str(), p.as_str(), v.as_str()))
    }

    /// Build a signed APDB image created at `now` (unix seconds, nanos).
    pub fn build(&self, signer: &dyn Signer, now: (i64, u32), trust: Trust) -> Result<Vec<u8>> {
        let ao = self
            .archos
            .ok_or_else(|| Error::Invalid("index without platform".into()))?;
        let mut data = Vec::new();
        for r in self.packages.values() {
            r.write(&mut data);
        }
        for ((channel, prefix), version) in &self.pins {
            Pin {
                channel: channel.clone(),
                prefix: prefix.clone(),
                version: version.clone(),
            }
            .write(&mut data);
        }
        let empty = sig::sha256(b"");
        let data_loc = (apdb::HEADER_LEN + SIGNATURE_SIZE) as u32;
        let mut h = Vec::with_capacity(apdb::HEADER_LEN);
        h.extend_from_slice(b"APDB");
        h.extend_from_slice(&1u32.to_be_bytes());
        h.extend_from_slice(&0u64.to_be_bytes());
        h.extend_from_slice(&(now.0 as u64).to_be_bytes());
        h.extend_from_slice(&u64::from(now.1).to_be_bytes());
        h.extend_from_slice(&ao.os.id().to_be_bytes());
        h.extend_from_slice(&ao.arch.id().to_be_bytes());
        h.extend_from_slice(&(self.packages.len() as u32).to_be_bytes());
        let mut name = [0u8; 32];
        let nb = self.name.as_bytes();
        if nb.len() > 32 {
            return Err(Error::Invalid("database name longer than 32 bytes".into()));
        }
        name[..nb.len()].copy_from_slice(nb);
        h.extend_from_slice(&name);
        h.extend_from_slice(&data_loc.to_be_bytes());
        h.extend_from_slice(&(data.len() as u32).to_be_bytes());
        h.extend_from_slice(&sig::sha256(&data));
        for _ in 0..2 {
            // id index, name index: reserved
            h.extend_from_slice(&0u32.to_be_bytes());
            h.extend_from_slice(&0u32.to_be_bytes());
            h.extend_from_slice(&empty);
        }
        debug_assert_eq!(h.len(), apdb::HEADER_LEN);
        let blob = sign::signature_blob(signer, &h)?;
        check_sig(&h, &blob, true, trust)?;
        let mut out = h;
        let mut sigbuf = vec![0u8; SIGNATURE_SIZE];
        sigbuf[..blob.len()].copy_from_slice(&blob);
        out.extend_from_slice(&sigbuf);
        out.extend_from_slice(&data);
        Ok(out)
    }

    /// Write `<version>.bin`, `LATEST.txt` and `LATEST.jwt` into `dir`.
    pub fn export(&self, signer: &dyn Signer, dir: &Path, trust: Trust) -> Result<Exported> {
        let ao = self
            .archos
            .ok_or_else(|| Error::Invalid("index without platform".into()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as i64;
        let version = timefmt::stamp(secs);
        crate::log!(
            "apkgdb: creating database export version {version} ({} packages)",
            self.packages.len()
        );
        let bin = self.build(signer, (secs, now.subsec_nanos()), trust)?;

        // sanity check: the result must parse back to what we wrote
        let parsed = match trust {
            Trust::Required => apdb::parse(&bin)?,
            Trust::AnyKey => apdb::parse_any_signer(&bin)?,
        };
        if parsed.packages.len() != self.packages.len() || parsed.pins.len() != self.pins.len() {
            return Err(Error::Integrity(
                "exported database does not read back".into(),
            ));
        }

        std::fs::create_dir_all(dir)?;
        let bin_path = dir.join(format!("{version}.bin"));
        std::fs::write(&bin_path, &bin)?;
        let latest_txt = dir.join("LATEST.txt");
        std::fs::write(&latest_txt, format!("{version}\n"))?;
        let mut payload = String::from("{\"arch\":");
        write_str(&mut payload, ao.arch.as_str());
        payload.push_str(",\"name\":");
        write_str(&mut payload, &self.name);
        payload.push_str(",\"os\":");
        write_str(&mut payload, ao.os.as_str());
        payload.push_str(",\"ver\":");
        write_str(&mut payload, &version);
        payload.push('}');
        let token = sign::jwt(signer, &payload)?;
        if trust == Trust::Required {
            crate::jwt::verify_db_token(&token)?;
        }
        let latest_jwt = dir.join("LATEST.jwt");
        std::fs::write(&latest_jwt, format!("{token}\n"))?;
        Ok(Exported {
            version,
            bin: bin_path,
            latest_txt,
            latest_jwt,
            count: self.packages.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SeedKey;

    fn rec(name: &str, h: u8) -> PackageRecord {
        PackageRecord {
            hash: [h; 32],
            size: 1,
            inodes: 1,
            name: name.into(),
            path: format!("{name}.apkg"),
            header: vec![0; 124],
            sig: vec![0; SIGNATURE_SIZE],
            meta: b"{}".to_vec(),
        }
    }

    #[test]
    fn build_and_parse_back() {
        let ao = ArchOs::new(Os::Linux, Arch::Amd64);
        let mut ix = Index::new("main", ao, vec![rec("a.b.core.1.linux.amd64", 1)], vec![]);
        ix.add(rec("a.b.core.2.linux.amd64", 2)).unwrap();
        assert!(ix.add(rec("x.y.core.1.linux.amd64", 2)).is_err()); // same hash
        ix.set_pin("stable", "a.b.core", Some("1"));
        let key = SeedKey::from_seed([3; 32], "test");
        let bin = ix.build(&key, (1_700_000_000, 5), Trust::AnyKey).unwrap();
        // production verification refuses the untrusted test key...
        assert!(apdb::parse(&bin).is_err());
        assert!(ix.build(&key, (1, 0), Trust::Required).is_err());
        // ...but the structure is valid
        let db = apdb::parse_any_signer(&bin).unwrap();
        assert_eq!(db.name, "main");
        assert_eq!(db.created, 1_700_000_000);
        assert_eq!(db.packages.len(), 2);
        assert_eq!(db.packages[0].name, "a.b.core.1.linux.amd64");
        assert_eq!(
            db.pins,
            vec![Pin {
                channel: "stable".into(),
                prefix: "a.b.core".into(),
                version: "1".into()
            }]
        );
        assert!(ix.remove("a.b.core.1.linux.amd64"));
        assert!(!ix.remove("a.b.core.1.linux.amd64"));
    }
}
