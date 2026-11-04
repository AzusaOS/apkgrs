//! Reader/writer for glibc's `ld.so.cache` (new format, `glibc-ld.so.cache1.1`).
//!
//! Packages in the `libs` subcategory ship their own small cache in their
//! metadata; the database merges them into one cache served at
//! `/pkg/<db>/ld.so.cache`.

use std::cmp::Ordering;

use crate::error::{Error, Result};

const MAGIC: &[u8; 17] = b"glibc-ld.so.cache";
const VERSION: &[u8; 3] = b"1.1";
const HEADER_LEN: usize = 48;
const ENTRY_LEN: usize = 24;

/// One library entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub flags: i32,
    /// Library soname, e.g. `libz.so.1`.
    pub key: String,
    /// Full path of the library.
    pub value: String,
    pub os_version: u32,
    pub hwcap: u64,
}

#[derive(Clone, Copy)]
enum Order {
    Big,
    Little,
}

impl Order {
    fn u32(self, b: &[u8]) -> u32 {
        let a: [u8; 4] = b[..4].try_into().unwrap();
        match self {
            Order::Big => u32::from_be_bytes(a),
            Order::Little => u32::from_le_bytes(a),
        }
    }
    fn u64(self, b: &[u8]) -> u64 {
        let a: [u8; 8] = b[..8].try_into().unwrap();
        match self {
            Order::Big => u64::from_be_bytes(a),
            Order::Little => u64::from_le_bytes(a),
        }
    }
}

fn cstr(data: &[u8], pos: u32) -> Result<String> {
    let pos = pos as usize;
    if pos >= data.len() {
        return Err(Error::Format("ld.so.cache: string offset out of range".into()));
    }
    let s = &data[pos..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    Ok(String::from_utf8_lossy(&s[..end]).into_owned())
}

/// Parse a cache file; byte order is detected automatically.
pub fn parse(data: &[u8]) -> Result<Vec<Entry>> {
    if data.len() < HEADER_LEN || &data[..17] != MAGIC || &data[17..20] != VERSION {
        return Err(Error::Format("ld.so.cache: bad header".into()));
    }
    let mut order = Order::Big;
    let mut nlibs = order.u32(&data[20..]);
    if nlibs >= 0x100_0000 {
        order = Order::Little;
        nlibs = order.u32(&data[20..]);
    }
    let nlibs = nlibs as usize;
    let table_off = HEADER_LEN
        .checked_add(nlibs.checked_mul(ENTRY_LEN).ok_or_else(|| Error::Format("ld.so.cache: too many libs".into()))?)
        .filter(|&o| o <= data.len())
        .ok_or_else(|| Error::Format("ld.so.cache: truncated".into()))?;
    let mut out = Vec::with_capacity(nlibs);
    for i in 0..nlibs {
        let e = &data[HEADER_LEN + i * ENTRY_LEN..];
        let (k, v) = (order.u32(&e[4..]), order.u32(&e[8..]));
        if (k as usize) < table_off || (v as usize) < table_off {
            return Err(Error::Format("ld.so.cache: string offset too low".into()));
        }
        out.push(Entry {
            flags: order.u32(e) as i32,
            key: cstr(data, k)?,
            value: cstr(data, v)?,
            os_version: order.u32(&e[12..]),
            hwcap: order.u64(&e[16..]),
        });
    }
    Ok(out)
}

/// glibc's `_dl_cache_libcmp`: digit runs compare numerically.
pub fn libcmp(p1: &str, p2: &str) -> Ordering {
    let (a, b) = (p1.as_bytes(), p2.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() {
        let c1 = a[i];
        let d2 = j < b.len() && b[j].is_ascii_digit();
        if c1.is_ascii_digit() {
            if !d2 {
                return Ordering::Greater;
            }
            let mut v1: u64 = 0;
            while i < a.len() && a[i].is_ascii_digit() {
                v1 = v1.wrapping_mul(10).wrapping_add(u64::from(a[i] - b'0'));
                i += 1;
            }
            let mut v2: u64 = 0;
            while j < b.len() && b[j].is_ascii_digit() {
                v2 = v2.wrapping_mul(10).wrapping_add(u64::from(b[j] - b'0'));
                j += 1;
            }
            if v1 != v2 {
                return v1.cmp(&v2);
            }
        } else {
            if d2 {
                return Ordering::Less;
            }
            let c2 = b.get(j).copied().unwrap_or(0);
            if c1 != c2 {
                return c1.cmp(&c2);
            }
            i += 1;
            j += 1;
        }
    }
    if j < b.len() { Ordering::Less } else { Ordering::Equal }
}

/// Sort entries the way ldconfig does (descending by [`libcmp`]), which the
/// dynamic loader's binary search relies on.
pub fn sort(entries: &mut [Entry]) {
    entries.sort_by(|x, y| libcmp(&y.key, &x.key));
}

/// Serialize entries (already sorted) in host byte order.
pub fn build(entries: &[Entry]) -> Vec<u8> {
    let table_off = HEADER_LEN + ENTRY_LEN * entries.len();
    let mut table = Vec::new();
    let mut out = Vec::with_capacity(table_off);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(VERSION);
    out.extend_from_slice(&(entries.len() as u32).to_ne_bytes());
    let mut ents = Vec::with_capacity(ENTRY_LEN * entries.len());
    for e in entries {
        let kpos = (table_off + table.len()) as u32;
        table.extend_from_slice(e.key.as_bytes());
        table.push(0);
        let vpos = (table_off + table.len()) as u32;
        table.extend_from_slice(e.value.as_bytes());
        table.push(0);
        ents.extend_from_slice(&e.flags.to_ne_bytes());
        ents.extend_from_slice(&kpos.to_ne_bytes());
        ents.extend_from_slice(&vpos.to_ne_bytes());
        ents.extend_from_slice(&e.os_version.to_ne_bytes());
        ents.extend_from_slice(&e.hwcap.to_ne_bytes());
    }
    out.extend_from_slice(&(table.len() as u32).to_ne_bytes());
    out.resize(HEADER_LEN, 0);
    out.extend_from_slice(&ents);
    out.extend_from_slice(&table);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut e = vec![
            Entry { flags: 0x303, key: "libz.so.1".into(), value: "/pkg/main/libs.zlib.libs/lib64/libz.so.1".into(), os_version: 0, hwcap: 0 },
            Entry { flags: 0x303, key: "libc.so.6".into(), value: "/pkg/main/glibc/lib64/libc.so.6".into(), os_version: 0, hwcap: 0 },
            Entry { flags: 0x303, key: "libz.so.10".into(), value: "/x".into(), os_version: 1, hwcap: 2 },
        ];
        sort(&mut e);
        assert_eq!(e[0].key, "libz.so.10");
        assert_eq!(e[2].key, "libc.so.6");
        let b = build(&e);
        assert_eq!(parse(&b).unwrap(), e);
    }

    #[test]
    fn libcmp_order() {
        assert_eq!(libcmp("libz.so.2", "libz.so.10"), Ordering::Less);
        assert_eq!(libcmp("libz.so", "libz.so.1"), Ordering::Less);
        assert_eq!(libcmp("a1", "ab"), Ordering::Greater);
        assert_eq!(libcmp("abc", "abc"), Ordering::Equal);
    }
}
