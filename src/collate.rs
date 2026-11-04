//! Version-aware ordering of package names.
//!
//! * [`collated_version`] produces index keys: each run of digits is prefixed
//!   with a byte `0x7f + run length`, so byte order equals version order and
//!   digit runs sort after letters.
//! * [`natural_cmp`] compares two names the same way for display sorting.

use std::cmp::Ordering;

/// Collation key of `v` for indexing. Runs longer than 33 digits are split (matching the Go implementation).
pub fn collated_version(v: &str) -> Vec<u8> {
    let v = v.as_bytes();
    let mut r = Vec::with_capacity(v.len() + 8);
    let mut i = 0;
    while i < v.len() {
        if !v[i].is_ascii_digit() {
            r.push(v[i]);
            i += 1;
            continue;
        }
        let mut n = 1;
        while n < 33 && i + n < v.len() && v[i + n].is_ascii_digit() {
            n += 1;
        }
        r.push(0x7f + n as u8);
        r.extend_from_slice(&v[i..i + n]);
        i += n;
    }
    r
}

/// Natural ("version") order: numbers compare numerically (leading zeros
/// ignored), and digits sort after any other character.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    loop {
        match (i < a.len(), j < b.len()) {
            (false, false) => return Ordering::Equal,
            (false, true) => return Ordering::Less,
            (true, false) => return Ordering::Greater,
            _ => {}
        }
        let (ca, cb) = (a[i], b[j]);
        if ca.is_ascii_digit() && cb.is_ascii_digit() {
            let run = |s: &[u8], mut p: usize| {
                // skip leading zeros, keeping at least one digit
                while p + 1 < s.len() && s[p] == b'0' && s[p + 1].is_ascii_digit() {
                    p += 1;
                }
                let st = p;
                while p < s.len() && s[p].is_ascii_digit() {
                    p += 1;
                }
                (st, p)
            };
            let (sa, ea) = run(a, i);
            let (sb, eb) = run(b, j);
            let ord = (ea - sa)
                .cmp(&(eb - sb))
                .then_with(|| a[sa..ea].cmp(&b[sb..eb]));
            if ord != Ordering::Equal {
                return ord;
            }
            i = ea;
            j = eb;
            continue;
        }
        if ca == cb {
            i += 1;
            j += 1;
            continue;
        }
        if cb.is_ascii_digit() {
            return Ordering::Less;
        }
        if ca.is_ascii_digit() {
            return Ordering::Greater;
        }
        return ca.cmp(&cb);
    }
}

/// Sort names in natural order.
pub fn natural_sort(list: &mut [String]) {
    list.sort_by(|a, b| natural_cmp(a, b));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(v: &[&str]) -> Vec<String> {
        let mut l: Vec<String> = v.iter().map(|s| s.to_string()).collect();
        natural_sort(&mut l);
        l
    }

    #[test]
    fn natsort() {
        assert_eq!(
            sorted(&[
                "media-video.ffmpeg.libs.5.1.3.linux.amd64",
                "media-video.ffmpeg.libs.5.0.1.linux.amd64"
            ])[0],
            "media-video.ffmpeg.libs.5.0.1.linux.amd64"
        );
        assert_eq!(sorted(&["foo00001", "foo002"])[0], "foo00001");
        assert_eq!(sorted(&["foo10", "foo01"])[0], "foo01");
        assert_eq!(sorted(&["foo10", "foo1"])[0], "foo1");
        assert_eq!(sorted(&["a.1", "a.b"])[0], "a.b");
    }

    #[test]
    fn collation() {
        assert_eq!(collated_version("a1"), b"a\x801");
        assert_eq!(collated_version("x.42.y"), b"x.\x8142.y");
        assert!(collated_version("core.1.2.9") < collated_version("core.1.2.10"));
        assert!(collated_version("core.a") < collated_version("core.1"));
        // a 34-digit run is split into 33 + 1
        let k = collated_version(&"1".repeat(34));
        assert_eq!(k[0], 0x7f + 33);
        assert_eq!(k[34], 0x80);
    }
}
