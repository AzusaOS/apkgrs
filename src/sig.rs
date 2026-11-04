//! Package and database signatures (`apkgsig` in the Go implementation).
//!
//! A signature blob is `uvarint(1)` (type: ed25519) followed by two varblobs:
//! the 32-byte public key and the 64-byte signature over the raw header.
//! The key must be one of the trusted keys below.

use purecrypto::ec::ed25519::{Ed25519PublicKey, Ed25519Signature};

use crate::base64;
use crate::error::{Error, Result};

/// Ed25519 public key length.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Size of an encoded signature blob: three one-byte varints + key + signature.
pub const SIGNATURE_SIZE: usize = 3 + PUBLIC_KEY_SIZE + SIGNATURE_LEN;

/// Keys trusted to sign package databases (base64url key → owner).
pub const TRUSTED_DB_KEYS: &[(&str, &str)] = &[
    ("dbXFt7yjQhHcpPq0UIRMonWUyO5f4DoNVOYcefKCIhU", "Mark Karpeles <magicaltux@gmail.com>"),
    ("TPDBy98_HUS9JikdsjCbw_FjUjNWTx5ryNron_DHEBA", "APDB emergency key #1"),
];

/// Keys trusted to sign packages (base64url key → owner).
pub const TRUSTED_PKG_KEYS: &[(&str, &str)] = &[
    ("n21_CiuzEuo_OaSfEVodAXpQtcc4Qe_NprMSAs3B9QU", "Mark Karpeles <magicaltux@gmail.com>"),
    ("TPKGBiS_JH8tnSUgAE-4_f8gOkvzFqR2dnOKrJyLRus", "APKG emergency key #1"),
    ("TPKG37jwLgVabYPH3GSDAqSoAxlRAHN-aTQT3dLYLMQ", "APKG emergency key #2"),
];

/// Outcome of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// Signature format version (always 1 today).
    pub version: u64,
    /// Signing key, base64url.
    pub key: String,
    /// Human readable owner of the key.
    pub name: &'static str,
}

/// Simple forward-only cursor over a byte slice.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Format("unexpected end of data".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64_be(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Unsigned LEB128 varint, as Go's `binary.ReadUvarint`.
    pub fn uvarint(&mut self) -> Result<u64> {
        let mut x: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            if i == 9 && b > 1 {
                return Err(Error::Format("varint overflow".into()));
            }
            x |= u64::from(b & 0x7f) << (7 * i);
            if b < 0x80 {
                return Ok(x);
            }
        }
        Err(Error::Format("varint overflow".into()))
    }

    /// Length-prefixed blob, refusing anything longer than `max_len`.
    pub fn varblob(&mut self, max_len: u64) -> Result<&'a [u8]> {
        let l = self.uvarint()?;
        if l > max_len {
            return Err(Error::Format("oversized blob".into()));
        }
        self.take(l as usize)
    }
}

/// Append a Go-compatible uvarint.
pub fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Append a length-prefixed blob.
pub fn put_varblob(out: &mut Vec<u8>, v: &[u8]) {
    put_uvarint(out, v.len() as u64);
    out.extend_from_slice(v);
}

fn lookup(trust: &[(&str, &'static str)], key: &str) -> Option<&'static str> {
    trust.iter().find(|(k, _)| *k == key).map(|(_, n)| *n)
}

/// Name of a trusted database key, if `key` (base64url) is one.
pub fn db_key_name(key: &str) -> Option<&'static str> {
    lookup(TRUSTED_DB_KEYS, key)
}

/// Verify a raw ed25519 signature with a raw 32-byte key.
pub fn ed25519_verify(public: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sg)) = (<[u8; 32]>::try_from(public), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    Ed25519PublicKey::from_bytes(pk)
        .verify(data, &Ed25519Signature::from_bytes(sg))
        .is_ok()
}

fn verify(data: &[u8], sig: &[u8], trust: &[(&str, &'static str)]) -> Result<VerifyResult> {
    let mut c = Cursor::new(sig);
    let version = c.uvarint().unwrap_or(0);
    if version != 1 {
        return Err(Error::Integrity("unsupported signature version".into()));
    }
    let public = c.varblob(PUBLIC_KEY_SIZE as u64)?;
    let blob = c.varblob(SIGNATURE_LEN as u64)?;
    if !ed25519_verify(public, data, blob) {
        return Err(Error::Integrity("invalid signature".into()));
    }
    let key = base64::encode_url(public);
    let name = lookup(trust, &key)
        .ok_or_else(|| Error::Integrity("valid signature from non trusted key".into()))?;
    Ok(VerifyResult { version, key, name })
}

/// Verify a package header signature.
pub fn verify_pkg(data: &[u8], sig: &[u8]) -> Result<VerifyResult> {
    verify(data, sig, TRUSTED_PKG_KEYS)
}

/// Verify a database header signature.
pub fn verify_db(data: &[u8], sig: &[u8]) -> Result<VerifyResult> {
    verify(data, sig, TRUSTED_DB_KEYS)
}

/// SHA-256 helper.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    purecrypto::hash::sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 1 << 35, u64::MAX] {
            let mut b = Vec::new();
            put_uvarint(&mut b, v);
            assert_eq!(Cursor::new(&b).uvarint().unwrap(), v);
        }
    }

    #[test]
    fn rejects_untrusted_and_bad() {
        let mut sig = Vec::new();
        put_uvarint(&mut sig, 1);
        put_varblob(&mut sig, &[0u8; 32]);
        put_varblob(&mut sig, &[0u8; 64]);
        assert!(verify_pkg(b"hello", &sig).is_err());
        assert!(verify_db(b"hello", &[2]).is_err());
    }
}
