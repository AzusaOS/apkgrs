//! Ed25519 signing for repository tools: package headers, database
//! headers and `LATEST.jwt` descriptors.
//!
//! Keys come from a YubiHSM 2 (production) or from a seed file (testing),
//! selected with the `HSM` environment variable like the Go tools:
//!
//! * `HSM=yubihsm2` — talk to `yubihsm-connector` (address in
//!   `YUBIHSM_CONNECTOR`, default `localhost:12345`), authenticating with
//!   auth key 1; the passphrase is read from `YUBIHSM_PASSWORD` or prompted
//!   on the terminal. Keys are found by label (`pkg_sign_ed25519`,
//!   `tpdb_sign_ed25519`).
//! * `HSM=file:<path>` — an ed25519 seed, 64 hex characters (or 32 raw
//!   bytes), used for every label. For tests only.

mod yubihsm;

use std::sync::Arc;

use purecrypto::ec::ed25519::Ed25519PrivateKey;

pub use yubihsm::YubiHsm;

use crate::base64;
use crate::error::{Error, Result};
use crate::sig;

/// Label of the package signing key.
pub const PKG_KEY_LABEL: &str = "pkg_sign_ed25519";
/// Label of the database signing key.
pub const DB_KEY_LABEL: &str = "tpdb_sign_ed25519";

/// An ed25519 signing key, wherever it lives.
pub trait Signer: Send + Sync {
    /// Raw 32-byte public key.
    fn public_key(&self) -> Result<[u8; 32]>;
    /// Sign `msg` (pure ed25519, no prehash).
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]>;
    /// Human readable description for logs.
    fn describe(&self) -> String;

    /// Public key, base64url (the form used in trust lists and JWT `kid`).
    fn key_id(&self) -> Result<String> {
        Ok(base64::encode_url(&self.public_key()?))
    }
}

/// A key held in memory (from a seed file).
pub struct SeedKey {
    key: Ed25519PrivateKey,
    origin: String,
}

impl SeedKey {
    /// Key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32], origin: &str) -> SeedKey {
        SeedKey {
            key: Ed25519PrivateKey::from_bytes(seed),
            origin: origin.to_string(),
        }
    }

    /// Load a seed file: 64 hex characters, or exactly 32 raw bytes.
    pub fn load(path: &std::path::Path) -> Result<SeedKey> {
        let data = std::fs::read(path)?;
        let text = String::from_utf8_lossy(&data);
        let t = text.trim();
        let seed: [u8; 32] = if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap();
            }
            s
        } else {
            data.as_slice().try_into().map_err(|_| {
                Error::Invalid(format!(
                    "{}: expected a 32-byte ed25519 seed",
                    path.display()
                ))
            })?
        };
        Ok(SeedKey::from_seed(seed, &path.display().to_string()))
    }
}

impl Signer for SeedKey {
    fn public_key(&self) -> Result<[u8; 32]> {
        Ok(self.key.public_key().to_bytes())
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        Ok(self.key.sign(msg).to_bytes())
    }
    fn describe(&self) -> String {
        format!("seed file {}", self.origin)
    }
}

/// A key of a YubiHSM 2, addressed by object id.
pub struct HsmKey {
    hsm: Arc<YubiHsm>,
    id: u16,
    label: String,
}

impl Signer for HsmKey {
    fn public_key(&self) -> Result<[u8; 32]> {
        self.hsm.ed25519_public_key(self.id)
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        self.hsm.sign_eddsa(self.id, msg)
    }
    fn describe(&self) -> String {
        format!("YubiHSM2 key 0x{:04x} ({})", self.id, self.label)
    }
}

/// Key source selected by the `HSM` environment variable.
pub enum KeySource {
    YubiHsm(Arc<YubiHsm>),
    Seed(std::path::PathBuf),
}

impl KeySource {
    /// Read the `HSM` environment variable.
    pub fn from_env() -> Result<KeySource> {
        match std::env::var("HSM").ok().as_deref() {
            Some("yubihsm2") => {
                let addr =
                    std::env::var("YUBIHSM_CONNECTOR").unwrap_or_else(|_| "localhost:12345".into());
                Ok(KeySource::YubiHsm(Arc::new(YubiHsm::connect_interactive(
                    &addr, 1,
                )?)))
            }
            Some(v) if v.starts_with("file:") => Ok(KeySource::Seed(v[5..].into())),
            _ => Err(Error::Invalid(
                "no HSM enabled: set HSM=yubihsm2 (or HSM=file:<seed file> for tests)".into(),
            )),
        }
    }

    /// The signing key with `label`.
    pub fn key(&self, label: &str) -> Result<Box<dyn Signer>> {
        match self {
            KeySource::Seed(p) => Ok(Box::new(SeedKey::load(p)?)),
            KeySource::YubiHsm(h) => {
                let ids = h.find_asymmetric_keys(label)?;
                let id = *ids.first().ok_or(Error::NotFound)?;
                Ok(Box::new(HsmKey {
                    hsm: h.clone(),
                    id,
                    label: label.to_string(),
                }))
            }
        }
    }
}

/// Build an apkg signature blob (`uvarint(1)`, key, signature) for `data`.
pub fn signature_blob(signer: &dyn Signer, data: &[u8]) -> Result<Vec<u8>> {
    let public = signer.public_key()?;
    let signature = signer.sign(data)?;
    if !sig::ed25519_verify(&public, data, &signature) {
        return Err(Error::Integrity(format!(
            "{} produced an invalid signature",
            signer.describe()
        )));
    }
    let mut out = Vec::with_capacity(sig::SIGNATURE_SIZE);
    sig::put_uvarint(&mut out, 1);
    sig::put_varblob(&mut out, &public);
    sig::put_varblob(&mut out, &signature);
    Ok(out)
}

/// Sign `payload` (a JSON object) as a compact EdDSA JWT whose `kid` is the
/// base64url public key, as `LATEST.jwt` descriptors are.
pub fn jwt(signer: &dyn Signer, payload_json: &str) -> Result<String> {
    let header = format!("{{\"alg\":\"EdDSA\",\"kid\":\"{}\"}}", signer.key_id()?);
    let signing_input = format!(
        "{}.{}",
        base64::encode_url(header.as_bytes()),
        base64::encode_url(payload_json.as_bytes())
    );
    let s = signer.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", base64::encode_url(&s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_key_signs() {
        let k = SeedKey::from_seed([7; 32], "test");
        let blob = signature_blob(&k, b"hello").unwrap();
        assert_eq!(blob.len(), sig::SIGNATURE_SIZE);
        // untrusted key: verify_pkg rejects it, but the signature itself is valid
        let e = sig::verify_pkg(b"hello", &blob).unwrap_err();
        assert!(e.to_string().contains("non trusted"), "{e}");
        let t = jwt(&k, r#"{"ver":"1"}"#).unwrap();
        assert_eq!(t.split('.').count(), 3);
    }
}
