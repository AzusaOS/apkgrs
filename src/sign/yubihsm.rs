//! Minimal YubiHSM 2 client: authenticated SCP03 session through
//! `yubihsm-connector`, enough to find ed25519 keys by label, read their
//! public key and sign with them.
//!
//! Protocol reference: <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>
//! (and the Go `github.com/KarpelesLab/hsm/yubihsm2` client this mirrors).

use std::sync::Mutex;

use purecrypto::cipher::{Aes128, BlockCipher, Cmac};
use purecrypto::hash::Sha256;
use purecrypto::rng::{OsRng, RngCore};

use crate::error::{Error, Result};
use crate::http;

const CMD_CREATE_SESSION: u8 = 0x03;
const CMD_AUTHENTICATE_SESSION: u8 = 0x04;
const CMD_SESSION_MESSAGE: u8 = 0x05;
const CMD_CLOSE_SESSION: u8 = 0x40;
const CMD_LIST_OBJECTS: u8 = 0x48;
const CMD_GET_PUBKEY: u8 = 0x54;
const CMD_SIGN_EDDSA: u8 = 0x6a;
const RESPONSE_FLAG: u8 = 0x80;
const ERROR_RESPONSE: u8 = 0xff;

const OBJECT_ASYMMETRIC_KEY: u8 = 0x03;
const ALGO_ED25519: u8 = 46;

const MAX_MESSAGES: u32 = 10_000;

struct Session {
    id: u8,
    enc: Aes128,
    mac: [u8; 16],
    rmac: [u8; 16],
    chain: [u8; 16],
    counter: u32,
}

/// A YubiHSM 2 reached through `yubihsm-connector`.
pub struct YubiHsm {
    url: String,
    auth_key: u16,
    /// PBKDF2-derived static keys (enc ‖ mac).
    static_keys: [u8; 32],
    session: Mutex<Option<Session>>,
}

fn cmac(key: &[u8; 16], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = Cmac::new(Aes128::new(key));
    for p in parts {
        m.update(p);
    }
    m.finalize()
}

/// SCP03 KDF (NIST SP 800-108 counter mode, AES-CMAC PRF).
fn kdf(key: &[u8], constant: u8, len_bytes: usize, host: &[u8; 8], card: &[u8; 8]) -> [u8; 16] {
    let key: &[u8; 16] = key.try_into().expect("16-byte key");
    let mut ctx = [0u8; 16];
    ctx[11] = constant;
    // ctx[12] = 0 separator; L in bits, big endian; counter 1
    let l = ((len_bytes * 8) as u16).to_be_bytes();
    cmac(key, &[&ctx[..12], &[0], &l, &[1], host, card])
}

/// ISO 9797-1 method 2 padding, skipped when already block aligned
/// (as the device and the reference client do).
fn pad(mut v: Vec<u8>) -> Vec<u8> {
    if !v.len().is_multiple_of(16) {
        v.push(0x80);
        while !v.len().is_multiple_of(16) {
            v.push(0);
        }
    }
    v
}

fn unpad(v: &[u8]) -> &[u8] {
    match v.last() {
        Some(0) | Some(0x80) => {}
        _ => return v,
    }
    let mut end = v.len();
    while end > 0 && v[end - 1] == 0 {
        end -= 1;
    }
    if end > 0 && v[end - 1] == 0x80 {
        end -= 1;
    }
    &v[..end]
}

fn frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + payload.len());
    v.push(cmd);
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hsm_error(code: u8) -> Error {
    let msg = match code {
        1 => "invalid command",
        2 => "invalid data",
        3 => "invalid session",
        4 => "authentication failed",
        5 => "no free sessions",
        6 => "session failed",
        7 => "storage failed",
        8 => "wrong length",
        9 => "insufficient permissions",
        10 => "log full",
        11 => "object not found",
        12 => "invalid id",
        13 => "invalid OTP",
        14 => "demo mode",
        15 => "command unexecuted",
        _ => "unknown error",
    };
    Error::Invalid(format!("YubiHSM2: {msg} (0x{code:02x})"))
}

/// Parse a response frame, checking its type.
fn parse(resp: &[u8], cmd: u8) -> Result<Vec<u8>> {
    if resp.len() < 3 {
        return Err(Error::Format("YubiHSM2: short response".into()));
    }
    let len = u16::from_be_bytes([resp[1], resp[2]]) as usize;
    let payload = &resp[3..];
    if payload.len() != len {
        return Err(Error::Format("YubiHSM2: response length mismatch".into()));
    }
    if resp[0] == ERROR_RESPONSE {
        return Err(hsm_error(payload.first().copied().unwrap_or(0)));
    }
    if resp[0] != cmd | RESPONSE_FLAG {
        return Err(Error::Format(format!(
            "YubiHSM2: unexpected response type 0x{:02x}",
            resp[0]
        )));
    }
    Ok(payload.to_vec())
}

impl YubiHsm {
    /// Connect to `yubihsm-connector` at `addr` (`host:port`) and open an
    /// authenticated session with auth key `auth_key` and `password`.
    pub fn connect(addr: &str, auth_key: u16, password: &str) -> Result<YubiHsm> {
        let mut static_keys = [0u8; 32];
        purecrypto::kdf::pbkdf2::<Sha256>(password.as_bytes(), b"Yubico", 10_000, &mut static_keys);
        let h = YubiHsm {
            url: format!("http://{addr}/connector/api"),
            auth_key,
            static_keys,
            session: Mutex::new(None),
        };
        *h.session.lock().unwrap() = Some(h.open_session()?);
        Ok(h)
    }

    /// Check the connector, then prompt for the passphrase (or take it from
    /// `YUBIHSM_PASSWORD`), allowing three attempts.
    pub fn connect_interactive(addr: &str, auth_key: u16) -> Result<YubiHsm> {
        let (status, body) = http::get(&format!("http://{addr}/connector/status"))?;
        let body = String::from_utf8_lossy(&body);
        let field = |k: &str| {
            body.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .unwrap_or("")
                .to_string()
        };
        if status != 200 || field("status") != "OK" {
            return Err(Error::Invalid(format!(
                "unable to access key: connector status {:?}",
                field("status")
            )));
        }
        crate::log!("Connected to YubiHSM manager v{}", field("version"));
        if let Ok(pw) = std::env::var("YUBIHSM_PASSWORD") {
            return Self::connect(addr, auth_key, &pw);
        }
        let mut last = None;
        for _ in 0..3 {
            eprint!("Enter passphrase for YubiHSM2 Key {auth_key}: ");
            let pw = crate::sys::read_password(0).map_err(Error::Io)?;
            eprintln!();
            match Self::connect(addr, auth_key, &pw) {
                Ok(h) => return Ok(h),
                Err(e) => {
                    eprintln!("Failed to unlock YubiHSM2: {e}");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap())
    }

    fn post(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        let (status, body) = http::post(&self.url, "application/octet-stream", data)?;
        if status != 200 {
            return Err(Error::Http(format!(
                "yubihsm-connector returned status {status}"
            )));
        }
        Ok(body)
    }

    fn open_session(&self) -> Result<Session> {
        let mut host = [0u8; 8];
        OsRng.fill_bytes(&mut host);
        let mut payload = self.auth_key.to_be_bytes().to_vec();
        payload.extend_from_slice(&host);
        let resp = parse(
            &self.post(frame(CMD_CREATE_SESSION, &payload))?,
            CMD_CREATE_SESSION,
        )?;
        if resp.len() != 17 {
            return Err(Error::Format(
                "YubiHSM2: bad create session response".into(),
            ));
        }
        let id = resp[0];
        let card: [u8; 8] = resp[1..9].try_into().unwrap();
        let (enc_s, mac_s) = self.static_keys.split_at(16);
        let enc = kdf(enc_s, 0x04, 16, &host, &card);
        let mac = kdf(mac_s, 0x06, 16, &host, &card);
        let rmac = kdf(mac_s, 0x07, 16, &host, &card);
        let card_crypto = kdf(&mac, 0x00, 8, &host, &card);
        if card_crypto[..8] != resp[9..17] {
            return Err(Error::Integrity(
                "YubiHSM2 authentication failed (wrong passphrase?)".into(),
            ));
        }
        let host_crypto = kdf(&mac, 0x01, 8, &host, &card);
        let mut s = Session {
            id,
            enc: Aes128::new(&enc),
            mac,
            rmac,
            chain: [0; 16],
            counter: 0,
        };
        let msg = self.mac_command(&mut s, CMD_AUTHENTICATE_SESSION, &host_crypto[..8]);
        parse(&self.post(msg)?, CMD_AUTHENTICATE_SESSION)?;
        s.counter = 1;
        Ok(s)
    }

    /// Frame `data` as a MAC-protected command of session `s`.
    fn mac_command(&self, s: &mut Session, cmd: u8, data: &[u8]) -> Vec<u8> {
        let len = ((1 + data.len() + 8) as u16).to_be_bytes();
        let full = cmac(&s.mac, &[&s.chain, &[cmd], &len, &[s.id], data]);
        s.chain = full;
        let mut v = vec![cmd];
        v.extend_from_slice(&len);
        v.push(s.id);
        v.extend_from_slice(data);
        v.extend_from_slice(&full[..8]);
        v
    }

    fn encrypted(&self, s: &mut Session, cmd: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if s.counter >= MAX_MESSAGES {
            return Err(Error::Invalid("YubiHSM2 session exhausted".into()));
        }
        let mut iv = [0u8; 16];
        iv[12..].copy_from_slice(&s.counter.to_be_bytes());
        s.enc.encrypt_block(&mut iv);

        // CBC encrypt
        let mut data = pad(frame(cmd, payload));
        let mut prev = iv;
        for block in data.as_chunks_mut::<16>().0 {
            let b: &mut [u8; 16] = block;
            for (x, p) in b.iter_mut().zip(prev) {
                *x ^= p;
            }
            s.enc.encrypt_block(b);
            prev = *b;
        }
        let msg = self.mac_command(s, CMD_SESSION_MESSAGE, &data);
        let resp = parse(&self.post(msg)?, CMD_SESSION_MESSAGE)?;
        if resp.len() < 1 + 8 || (resp.len() - 9) % 16 != 0 {
            return Err(Error::Format(
                "YubiHSM2: bad session message response".into(),
            ));
        }
        let (body, rmac) = resp.split_at(resp.len() - 8);
        let len = ((body.len() + 8) as u16).to_be_bytes();
        let expect = cmac(
            &s.rmac,
            &[&s.chain, &[CMD_SESSION_MESSAGE | RESPONSE_FLAG], &len, body],
        );
        if expect[..8] != *rmac {
            return Err(Error::Integrity("YubiHSM2: invalid response MAC".into()));
        }
        s.counter += 1;

        // CBC decrypt (same IV as the command)
        let mut plain = body[1..].to_vec();
        let mut prev = iv;
        for block in plain.as_chunks_mut::<16>().0 {
            let b: &mut [u8; 16] = block;
            let c = *b;
            s.enc.decrypt_block(b);
            for (x, p) in b.iter_mut().zip(prev) {
                *x ^= p;
            }
            prev = c;
        }
        parse(unpad(&plain), cmd)
    }

    /// Send an encrypted command; a stale session (timeouts happen after
    /// 30 s of inactivity) is replaced once.
    fn call(&self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut guard = self.session.lock().unwrap();
        if let Some(s) = guard.as_mut() {
            match self.encrypted(s, cmd, payload) {
                Ok(r) => return Ok(r),
                Err(e @ Error::Invalid(_)) if !e.to_string().contains("session") => return Err(e),
                Err(_) => {}
            }
        }
        let mut s = self.open_session()?;
        let r = self.encrypted(&mut s, cmd, payload);
        *guard = Some(s);
        r
    }

    /// Object ids of asymmetric keys labelled `label`.
    pub fn find_asymmetric_keys(&self, label: &str) -> Result<Vec<u16>> {
        if label.len() > 40 {
            return Err(Error::Invalid("label too long".into()));
        }
        let mut q = vec![0x02, OBJECT_ASYMMETRIC_KEY, 0x06];
        q.extend_from_slice(label.as_bytes());
        q.resize(3 + 40, 0);
        let r = self.call(CMD_LIST_OBJECTS, &q)?;
        Ok(r.as_chunks::<4>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect())
    }

    /// Public key of ed25519 key `id`.
    pub fn ed25519_public_key(&self, id: u16) -> Result<[u8; 32]> {
        let r = self.call(CMD_GET_PUBKEY, &id.to_be_bytes())?;
        if r.first() != Some(&ALGO_ED25519) || r.len() != 33 {
            return Err(Error::Invalid(format!(
                "YubiHSM2 key 0x{id:04x} is not ed25519"
            )));
        }
        Ok(r[1..].try_into().unwrap())
    }

    /// Sign `msg` with ed25519 key `id`.
    pub fn sign_eddsa(&self, id: u16, msg: &[u8]) -> Result<[u8; 64]> {
        if msg.len() > 2000 {
            return Err(Error::Invalid(
                "ed25519: message too large for the HSM".into(),
            ));
        }
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(msg);
        let r = self.call(CMD_SIGN_EDDSA, &q)?;
        r.as_slice()
            .try_into()
            .map_err(|_| Error::Format("YubiHSM2: bad signature length".into()))
    }
}

impl Drop for YubiHsm {
    fn drop(&mut self) {
        if let Ok(mut g) = self.session.lock()
            && let Some(mut s) = g.take()
        {
            let _ = self.encrypted(&mut s, CMD_CLOSE_SESSION, &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        assert_eq!(pad(vec![1, 2, 3]).len(), 16);
        assert_eq!(unpad(&pad(vec![1, 2, 3])), &[1, 2, 3]);
        assert_eq!(pad(vec![0; 16]).len(), 16);
    }

    #[test]
    fn password_derivation() {
        // yubihsm-shell's default auth key: password "password" derives
        // enc 090b47dbed595654901dee1cc655e420 / mac 592fd483f759e29909a04c4505d2ce0a
        let mut k = [0u8; 32];
        purecrypto::kdf::pbkdf2::<Sha256>(b"password", b"Yubico", 10_000, &mut k);
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "090b47dbed595654901dee1cc655e420592fd483f759e29909a04c4505d2ce0a"
        );
    }
}
