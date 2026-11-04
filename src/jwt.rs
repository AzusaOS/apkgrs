//! Verification of the EdDSA-signed `LATEST.jwt` database descriptors.

use crate::base64;
use crate::error::{Error, Result};
use crate::json::Value;
use crate::sig;

/// A JWT whose signature has been verified against a trusted database key.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    /// Signing key id (base64url ed25519 public key).
    pub key_id: String,
    /// Owner of the signing key.
    pub key_name: &'static str,
    /// Decoded claims.
    pub payload: Value,
}

/// Parse and verify a compact JWS signed with EdDSA by a trusted DB key.
pub fn verify_db_token(token: &str) -> Result<VerifiedToken> {
    let token = token.trim();
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Format("jwt: expected three segments".into()));
    };
    let dec = |s: &str, what: &str| {
        base64::decode(s.as_bytes()).ok_or_else(|| Error::Format(format!("jwt: bad base64 in {what}")))
    };
    let header = Value::parse(&dec(h64, "header")?).map_err(|e| Error::Format(format!("jwt header: {e}")))?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(Error::Integrity("jwt: unsupported algorithm".into()));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Integrity("jwt: missing kid".into()))?;
    let key_name = sig::db_key_name(kid)
        .ok_or_else(|| Error::Integrity("unknown key used for jwt signature".into()))?;
    let public = dec(kid, "kid")?;
    let signature = dec(s64, "signature")?;
    let signed = &token[..h64.len() + 1 + p64.len()];
    if !sig::ed25519_verify(&public, signed.as_bytes(), &signature) {
        return Err(Error::Integrity("jwt: invalid signature".into()));
    }
    let payload = Value::parse(&dec(p64, "payload")?).map_err(|e| Error::Format(format!("jwt payload: {e}")))?;
    Ok(VerifiedToken { key_id: kid.to_string(), key_name, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real descriptor published at data.apkg.net (main/linux/amd64).
    const REAL: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRiWEZ0N3lqUWhIY3BQcTBVSVJNb25XVXlPNWY0RG9OVk9ZY2VmS0NJaFUifQ.eyJhcmNoIjoiYW1kNjQiLCJuYW1lIjoibWFpbiIsIm9zIjoibGludXgiLCJ2ZXIiOiIyMDI2MTAyNDExMTE0MCJ9.sqKa64aRZKDgK-I2sQuqTCtzIS4qk75iZm1aHQ8S6U_Dimnct5h7nD3Iw7kHvdkydFqF0jG6TudJMbrX5f-RCQ";

    #[test]
    fn verifies_real_token() {
        let t = verify_db_token(REAL).unwrap();
        assert_eq!(t.payload.get("ver").unwrap().as_str(), Some("20261024111140"));
        assert_eq!(t.payload.get("os").unwrap().as_str(), Some("linux"));
    }

    #[test]
    fn rejects_tampered() {
        // flip the payload to another version
        let mut parts: Vec<String> = REAL.split('.').map(String::from).collect();
        parts[1] = base64::encode_url(br#"{"arch":"amd64","name":"main","os":"linux","ver":"29991024111140"}"#);
        assert!(verify_db_token(&parts.join(".")).is_err());
    }
}
