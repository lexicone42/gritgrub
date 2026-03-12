//! Stateless bearer tokens for gRPC auth.
//!
//! Token format: `forge-v1:<identity-uuid>:<expiry-hex>:<ed25519-sig-hex>`
//!
//! The signature covers: "forge-token-v1\n<identity-uuid>\n<expiry-hex>"
//! Stateless = no server-side storage. Verify by checking the signature
//! against the identity's stored public key.

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use crate::identity::IdentityId;

const TOKEN_PREFIX: &str = "forge-v1";
const SIGN_DOMAIN: &str = "forge-token-v1";

/// Generate a bearer token for an identity.
/// `expiry_micros` is the unix timestamp (microseconds) when the token expires.
/// Pass 0 for a non-expiring token.
pub fn generate_token(
    identity: IdentityId,
    signing_key: &SigningKey,
    expiry_micros: i64,
) -> String {
    let expiry_hex = format!("{:016x}", expiry_micros);
    let message = sign_message(&identity, &expiry_hex);
    let signature = signing_key.sign(message.as_bytes());
    let sig_hex: String = signature.to_bytes().iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    format!("{}:{}:{}:{}", TOKEN_PREFIX, identity, expiry_hex, sig_hex)
}

/// Parse and validate a bearer token.
/// Returns the identity if the token is valid and not expired.
pub fn validate_token(
    token: &str,
    now_micros: i64,
    public_key_lookup: impl Fn(&IdentityId) -> Option<[u8; 32]>,
) -> Result<IdentityId, TokenError> {
    if !token.starts_with("forge-v1:") {
        return Err(TokenError::InvalidFormat);
    }

    let rest = &token["forge-v1:".len()..];

    // UUID is 36 chars (8-4-4-4-12), then ":", then 16 hex expiry, then ":", then 128 hex sig
    if rest.len() < 36 + 1 + 16 + 1 + 128 {
        return Err(TokenError::InvalidFormat);
    }

    let uuid_str = &rest[..36];
    let identity = IdentityId(
        uuid::Uuid::parse_str(uuid_str).map_err(|_| TokenError::InvalidFormat)?
    );

    // After UUID: ":expiry:sig"
    let after_uuid = &rest[37..]; // skip ":"
    if after_uuid.len() < 16 + 1 + 128 {
        return Err(TokenError::InvalidFormat);
    }

    let expiry_hex = &after_uuid[..16];
    let sig_hex = &after_uuid[17..]; // skip ":"

    // Check expiry.
    let expiry_micros = i64::from_str_radix(expiry_hex, 16)
        .map_err(|_| TokenError::InvalidFormat)?;
    if expiry_micros != 0 && now_micros > expiry_micros {
        return Err(TokenError::Expired);
    }

    // Look up the public key.
    let public_key_bytes = public_key_lookup(&identity)
        .ok_or(TokenError::UnknownIdentity)?;

    // Verify signature.
    let sig_bytes = hex_to_bytes_64(sig_hex).ok_or(TokenError::InvalidSignature)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| TokenError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let message = sign_message(&identity, expiry_hex);
    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|_| TokenError::InvalidSignature)?;

    Ok(identity)
}

fn sign_message(identity: &IdentityId, expiry_hex: &str) -> String {
    format!("{}\n{}\n{}", SIGN_DOMAIN, identity, expiry_hex)
}

fn hex_to_bytes_64(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(bytes)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid token format")]
    InvalidFormat,
    #[error("token expired")]
    Expired,
    #[error("unknown identity")]
    UnknownIdentity,
    #[error("invalid signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let id = IdentityId::new();
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let token = generate_token(id, &signing_key, 0); // non-expiring

        let result = validate_token(&token, 0, |lookup_id| {
            if *lookup_id == id { Some(public_bytes) } else { None }
        });
        assert_eq!(result.unwrap(), id);
    }

    #[test]
    fn expired_token_rejected() {
        let id = IdentityId::new();
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let token = generate_token(id, &signing_key, 1000); // expires at t=1000

        let result = validate_token(&token, 2000, |lookup_id| {
            if *lookup_id == id { Some(public_bytes) } else { None }
        });
        assert!(matches!(result, Err(TokenError::Expired)));
    }

    #[test]
    fn wrong_key_rejected() {
        let id = IdentityId::new();
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);

        let token = generate_token(id, &signing_key, 0);

        let result = validate_token(&token, 0, |lookup_id| {
            if *lookup_id == id { Some(wrong_key.verifying_key().to_bytes()) } else { None }
        });
        assert!(matches!(result, Err(TokenError::InvalidSignature)));
    }
}
