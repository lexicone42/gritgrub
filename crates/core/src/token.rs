//! Stateless bearer tokens for gRPC auth.
//!
//! ## Token formats
//!
//! **v1** (legacy, unscoped):
//!   `forge-v1:<uuid>:<expiry-hex>:<sig-hex>`
//!   Grants the full permissions of the identity.
//!
//! **v2** (current, scoped):
//!   `forge-v2:<uuid>:<expiry-hex>:<scopes>:<sig-hex>`
//!   Token permissions = identity capabilities ∩ token scopes.
//!
//! Scope strings: `*`, `read`, `write`, `attest`, `identity`, `ref:<pattern>`
//!
//! The signature covers identity + expiry + scopes, so tokens are
//! tamper-proof and self-describing. Agents can inspect their own
//! token to know what they're allowed to do before making requests.

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use crate::identity::IdentityId;

const TOKEN_V1_PREFIX: &str = "forge-v1";
const TOKEN_V2_PREFIX: &str = "forge-v2";
const SIGN_DOMAIN_V1: &str = "forge-token-v1";
const SIGN_DOMAIN_V2: &str = "forge-token-v2";

/// Parsed token scopes — what operations this token authorizes.
#[derive(Debug, Clone)]
pub struct TokenScopes {
    scopes: Vec<String>,
}

impl TokenScopes {
    /// Full-access token (equivalent to v1 behavior).
    pub fn admin() -> Self {
        Self { scopes: vec!["*".to_string()] }
    }

    /// Known valid scope prefixes.
    const VALID_SCOPES: &[&str] = &["*", "read", "write", "attest", "identity"];

    /// Create from a list of scope strings. Validates each scope (SE-9).
    pub fn from_strings(scopes: Vec<String>) -> Result<Self, String> {
        for s in &scopes {
            if s.starts_with("ref:") {
                continue; // ref:<pattern> is always valid
            }
            if !Self::VALID_SCOPES.contains(&s.as_str()) {
                return Err(format!(
                    "unknown scope '{}' — valid scopes: *, read, write, attest, identity, ref:<pattern>",
                    s
                ));
            }
        }
        Ok(Self { scopes })
    }

    pub fn as_strings(&self) -> &[String] {
        &self.scopes
    }

    /// Encode as comma-separated string for the token.
    pub fn encode(&self) -> String {
        self.scopes.join(",")
    }

    /// Decode from comma-separated string.
    pub fn decode(s: &str) -> Self {
        Self {
            scopes: s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        }
    }

    /// Is this an admin (unrestricted) token?
    pub fn is_admin(&self) -> bool {
        self.scopes.iter().any(|s| s == "*")
    }

    /// Does this token allow read operations?
    pub fn allows_read(&self) -> bool {
        self.is_admin() || self.scopes.iter().any(|s| s == "read" || s == "write")
    }

    /// Does this token allow write operations (objects, changesets)?
    pub fn allows_write(&self) -> bool {
        self.is_admin() || self.scopes.iter().any(|s| s == "write")
    }

    /// Does this token allow creating attestations?
    pub fn allows_attest(&self) -> bool {
        self.is_admin() || self.scopes.iter().any(|s| s == "attest")
    }

    /// Does this token allow identity management?
    pub fn allows_identity(&self) -> bool {
        self.is_admin() || self.scopes.iter().any(|s| s == "identity")
    }

    /// Does this token allow updating a specific ref?
    pub fn allows_ref(&self, ref_name: &str) -> bool {
        if self.is_admin() {
            return true;
        }
        self.scopes.iter().any(|s| {
            if let Some(pattern) = s.strip_prefix("ref:") {
                ref_scope_matches(pattern, ref_name)
            } else {
                false
            }
        })
    }
}

/// Check if a ref scope pattern matches a ref name.
/// Pattern: "refs/heads/*" matches "refs/heads/main" but not "refs/heads/a/b".
/// Pattern: "refs/heads/**" matches everything under refs/heads/.
fn ref_scope_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Reuse the glob matching from the policy module.
    crate::policy::glob_match_ref(pattern, name)
}

/// Validated token — identity + scopes extracted from a verified token.
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub identity: IdentityId,
    pub scopes: TokenScopes,
    /// Token expiry in microseconds since epoch (0 = non-expiring).
    pub expiry_micros: i64,
}

// ── v2 tokens (current) ────────────────────────────────────────────

/// Generate a scoped v2 bearer token.
pub fn generate_token_v2(
    identity: IdentityId,
    signing_key: &SigningKey,
    expiry_micros: i64,
    scopes: &TokenScopes,
) -> String {
    let expiry_hex = format!("{:016x}", expiry_micros);
    let scope_str = scopes.encode();
    let message = sign_message_v2(&identity, &expiry_hex, &scope_str);
    let signature = signing_key.sign(message.as_bytes());
    let sig_hex: String = signature.to_bytes().iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    format!("{}:{}:{}:{}:{}", TOKEN_V2_PREFIX, identity, expiry_hex, scope_str, sig_hex)
}

/// Generate a v1 bearer token (full permissions, backward compat).
pub fn generate_token(
    identity: IdentityId,
    signing_key: &SigningKey,
    expiry_micros: i64,
) -> String {
    let expiry_hex = format!("{:016x}", expiry_micros);
    let message = sign_message_v1(&identity, &expiry_hex);
    let signature = signing_key.sign(message.as_bytes());
    let sig_hex: String = signature.to_bytes().iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    format!("{}:{}:{}:{}", TOKEN_V1_PREFIX, identity, expiry_hex, sig_hex)
}

/// Parse and validate a bearer token (v1 or v2).
/// Returns the identity and scopes if valid.
pub fn validate_token(
    token: &str,
    now_micros: i64,
    public_key_lookup: impl Fn(&IdentityId) -> Option<[u8; 32]>,
) -> Result<ValidatedToken, TokenError> {
    if token.starts_with("forge-v2:") {
        validate_token_v2(token, now_micros, public_key_lookup)
    } else if token.starts_with("forge-v1:") {
        validate_token_v1(token, now_micros, public_key_lookup)
    } else {
        Err(TokenError::InvalidFormat)
    }
}

fn validate_token_v1(
    token: &str,
    now_micros: i64,
    public_key_lookup: impl Fn(&IdentityId) -> Option<[u8; 32]>,
) -> Result<ValidatedToken, TokenError> {
    let rest = &token[TOKEN_V1_PREFIX.len() + 1..]; // skip "forge-v1:"

    if !rest.is_ascii() {
        return Err(TokenError::InvalidFormat);
    }

    if rest.len() < 36 + 1 + 16 + 1 + 128 {
        return Err(TokenError::InvalidFormat);
    }

    let uuid_str = &rest[..36];
    let identity = IdentityId(
        uuid::Uuid::parse_str(uuid_str).map_err(|_| TokenError::InvalidFormat)?
    );

    let after_uuid = &rest[37..];
    if after_uuid.len() < 16 + 1 + 128 {
        return Err(TokenError::InvalidFormat);
    }

    let expiry_hex = &after_uuid[..16];
    let sig_hex = &after_uuid[17..];

    let expiry_micros = check_expiry(expiry_hex, now_micros)?;

    let message = sign_message_v1(&identity, expiry_hex);
    verify_signature(&identity, &message, sig_hex, &public_key_lookup)?;

    Ok(ValidatedToken {
        identity,
        scopes: TokenScopes::admin(), // v1 = full permissions
        expiry_micros,
    })
}

fn validate_token_v2(
    token: &str,
    now_micros: i64,
    public_key_lookup: impl Fn(&IdentityId) -> Option<[u8; 32]>,
) -> Result<ValidatedToken, TokenError> {
    let rest = &token[TOKEN_V2_PREFIX.len() + 1..]; // skip "forge-v2:"

    // Tokens are pure ASCII (hex digits, UUIDs, colons, scope names).
    // Reject non-ASCII early to avoid panics from byte-index string slicing.
    if !rest.is_ascii() {
        return Err(TokenError::InvalidFormat);
    }

    // Parse: <uuid>:<expiry>:<scopes>:<sig>
    // UUID is 36 chars, expiry is 16 hex, sig is 128 hex.
    // Scopes is variable length between the second and third colons.
    if rest.len() < 36 + 1 + 16 + 1 + 1 + 1 + 128 {
        return Err(TokenError::InvalidFormat);
    }

    let uuid_str = &rest[..36];
    let identity = IdentityId(
        uuid::Uuid::parse_str(uuid_str).map_err(|_| TokenError::InvalidFormat)?
    );

    let after_uuid = &rest[37..]; // skip ":"
    let expiry_hex = &after_uuid[..16];

    // Find the last colon — everything after it is the signature.
    let last_colon = after_uuid.rfind(':').ok_or(TokenError::InvalidFormat)?;
    // Scope string is between expiry: (pos 17) and :sig (last_colon).
    // If the colon structure is corrupted, last_colon may be <= 17.
    if last_colon <= 17 {
        return Err(TokenError::InvalidFormat);
    }
    let sig_hex = &after_uuid[last_colon + 1..];
    let scope_str = &after_uuid[17..last_colon];

    let expiry_micros = check_expiry(expiry_hex, now_micros)?;

    let message = sign_message_v2(&identity, expiry_hex, scope_str);
    verify_signature(&identity, &message, sig_hex, &public_key_lookup)?;

    Ok(ValidatedToken {
        identity,
        scopes: TokenScopes::decode(scope_str),
        expiry_micros,
    })
}

// ── Helpers ────────────────────────────────────────────────────────

fn check_expiry(expiry_hex: &str, now_micros: i64) -> Result<i64, TokenError> {
    let expiry_micros = i64::from_str_radix(expiry_hex, 16)
        .map_err(|_| TokenError::InvalidFormat)?;
    if expiry_micros != 0 && now_micros > expiry_micros {
        return Err(TokenError::Expired);
    }
    Ok(expiry_micros)
}

fn verify_signature(
    identity: &IdentityId,
    message: &str,
    sig_hex: &str,
    public_key_lookup: &impl Fn(&IdentityId) -> Option<[u8; 32]>,
) -> Result<(), TokenError> {
    let public_key_bytes = public_key_lookup(identity)
        .ok_or(TokenError::UnknownIdentity)?;

    let sig_bytes = hex_to_bytes_64(sig_hex).ok_or(TokenError::InvalidSignature)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| TokenError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|_| TokenError::InvalidSignature)?;

    Ok(())
}

fn sign_message_v1(identity: &IdentityId, expiry_hex: &str) -> String {
    format!("{}\n{}\n{}", SIGN_DOMAIN_V1, identity, expiry_hex)
}

fn sign_message_v2(identity: &IdentityId, expiry_hex: &str, scopes: &str) -> String {
    format!("{}\n{}\n{}\n{}", SIGN_DOMAIN_V2, identity, expiry_hex, scopes)
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
    #[error("token has been revoked")]
    Revoked,
    #[error("insufficient scope: {0}")]
    InsufficientScope(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (IdentityId, SigningKey, [u8; 32]) {
        let id = IdentityId::new();
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_bytes = signing_key.verifying_key().to_bytes();
        (id, signing_key, public_bytes)
    }

    #[test]
    fn v1_roundtrip() {
        let (id, sk, pk) = test_keypair();
        let token = generate_token(id, &sk, 0);
        let result = validate_token(&token, 0, |lid| {
            if *lid == id { Some(pk) } else { None }
        });
        let validated = result.unwrap();
        assert_eq!(validated.identity, id);
        assert!(validated.scopes.is_admin());
    }

    #[test]
    fn v2_roundtrip() {
        let (id, sk, pk) = test_keypair();
        let scopes = TokenScopes::from_strings(vec![
            "write".to_string(),
            "ref:refs/heads/feature/*".to_string(),
        ]).unwrap();
        let token = generate_token_v2(id, &sk, 0, &scopes);
        let result = validate_token(&token, 0, |lid| {
            if *lid == id { Some(pk) } else { None }
        });
        let validated = result.unwrap();
        assert_eq!(validated.identity, id);
        assert!(validated.scopes.allows_write());
        assert!(validated.scopes.allows_ref("refs/heads/feature/foo"));
        assert!(!validated.scopes.allows_ref("refs/heads/main"));
        assert!(!validated.scopes.allows_attest());
    }

    #[test]
    fn v1_expired_rejected() {
        let (id, sk, pk) = test_keypair();
        let token = generate_token(id, &sk, 1000);
        let result = validate_token(&token, 2000, |lid| {
            if *lid == id { Some(pk) } else { None }
        });
        assert!(matches!(result, Err(TokenError::Expired)));
    }

    #[test]
    fn v2_wrong_key_rejected() {
        let (id, sk, _pk) = test_keypair();
        let (_, wrong_sk, _) = test_keypair();
        let scopes = TokenScopes::admin();
        let token = generate_token_v2(id, &sk, 0, &scopes);
        let result = validate_token(&token, 0, |lid| {
            if *lid == id { Some(wrong_sk.verifying_key().to_bytes()) } else { None }
        });
        assert!(matches!(result, Err(TokenError::InvalidSignature)));
    }

    #[test]
    fn v2_tampered_scopes_rejected() {
        let (id, sk, pk) = test_keypair();
        let scopes = TokenScopes::from_strings(vec!["read".to_string()]).unwrap();
        let token = generate_token_v2(id, &sk, 0, &scopes);
        // Replace "read" with "*" in the token (scope escalation attempt).
        let tampered = token.replace(":read:", ":*:");
        let result = validate_token(&tampered, 0, |lid| {
            if *lid == id { Some(pk) } else { None }
        });
        assert!(matches!(result, Err(TokenError::InvalidSignature)));
    }

    #[test]
    fn scope_validation_rejects_typos() {
        let result = TokenScopes::from_strings(vec!["readd".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown scope 'readd'"));
    }

    #[test]
    fn scope_validation_accepts_valid() {
        let result = TokenScopes::from_strings(vec![
            "read".to_string(),
            "write".to_string(),
            "ref:refs/heads/*".to_string(),
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_scopes_decode() {
        let scopes = TokenScopes::decode("");
        assert!(scopes.as_strings().is_empty());
        assert!(!scopes.is_admin());
        assert!(!scopes.allows_read());
    }

    #[test]
    fn admin_permissions_imply_all() {
        use crate::identity::Permissions;
        let admin_only = Permissions(Permissions::ADMIN);
        assert!(admin_only.can_read());
        assert!(admin_only.can_write());
        assert!(admin_only.can_create());
        assert!(admin_only.can_delete());
        assert!(admin_only.is_admin());
    }
}
