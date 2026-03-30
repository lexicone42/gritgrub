//! Capability tokens v3 — Macaroon-inspired, zero-lookup auth.
//!
//! # Design
//!
//! A capability token is a chain of HMAC'd caveats that encode permissions
//! directly in the token. Verification is a single HMAC computation with
//! the server's secret key — no database lookups, no public key retrieval,
//! no revocation table check.
//!
//! # Why this is better for agents
//!
//! Traditional auth:
//! ```text
//! request → parse token → DB lookup (public key) → Ed25519 verify
//!         → DB lookup (revocation) → check scopes = ~120μs, 2 DB reads
//! ```
//!
//! Capability tokens:
//! ```text
//! request → parse token → HMAC verify (in-memory secret) → check caveats
//!         = ~5μs, 0 DB reads
//! ```
//!
//! # How delegation works
//!
//! An admin creates a root token with broad permissions. They can add
//! "caveats" that restrict the token — scopes, ref patterns, expiry,
//! identity binding. Each caveat is chained into the HMAC, so removing
//! a caveat invalidates the token.
//!
//! The critical property: **caveats can only be added, never removed**.
//! An agent can attenuate its own token (narrow permissions) and hand
//! the result to a sub-agent, without contacting the server. The sub-agent
//! can verify the token and further attenuate it.
//!
//! ```text
//! Admin token:        HMAC(secret, "root")
//! + caveat "scope=*": HMAC(previous, "scope=*")
//! + caveat "ttl=5m":  HMAC(previous, "ttl=5m")
//!
//! Agent attenuates:
//! + caveat "scope=read,write":  HMAC(previous, "scope=read,write")
//! + caveat "ref=refs/explore/abc/*": HMAC(previous, "ref=refs/explore/abc/*")
//!
//! Sub-agent can further narrow but never broaden.
//! ```
//!
//! # Why short TTL eliminates revocation
//!
//! With a 5-minute TTL, a stolen token is usable for at most 5 minutes.
//! The agent refreshes by requesting a new token from the server — if the
//! identity has been revoked, the refresh fails. No per-request revocation
//! check needed.

use serde::{Serialize, Deserialize};
use crate::identity::IdentityId;

/// Default TTL for capability tokens: 5 minutes.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// A capability token — self-describing, HMAC-chained, delegatable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// The identity this token was issued to.
    pub identity: IdentityId,
    /// Ordered list of caveats (restrictions). Can only grow, never shrink.
    pub caveats: Vec<Caveat>,
    /// HMAC signature over the identity + all caveats.
    /// Computed as: HMAC(HMAC(HMAC(secret, identity), caveat[0]), caveat[1])...
    pub signature: [u8; 32],
}

/// A restriction on what the token allows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Caveat {
    /// Token expires at this Unix timestamp (microseconds).
    Expiry(i64),
    /// Allowed scopes (e.g., ["read", "write", "attest"]).
    Scopes(Vec<String>),
    /// Ref pattern restriction (glob). Only refs matching this pattern are accessible.
    RefPattern(String),
    /// Goal restriction. Token only valid for operations on this goal.
    GoalId(String),
    /// Maximum number of operations (rate limit embedded in token).
    MaxOps(u32),
    /// Bind to a specific IP address (prevent token theft across networks).
    SourceIP(String),
}

impl CapabilityToken {
    /// Create a new root token for an identity.
    /// Only the server can create root tokens (requires the server secret).
    pub fn mint(identity: IdentityId, server_secret: &[u8; 32]) -> Self {
        let sig = hmac_step(server_secret, identity.as_bytes().as_slice());
        Self {
            identity,
            caveats: vec![],
            signature: sig,
        }
    }

    /// Add a caveat (restriction). This narrows the token's permissions.
    /// Anyone holding the token can add caveats — no server contact needed.
    pub fn attenuate(&mut self, caveat: Caveat) {
        let caveat_bytes = serde_json::to_vec(&caveat).unwrap_or_default();
        self.signature = hmac_step(&self.signature, &caveat_bytes);
        self.caveats.push(caveat);
    }

    /// Add a caveat and return self (builder pattern).
    pub fn with_caveat(mut self, caveat: Caveat) -> Self {
        self.attenuate(caveat);
        self
    }

    /// Verify this token against a server secret.
    /// Recomputes the HMAC chain from scratch and compares.
    pub fn verify(&self, server_secret: &[u8; 32]) -> bool {
        let mut sig = hmac_step(server_secret, self.identity.as_bytes().as_slice());
        for caveat in &self.caveats {
            let caveat_bytes = serde_json::to_vec(caveat).unwrap_or_default();
            sig = hmac_step(&sig, &caveat_bytes);
        }
        constant_time_eq(&sig, &self.signature)
    }

    /// Check if the token is expired.
    pub fn is_expired(&self, now_micros: i64) -> bool {
        for caveat in &self.caveats {
            if let Caveat::Expiry(exp) = caveat
                && now_micros > *exp {
                    return true;
                }
        }
        // No expiry caveat = never expires (but the server should always add one).
        false
    }

    /// Check if the token allows a specific scope.
    /// Intersects ALL scope caveats — each one can only narrow, never broaden.
    pub fn allows_scope(&self, scope: &str) -> bool {
        let scope_caveats: Vec<_> = self.caveats.iter()
            .filter_map(|c| if let Caveat::Scopes(s) = c { Some(s) } else { None })
            .collect();
        if scope_caveats.is_empty() {
            return true; // No scope restriction = root token.
        }
        // EVERY scope caveat must allow this scope (intersection).
        scope_caveats.iter().all(|scopes| {
            scopes.iter().any(|s| s == "*" || s == scope)
        })
    }

    /// Check if the token allows access to a specific ref.
    /// Intersects ALL ref pattern caveats.
    pub fn allows_ref(&self, ref_name: &str) -> bool {
        let ref_caveats: Vec<_> = self.caveats.iter()
            .filter_map(|c| if let Caveat::RefPattern(p) = c { Some(p.as_str()) } else { None })
            .collect();
        if ref_caveats.is_empty() {
            return true; // No ref restriction = all refs.
        }
        // EVERY ref caveat must match (intersection).
        ref_caveats.iter().all(|pattern| {
            crate::policy::glob_match_ref(pattern, ref_name)
        })
    }

    /// Check if the token is restricted to a specific goal.
    pub fn goal_restriction(&self) -> Option<&str> {
        for caveat in &self.caveats {
            if let Caveat::GoalId(gid) = caveat {
                return Some(gid);
            }
        }
        None
    }

    /// Serialize to a compact string for use as a Bearer token.
    /// Format: `forge-v3:<base64url-encoded-json>`
    pub fn encode(&self) -> String {
        use base64::Engine;
        let json = serde_json::to_vec(self).unwrap_or_default();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);
        format!("forge-v3:{}", b64)
    }

    /// Parse from a Bearer token string.
    pub fn decode(s: &str) -> Result<Self, String> {
        use base64::Engine;
        let b64 = s.strip_prefix("forge-v3:")
            .ok_or_else(|| "not a v3 token".to_string())?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64)
            .map_err(|e| format!("invalid base64: {}", e))?;
        serde_json::from_slice(&json)
            .map_err(|e| format!("invalid token JSON: {}", e))
    }
}

/// HMAC-BLAKE3: use BLAKE3 keyed hash as HMAC.
/// BLAKE3's keyed mode is specifically designed for this — it's a PRF
/// that takes a 32-byte key and arbitrary input, producing a 32-byte output.
fn hmac_step(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        *blake3::hash(b"test-server-secret").as_bytes()
    }

    #[test]
    fn mint_and_verify() {
        let secret = test_secret();
        let id = IdentityId::new();
        let token = CapabilityToken::mint(id, &secret);
        assert!(token.verify(&secret));
    }

    #[test]
    fn wrong_secret_fails() {
        let secret = test_secret();
        let wrong = *blake3::hash(b"wrong-secret").as_bytes();
        let id = IdentityId::new();
        let token = CapabilityToken::mint(id, &secret);
        assert!(!token.verify(&wrong));
    }

    #[test]
    fn attenuate_preserves_validity() {
        let secret = test_secret();
        let id = IdentityId::new();
        let token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["read".into(), "write".into()]))
            .with_caveat(Caveat::Expiry(i64::MAX));
        assert!(token.verify(&secret));
    }

    #[test]
    fn tampered_caveat_fails() {
        let secret = test_secret();
        let id = IdentityId::new();
        let mut token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["read".into()]));

        // Tamper: change scope to admin.
        token.caveats[0] = Caveat::Scopes(vec!["*".into()]);
        assert!(!token.verify(&secret), "tampered token should fail verification");
    }

    #[test]
    fn removed_caveat_fails() {
        let secret = test_secret();
        let id = IdentityId::new();
        let mut token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["read".into()]))
            .with_caveat(Caveat::Expiry(i64::MAX));

        // Remove a caveat.
        token.caveats.pop();
        assert!(!token.verify(&secret), "removing a caveat should fail");
    }

    #[test]
    fn expiry_check() {
        let secret = test_secret();
        let id = IdentityId::new();
        let past = 1_000_000i64;
        let future = i64::MAX;

        let expired = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Expiry(past));
        assert!(expired.is_expired(2_000_000));

        let valid = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Expiry(future));
        assert!(!valid.is_expired(2_000_000));
    }

    #[test]
    fn scope_restriction() {
        let secret = test_secret();
        let id = IdentityId::new();
        let token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["read".into(), "write".into()]));

        assert!(token.allows_scope("read"));
        assert!(token.allows_scope("write"));
        assert!(!token.allows_scope("admin"));
        assert!(!token.allows_scope("identity"));
    }

    #[test]
    fn admin_scope_allows_all() {
        let secret = test_secret();
        let id = IdentityId::new();
        let token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["*".into()]));

        assert!(token.allows_scope("read"));
        assert!(token.allows_scope("write"));
        assert!(token.allows_scope("anything"));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let secret = test_secret();
        let id = IdentityId::new();
        let token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["read".into()]))
            .with_caveat(Caveat::Expiry(i64::MAX));

        let encoded = token.encode();
        assert!(encoded.starts_with("forge-v3:"));

        let decoded = CapabilityToken::decode(&encoded).unwrap();
        assert!(decoded.verify(&secret));
        assert_eq!(decoded.identity, id);
        assert_eq!(decoded.caveats.len(), 2);
    }

    #[test]
    fn delegation_by_attenuation() {
        let secret = test_secret();
        let id = IdentityId::new();

        // Admin creates broad token.
        let admin_token = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["*".into()]))
            .with_caveat(Caveat::Expiry(i64::MAX));

        assert!(admin_token.allows_scope("anything"));

        // Agent attenuates for sub-agent (no server contact needed).
        let mut sub_token = admin_token.clone();
        sub_token.attenuate(Caveat::Scopes(vec!["read".into(), "write".into()]));
        sub_token.attenuate(Caveat::RefPattern("refs/explore/abc/*".into()));

        // Sub-token is still valid (same HMAC chain).
        assert!(sub_token.verify(&secret));

        // Sub-token has narrower permissions (intersection of all scope caveats).
        assert!(sub_token.allows_scope("read"));
        assert!(sub_token.allows_scope("write"));
        assert!(!sub_token.allows_scope("identity"), "attenuated token should not allow identity scope");

        // Ref pattern is restricted.
        assert!(sub_token.allows_ref("refs/explore/abc/approach-0"));
        assert!(!sub_token.allows_ref("refs/heads/main"), "attenuated token should not allow main");
    }

    #[test]
    fn sub_agent_cannot_escalate() {
        let secret = test_secret();
        let id = IdentityId::new();

        let restricted = CapabilityToken::mint(id, &secret)
            .with_caveat(Caveat::Scopes(vec!["read".into()]));

        // Sub-agent tries to add broader scope — it adds the caveat
        // but the intersection still restricts to "read".
        let mut escalated = restricted.clone();
        escalated.attenuate(Caveat::Scopes(vec!["*".into()]));

        // Token is valid (HMAC chain is correct).
        assert!(escalated.verify(&secret));

        // But permissions are the intersection: read AND * = read.
        assert!(escalated.allows_scope("read"));
        assert!(!escalated.allows_scope("write"), "escalation should fail: intersection of ['read'] and ['*'] = ['read']");
    }
}
