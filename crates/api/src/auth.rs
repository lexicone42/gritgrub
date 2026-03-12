//! gRPC auth interceptor — validates bearer tokens, checks revocation,
//! and enforces rate limits. Token scopes are attached for per-RPC checks.

use std::sync::Arc;
use tonic::{Request, Status};
use gritgrub_core::{IdentityId, TokenScopes, validate_token};
use gritgrub_store::Repository;
use crate::rate_limit::RateLimiter;

/// Extension type attached to authenticated requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedRequest {
    pub identity: IdentityId,
    pub scopes: TokenScopes,
}

/// Create a tonic interceptor that validates bearer tokens, checks revocation,
/// and enforces rate limits.
///
/// When `require_auth_for_reads` is true, all RPCs require a token.
/// Otherwise, read RPCs work without auth (write RPCs are checked per-RPC
/// via `require_scope`).
pub fn auth_interceptor(
    repo: Arc<Repository>,
    rate_limiter: Arc<RateLimiter>,
    require_auth_for_reads: bool,
    max_token_lifetime_hours: u64,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |mut req: Request<()>| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let token_str = req.metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        let identity = match &token_str {
            Some(token) => {
                // Check revocation list.
                if repo.is_token_revoked(token).unwrap_or(false) {
                    return Err(Status::unauthenticated("token has been revoked"));
                }

                let repo_ref = repo.clone();
                let validated = validate_token(token, now, move |id| {
                    repo_ref.get_public_key(id).ok().flatten()
                }).map_err(|e| Status::unauthenticated(format!("invalid token: {}", e)))?;

                // Enforce max token lifetime (SE-1): reject tokens with too much
                // remaining lifetime. This caps the damage window of stolen tokens.
                if max_token_lifetime_hours > 0 && validated.expiry_micros != 0 {
                    let max_remaining_micros = max_token_lifetime_hours as i64 * 3_600_000_000;
                    let remaining = validated.expiry_micros - now;
                    if remaining > max_remaining_micros {
                        return Err(Status::unauthenticated(format!(
                            "token lifetime exceeds server maximum of {}h — generate a shorter-lived token",
                            max_token_lifetime_hours
                        )));
                    }
                }

                // Non-expiring tokens rejected when max_token_lifetime_hours is set.
                if max_token_lifetime_hours > 0 && validated.expiry_micros == 0 {
                    return Err(Status::unauthenticated(
                        "non-expiring tokens are not allowed by this server — generate a token with --expiry-hours"
                    ));
                }

                req.extensions_mut().insert(AuthenticatedRequest {
                    identity: validated.identity,
                    scopes: validated.scopes,
                });
                Some(validated.identity)
            }
            None => {
                // SE-2: enforce require_auth_for_reads.
                if require_auth_for_reads {
                    return Err(Status::unauthenticated(
                        "authentication required — pass Bearer token in authorization metadata"
                    ));
                }
                None
            }
        };

        // Rate limit check.
        let check = rate_limiter.check(identity);
        if !check.allowed {
            return Err(Status::resource_exhausted(format!(
                "rate limit exceeded — retry in {}s", check.reset_secs
            )));
        }

        // Attach rate info as metadata so agents can self-throttle.
        if let Ok(v) = check.remaining.to_string().parse() {
            req.metadata_mut().insert("x-ratelimit-remaining", v);
        }
        if let Ok(v) = check.reset_secs.to_string().parse() {
            req.metadata_mut().insert("x-ratelimit-reset", v);
        }

        Ok(req)
    }
}

/// Extract authenticated identity from a request, or return UNAUTHENTICATED.
pub fn require_auth<T>(req: &Request<T>) -> Result<IdentityId, Status> {
    req.extensions()
        .get::<AuthenticatedRequest>()
        .map(|a| a.identity)
        .ok_or_else(|| Status::unauthenticated(
            "authentication required — pass Bearer token in authorization metadata"
        ))
}

/// Extract the full auth context (identity + scopes) if present.
pub fn require_auth_with_scopes<T>(req: &Request<T>) -> Result<&AuthenticatedRequest, Status> {
    req.extensions()
        .get::<AuthenticatedRequest>()
        .ok_or_else(|| Status::unauthenticated(
            "authentication required — pass Bearer token in authorization metadata"
        ))
}

/// Extract the authenticated identity if present, or return None for read-only ops.
pub fn optional_auth<T>(req: &Request<T>) -> Option<IdentityId> {
    req.extensions()
        .get::<AuthenticatedRequest>()
        .map(|a| a.identity)
}

/// Check that the token has a required scope, returning a clear error if not.
pub fn require_scope<T>(req: &Request<T>, check: impl FnOnce(&TokenScopes) -> bool, scope_name: &str) -> Result<IdentityId, Status> {
    let auth = require_auth_with_scopes(req)?;
    if check(&auth.scopes) {
        Ok(auth.identity)
    } else {
        Err(Status::permission_denied(format!(
            "token lacks required scope '{}' — generate a new token with this scope",
            scope_name
        )))
    }
}
