//! gRPC auth interceptor — validates bearer tokens on incoming requests.

use std::sync::Arc;
use tonic::{Request, Status};
use gritgrub_core::{IdentityId, validate_token};
use gritgrub_store::Repository;

/// Extension type attached to authenticated requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity(pub IdentityId);

/// Create a tonic interceptor that validates bearer tokens.
///
/// Unauthenticated RPCs (GetObject, HasObject, GetRef, ListRefs, Log,
/// GetChangeset, GetIdentity) are allowed without a token — they're read-only.
/// Write RPCs require a valid token.
pub fn auth_interceptor(
    repo: Arc<Repository>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |mut req: Request<()>| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let token = req.metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        match token {
            Some(token_str) => {
                let repo_ref = repo.clone();
                let identity = validate_token(token_str, now, move |id| {
                    repo_ref.get_public_key(id).ok().flatten()
                }).map_err(|e| Status::unauthenticated(format!("invalid token: {}", e)))?;

                req.extensions_mut().insert(AuthenticatedIdentity(identity));
                Ok(req)
            }
            None => {
                // No token — mark as unauthenticated. Individual RPCs decide
                // whether to allow or reject.
                Ok(req)
            }
        }
    }
}

/// Extract the authenticated identity from a request, or return UNAUTHENTICATED.
pub fn require_auth<T>(req: &Request<T>) -> Result<IdentityId, Status> {
    req.extensions()
        .get::<AuthenticatedIdentity>()
        .map(|a| a.0)
        .ok_or_else(|| Status::unauthenticated("authentication required — pass Bearer token in authorization metadata"))
}

/// Extract the authenticated identity if present, or return None for read-only ops.
pub fn optional_auth<T>(req: &Request<T>) -> Option<IdentityId> {
    req.extensions()
        .get::<AuthenticatedIdentity>()
        .map(|a| a.0)
}
