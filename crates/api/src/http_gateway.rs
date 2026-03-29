//! HTTP/JSON REST gateway — maps REST endpoints to the Repository layer.
//!
//! Provides a JSON API alongside gRPC for browser clients, webhooks,
//! and tools that don't speak protobuf.
//!
//! All auth uses the same Bearer token scheme as gRPC.

use std::sync::Arc;
use std::convert::Infallible;
use tokio::sync::Notify;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Method},
    response::{Html, Json, Sse},
    routing::{get, post},
};
use axum::response::sse::{Event as SseEvent, KeepAlive};
use tower_http::cors::{CorsLayer, Any};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use gritgrub_core::*;
use gritgrub_store::Repository;
use crate::rate_limit::RateLimiter;

/// Hard cap on log entries for HTTP queries.
const MAX_LOG_ENTRIES: usize = 10_000;

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    pub repo: Arc<Repository>,
    pub rate_limiter: Arc<RateLimiter>,
    pub require_auth_for_reads: bool,
    pub max_token_lifetime_hours: u64,
    /// Maximum object size in bytes (prevents disk exhaustion via HTTP uploads).
    pub max_object_size: usize,
    /// Allowed CORS origins (empty = allow all for development).
    pub cors_origins: Vec<String>,
    /// Notification channel for push-based SSE. Handlers call notify_waiters()
    /// after mutations so the SSE stream wakes up immediately.
    pub event_notify: Arc<Notify>,
}

/// Build the axum Router for the HTTP/JSON gateway.
pub fn router(state: HttpState) -> Router {
    Router::new()
        // Health
        .route("/health", get(health))
        // Objects
        .route("/api/v1/objects/{id}", get(get_object))
        .route("/api/v1/objects", post(put_object))
        // Refs
        .route("/api/v1/refs", get(list_refs))
        .route("/api/v1/refs/{name}", get(get_ref))
        .route("/api/v1/refs/{name}", post(set_ref))
        // Changesets
        .route("/api/v1/log", get(log))
        .route("/api/v1/changesets/{id}", get(get_changeset))
        // Branches
        .route("/api/v1/branches", get(list_branches))
        // Identity
        .route("/api/v1/identities/{id}", get(get_identity))
        // Status / info
        .route("/api/v1/status", get(repo_status))
        // Exploration tree
        .route("/api/v1/explore/goals", get(list_goals))
        .route("/api/v1/explore/goals/{id}", get(get_goal))
        // Pipeline results
        .route("/api/v1/pipeline/{id}", get(get_pipeline_results))
        // Server-Sent Events
        .route("/api/v1/events", get(sse_events))
        // Provisioning (create agents via HTTP)
        .route("/api/v1/provision", post(provision_agent))
        .route("/api/v1/provision/batch", post(provision_batch))
        // Overview (everything the dashboard needs in one request)
        .route("/api/v1/overview", get(overview))
        // Exploration actions
        .route("/api/v1/explore/goals", post(create_goal))
        // Dashboard
        .route("/", get(dashboard))
        // CORS — configurable origins for production, allow all for development.
        .layer({
            let cors = CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any);
            if state.cors_origins.is_empty() {
                cors.allow_origin(Any)
            } else {
                let origins: Vec<_> = state.cors_origins.iter()
                    .filter_map(|o| o.parse().ok())
                    .collect();
                cors.allow_origin(origins)
            }
        })
        .with_state(state)
}

// ── Auth helpers ───────────────────────────────────────────────────

fn extract_token(headers: &HeaderMap) -> Option<String> {
    headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn validate_request(
    state: &HttpState,
    headers: &HeaderMap,
    require_write: bool,
) -> Result<Option<(IdentityId, TokenScopes)>, (StatusCode, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "system clock error".to_string()))?
        .as_micros() as i64;

    let token_str = extract_token(headers);

    match token_str {
        Some(ref token) => {
            if state.repo.is_token_revoked(token).unwrap_or(false) {
                return Err((StatusCode::UNAUTHORIZED, "token has been revoked".into()));
            }

            let repo_ref = state.repo.clone();
            let validated = validate_token(token, now, move |id| {
                repo_ref.get_public_key(id).ok().flatten()
            }).map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {}", e)))?;

            if state.max_token_lifetime_hours > 0 && validated.expiry_micros != 0 {
                let max_remaining = state.max_token_lifetime_hours as i64 * 3_600_000_000;
                let remaining = validated.expiry_micros - now;
                if remaining > max_remaining {
                    return Err((StatusCode::UNAUTHORIZED, format!(
                        "token lifetime exceeds server maximum of {}h",
                        state.max_token_lifetime_hours
                    )));
                }
            }

            if state.max_token_lifetime_hours > 0 && validated.expiry_micros == 0 {
                return Err((StatusCode::UNAUTHORIZED,
                    "non-expiring tokens not allowed".into()));
            }

            // Rate limit.
            let check = state.rate_limiter.check(Some(validated.identity));
            if !check.allowed {
                return Err((StatusCode::TOO_MANY_REQUESTS,
                    format!("rate limit exceeded — retry in {}s", check.reset_secs)));
            }

            Ok(Some((validated.identity, validated.scopes)))
        }
        None => {
            if require_write || state.require_auth_for_reads {
                return Err((StatusCode::UNAUTHORIZED,
                    "authentication required — pass Bearer token in Authorization header".into()));
            }

            let check = state.rate_limiter.check(None);
            if !check.allowed {
                return Err((StatusCode::TOO_MANY_REQUESTS,
                    format!("rate limit exceeded — retry in {}s", check.reset_secs)));
            }

            Ok(None)
        }
    }
}

// ── Response types ─────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize)]
struct ObjectResponse {
    id: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tree: Option<TreeResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    changeset: Option<ChangesetResponse>,
}

#[derive(Serialize)]
struct TreeResponse {
    entries: Vec<TreeEntryResponse>,
}

#[derive(Serialize)]
struct TreeEntryResponse {
    name: String,
    id: String,
    kind: String,
    executable: bool,
}

#[derive(Serialize, Clone)]
struct ChangesetResponse {
    id: String,
    parents: Vec<String>,
    tree: String,
    author: String,
    timestamp: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent: Option<IntentResponse>,
}

#[derive(Serialize, Clone)]
struct IntentResponse {
    kind: String,
    rationale: String,
}

#[derive(Serialize)]
struct RefResponse {
    name: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved: Option<String>,
}

#[derive(Serialize)]
struct BranchResponse {
    name: String,
    head: String,
    current: bool,
}

#[derive(Serialize)]
struct IdentityResponse {
    id: String,
    name: String,
    kind: String,
}

#[derive(Serialize)]
struct StatusResponse {
    branch: Option<String>,
    head: Option<String>,
    changes: Vec<StatusChange>,
}

#[derive(Serialize)]
struct StatusChange {
    path: String,
    status: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default = "default_count")]
    count: usize,
}
fn default_count() -> usize { 20 }

#[derive(Deserialize)]
struct RefsQuery {
    #[serde(default)]
    prefix: String,
}

#[derive(Deserialize)]
struct PutObjectBody {
    kind: String,
    #[serde(default)]
    data_base64: String,
}

#[derive(Deserialize)]
struct SetRefBody {
    kind: String,
    target: String,
}

// ── Handlers ───────────────────────────────────────────────────────

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: msg.into() }))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "serving", service: "forge" })
}

async fn get_object(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_hex): Path<String>,
) -> Result<Json<ObjectResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let id = parse_object_id(&id_hex).map_err(|(s, m)| err(s, m))?;
    let obj = state.repo.get_object(&id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "object not found"))?;

    Ok(Json(object_to_response(&id, &obj)))
}

async fn put_object(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<PutObjectBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let auth = validate_request(&state, &headers, true).map_err(|(s, m)| err(s, m))?;
    let (_, scopes) = auth.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "auth required"))?;
    if !scopes.allows_write() {
        return Err(err(StatusCode::FORBIDDEN, "token lacks write scope"));
    }

    let obj = match body.kind.as_str() {
        "blob" => {
            use base64::Engine;
            let data = base64::engine::general_purpose::STANDARD.decode(&body.data_base64)
                .map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid base64: {}", e)))?;
            if data.len() > state.max_object_size {
                return Err(err(StatusCode::PAYLOAD_TOO_LARGE,
                    format!("object too large: {} bytes (max {})", data.len(), state.max_object_size)));
            }
            Object::Blob(Blob { data })
        }
        _ => return Err(err(StatusCode::BAD_REQUEST, "unsupported object kind for HTTP API")),
    };

    let id = state.repo.put_object(&obj)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.event_notify.notify_waiters();
    Ok(Json(serde_json::json!({ "id": id.to_string() })))
}

async fn list_refs(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<RefsQuery>,
) -> Result<Json<Vec<RefResponse>>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let refs = state.repo.list_refs(&query.prefix)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result: Vec<RefResponse> = refs.into_iter().map(|(name, reference)| {
        ref_to_response(&name, &reference, &state.repo)
    }).collect();

    Ok(Json(result))
}

async fn get_ref(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<RefResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let refs = state.repo.list_refs("")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (_, reference) = refs.into_iter().find(|(n, _)| *n == name)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, format!("ref '{}' not found", name)))?;

    Ok(Json(ref_to_response(&name, &reference, &state.repo)))
}

async fn set_ref(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<SetRefBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Validate ref name: no traversal, no null bytes, reasonable length.
    validate_ref_name(&name).map_err(|msg| err(StatusCode::BAD_REQUEST, msg))?;

    let auth = validate_request(&state, &headers, true).map_err(|(s, m)| err(s, m))?;
    let (_, scopes) = auth.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "auth required"))?;
    if !scopes.allows_write() {
        return Err(err(StatusCode::FORBIDDEN, "token lacks write scope"));
    }
    if !scopes.allows_ref(&name) {
        return Err(err(StatusCode::FORBIDDEN, format!("token lacks scope for ref '{}'", name)));
    }

    let reference = match body.kind.as_str() {
        "direct" => {
            let id = parse_object_id(&body.target).map_err(|(s, m)| err(s, m))?;
            Ref::Direct(id)
        }
        "symbolic" => Ref::Symbolic(body.target),
        _ => return Err(err(StatusCode::BAD_REQUEST, "kind must be 'direct' or 'symbolic'")),
    };

    state.repo.set_ref(&name, &reference)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.event_notify.notify_waiters();
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn log(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<ChangesetResponse>>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let count = query.count.min(MAX_LOG_ENTRIES);
    let entries = state.repo.log(count)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result: Vec<ChangesetResponse> = entries.iter().map(|(id, cs)| {
        changeset_to_response(id, cs)
    }).collect();

    Ok(Json(result))
}

async fn get_changeset(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_hex): Path<String>,
) -> Result<Json<ChangesetResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let (id, obj) = if id_hex.len() == 64 {
        let id = parse_object_id(&id_hex).map_err(|(s, m)| err(s, m))?;
        let obj = state.repo.get_object(&id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        (id, obj)
    } else {
        let (id, obj) = state.repo.find_by_prefix(&id_hex)
            .map_err(|e| err(StatusCode::NOT_FOUND, e.to_string()))?;
        (id, Some(obj))
    };
    match obj {
        Some(Object::Changeset(cs)) => Ok(Json(changeset_to_response(&id, &cs))),
        _ => Err(err(StatusCode::NOT_FOUND, "changeset not found")),
    }
}

async fn list_branches(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BranchResponse>>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let current = state.repo.head_branch()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let refs = state.repo.list_refs("refs/heads/")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let branches: Vec<BranchResponse> = refs.into_iter().map(|(name, reference)| {
        let branch = name.strip_prefix("refs/heads/").unwrap_or(&name).to_string();
        let head = match reference {
            Ref::Direct(id) => id.to_string(),
            Ref::Symbolic(target) => target,
        };
        BranchResponse {
            current: current.as_deref() == Some(branch.as_str()),
            name: branch,
            head,
        }
    }).collect();

    Ok(Json(branches))
}

async fn get_identity(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_str): Path<String>,
) -> Result<Json<IdentityResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let uuid = uuid::Uuid::parse_str(&id_str)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid UUID: {}", e)))?;
    let id = IdentityId::from_bytes(*uuid.as_bytes());

    let ident = state.repo.get_identity(&id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "identity not found"))?;

    Ok(Json(IdentityResponse {
        id: ident.id.to_string(),
        name: ident.name,
        kind: match ident.kind {
            IdentityKind::Human => "human".into(),
            IdentityKind::Agent { runtime } => format!("agent ({})", runtime),
        },
    }))
}

async fn repo_status(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let branch = state.repo.head_branch()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let head = state.repo.resolve_head()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map(|id| id.to_string());

    Ok(Json(StatusResponse { branch, head, changes: vec![] }))
}

// ── Conversion helpers ─────────────────────────────────────────────

fn validate_ref_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("ref name cannot be empty".into());
    }
    if name.len() > 256 {
        return Err("ref name too long (max 256 chars)".into());
    }
    if name.contains('\0') {
        return Err("ref name cannot contain null bytes".into());
    }
    if name.contains("..") {
        return Err("ref name cannot contain '..'".into());
    }
    if name.starts_with('/') || name.ends_with('/') {
        return Err("ref name cannot start or end with '/'".into());
    }
    Ok(())
}

fn parse_object_id(hex: &str) -> Result<ObjectId, (StatusCode, String)> {
    if hex.len() != 64 {
        return Err((StatusCode::BAD_REQUEST, "object ID must be 64 hex chars".into()));
    }
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid hex in object ID".into()))?;
    let arr: [u8; 32] = bytes.try_into().unwrap();
    Ok(ObjectId::from_bytes(arr))
}

fn object_to_response(id: &ObjectId, obj: &Object) -> ObjectResponse {
    match obj {
        Object::Blob(blob) => {
            use base64::Engine;
            ObjectResponse {
                id: id.to_string(),
                kind: "blob".into(),
                data_base64: Some(base64::engine::general_purpose::STANDARD.encode(&blob.data)),
                tree: None,
                changeset: None,
            }
        }
        Object::Tree(tree) => {
            let entries = tree.entries.iter().map(|(name, entry)| {
                TreeEntryResponse {
                    name: name.clone(),
                    id: entry.id.to_string(),
                    kind: match entry.kind {
                        EntryKind::File => "file".into(),
                        EntryKind::Directory => "directory".into(),
                        EntryKind::Symlink => "symlink".into(),
                    },
                    executable: entry.executable,
                }
            }).collect();
            ObjectResponse {
                id: id.to_string(),
                kind: "tree".into(),
                data_base64: None,
                tree: Some(TreeResponse { entries }),
                changeset: None,
            }
        }
        Object::Changeset(cs) => ObjectResponse {
            id: id.to_string(),
            kind: "changeset".into(),
            data_base64: None,
            tree: None,
            changeset: Some(changeset_to_response(id, cs)),
        },
        Object::Envelope(env) => {
            use base64::Engine;
            ObjectResponse {
                id: id.to_string(),
                kind: "envelope".into(),
                data_base64: Some(base64::engine::general_purpose::STANDARD.encode(&env.payload)),
                tree: None,
                changeset: None,
            }
        }
    }
}

fn changeset_to_response(id: &ObjectId, cs: &Changeset) -> ChangesetResponse {
    ChangesetResponse {
        id: id.to_string(),
        parents: cs.parents.iter().map(|p| p.to_string()).collect(),
        tree: cs.tree.to_string(),
        author: cs.author.to_string(),
        timestamp: cs.timestamp,
        message: cs.message.clone(),
        intent: cs.intent.as_ref().map(|i| IntentResponse {
            kind: format!("{}", i.kind),
            rationale: i.rationale.clone(),
        }),
    }
}

// ── Exploration endpoints ──────────────────────────────────────

#[derive(Serialize)]
struct GoalResponse {
    id: String,
    description: String,
    target_branch: String,
    approaches: Vec<ApproachResponse>,
    claims: Vec<ClaimResponse>,
    promoted: Option<String>,
    constraints: Vec<ConstraintResponse>,
}

#[derive(Serialize)]
struct ApproachResponse {
    name: String,
    tip: Option<String>,
    changeset_count: usize,
    latest_message: Option<String>,
    created_by: Option<String>,
    verification: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    agent: String,
    approach: String,
    intent: String,
    heartbeat: u64,
}

#[derive(Serialize)]
struct ConstraintResponse {
    kind: String,
    description: String,
}

#[derive(Serialize)]
struct PipelineResponse {
    pipeline: String,
    changeset: String,
    passed: bool,
    duration_ms: u64,
    runner: String,
    stages: Vec<StageResponse>,
}

#[derive(Serialize)]
struct StageResponse {
    name: String,
    passed: bool,
    duration_ms: u64,
    summary: String,
    tests_passed: u32,
    tests_failed: u32,
    warnings: u32,
    required: bool,
}

async fn list_goals(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<GoalResponse>>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let goals = state.repo.list_goals()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut result = Vec::new();
    for (goal_id, _goal) in &goals {
        let summary = state.repo.goal_summary(goal_id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        result.push(goal_summary_to_response(&summary));
    }
    Ok(Json(result))
}

async fn get_goal(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_prefix): Path<String>,
) -> Result<Json<GoalResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let goals = state.repo.list_goals()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let matched: Vec<_> = goals.iter()
        .filter(|(id, _)| id.to_hex().starts_with(&id_prefix))
        .collect();

    match matched.len() {
        0 => Err(err(StatusCode::NOT_FOUND, format!("no goal matching '{}'", id_prefix))),
        1 => {
            let summary = state.repo.goal_summary(&matched[0].0)
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(Json(goal_summary_to_response(&summary)))
        }
        n => Err(err(StatusCode::BAD_REQUEST, format!("ambiguous prefix '{}': {} matches", id_prefix, n))),
    }
}

fn goal_summary_to_response(s: &GoalSummary) -> GoalResponse {
    GoalResponse {
        id: s.goal_id.to_hex()[..16].to_string(),
        description: s.goal.description.clone(),
        target_branch: s.goal.target_branch.clone(),
        approaches: s.approaches.iter().map(|a| ApproachResponse {
            name: a.name.clone(),
            tip: a.tip.map(|id| id.to_hex()[..12].to_string()),
            changeset_count: a.changeset_count,
            latest_message: a.latest_message.clone(),
            created_by: a.created_by.map(|id| id.to_string()),
            verification: format!("{}", a.verification),
        }).collect(),
        claims: s.claims.iter().map(|c| ClaimResponse {
            agent: c.agent.to_string(),
            approach: c.approach.clone(),
            intent: c.intent.clone(),
            heartbeat: c.heartbeat,
        }).collect(),
        promoted: s.promoted.clone(),
        constraints: s.goal.constraints.iter().map(|c| ConstraintResponse {
            kind: format!("{:?}", c.kind),
            description: c.description.clone(),
        }).collect(),
    }
}

async fn get_pipeline_results(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id_hex): Path<String>,
) -> Result<Json<Vec<PipelineResponse>>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    // Accept both full 64-char hex IDs and short prefixes.
    let id = if id_hex.len() == 64 {
        parse_object_id(&id_hex).map_err(|(s, m)| err(s, m))?
    } else {
        let (found_id, _) = state.repo.find_by_prefix(&id_hex)
            .map_err(|e| err(StatusCode::NOT_FOUND, e.to_string()))?;
        found_id
    };
    let results = state.repo.get_pipeline_results(&id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<PipelineResponse> = results.iter().map(|r| PipelineResponse {
        pipeline: r.pipeline.clone(),
        changeset: r.changeset.to_hex()[..12].to_string(),
        passed: r.passed,
        duration_ms: r.duration_ms,
        runner: r.runner.to_string(),
        stages: r.stages.iter().map(|s| StageResponse {
            name: s.name.clone(),
            passed: s.passed,
            duration_ms: s.duration_ms,
            summary: s.summary.clone(),
            tests_passed: s.tests_passed,
            tests_failed: s.tests_failed,
            warnings: s.warnings,
            required: s.required,
        }).collect(),
    }).collect();

    Ok(Json(response))
}

// ── Server-Sent Events ────────────────────────────────────────

async fn sse_events(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, (StatusCode, Json<ErrorResponse>)> {
    // SSE requires auth when require_auth_for_reads is enabled.
    // Even without auth, rate-limit connections.
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let repo = state.repo.clone();
    let notify = state.event_notify.clone();
    let stream = async_stream::stream! {
        // Start from latest event.
        let mut seq = repo.latest_event_seq().unwrap_or(0);
        loop {
            match repo.read_events(seq + 1, 10) {
                Ok(events) if !events.is_empty() => {
                    for (event_seq, data) in events {
                        seq = event_seq;
                        let json = String::from_utf8_lossy(&data).to_string();
                        yield Ok(SseEvent::default().data(json).id(event_seq.to_string()));
                    }
                }
                _ => {
                    // Wait for a mutation notification, or fall back to polling
                    // every 5 seconds as a safety net.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        notify.notified(),
                    ).await;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ── Overview endpoint ──────────────────────────────────────────

#[derive(Serialize)]
struct OverviewResponse {
    branch: Option<String>,
    head: Option<String>,
    changesets: Vec<ChangesetResponse>,
    branches: Vec<BranchResponse>,
    goals: Vec<GoalResponse>,
    pipeline: Vec<PipelineResponse>,
}

async fn overview(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<OverviewResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_request(&state, &headers, false).map_err(|(s, m)| err(s, m))?;

    let branch = state.repo.head_branch()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let head = state.repo.resolve_head()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let entries = state.repo.log(8)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let changesets: Vec<ChangesetResponse> = entries.iter()
        .map(|(id, cs)| changeset_to_response(id, cs))
        .collect();

    let refs = state.repo.list_refs("refs/heads/")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let branches: Vec<BranchResponse> = refs.into_iter().map(|(name, reference)| {
        let b = name.strip_prefix("refs/heads/").unwrap_or(&name).to_string();
        let h = match reference {
            Ref::Direct(id) => id.to_string(),
            Ref::Symbolic(target) => target,
        };
        BranchResponse {
            current: branch.as_deref() == Some(b.as_str()),
            name: b,
            head: h,
        }
    }).collect();

    let goal_list = state.repo.list_goals()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut goals = Vec::new();
    for (goal_id, _) in goal_list.iter().take(50) { // Cap at 50 goals for overview.
        if let Ok(summary) = state.repo.goal_summary(goal_id) {
            goals.push(goal_summary_to_response(&summary));
        }
    }

    let pipeline = if let Some(ref head_id) = head {
        state.repo.get_pipeline_results(head_id)
            .unwrap_or_default()
            .iter()
            .map(|r| PipelineResponse {
                pipeline: r.pipeline.clone(),
                changeset: r.changeset.to_hex()[..12].to_string(),
                passed: r.passed,
                duration_ms: r.duration_ms,
                runner: r.runner.to_string(),
                stages: r.stages.iter().map(|s| StageResponse {
                    name: s.name.clone(),
                    passed: s.passed,
                    duration_ms: s.duration_ms,
                    summary: s.summary.clone(),
                    tests_passed: s.tests_passed,
                    tests_failed: s.tests_failed,
                    warnings: s.warnings,
                    required: s.required,
                }).collect(),
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(OverviewResponse {
        branch,
        head: head.map(|id| id.to_string()),
        changesets,
        branches,
        goals,
        pipeline,
    }))
}

// ── Provisioning endpoints ────────────────────────────────────

#[derive(Deserialize)]
struct ProvisionRequest {
    /// Agent display name (auto-generated if omitted).
    #[serde(default)]
    name: String,
    /// Agent runtime (e.g., "claude-code").
    #[serde(default = "default_runtime")]
    runtime: String,
    /// Token expiry in hours (default 24).
    #[serde(default = "default_expiry")]
    expiry_hours: u64,
    /// Token scopes (default "read,write,attest").
    #[serde(default = "default_scope")]
    scope: String,
    /// Goal ID prefix to assign (optional).
    #[serde(default)]
    goal_id: Option<String>,
    /// Approach name (defaults to agent name).
    #[serde(default)]
    approach: Option<String>,
}

fn default_runtime() -> String { "claude-code".into() }
fn default_expiry() -> u64 { 24 }
fn default_scope() -> String { "read,write,attest".into() }

#[derive(Serialize)]
struct ProvisionResponse {
    identity: String,
    name: String,
    token: String,
    scopes: Vec<String>,
    expires_in_hours: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    goal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approach: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    branch: Option<String>,
}

async fn provision_agent(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Provisioning requires admin auth.
    let auth = validate_request(&state, &headers, true).map_err(|(s, m)| err(s, m))?;
    let (_, scopes) = auth.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "auth required"))?;
    if !scopes.allows_identity() {
        return Err(err(StatusCode::FORBIDDEN, "token lacks identity scope — provisioning requires admin or identity scope"));
    }

    let agent_name = if body.name.is_empty() {
        format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8])
    } else {
        body.name
    };

    // Create identity.
    let identity = state.repo.create_identity(
        &agent_name,
        IdentityKind::Agent { runtime: body.runtime },
    ).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Grant capabilities.
    state.repo.grant_capabilities(&identity.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions::read_write(),
        expires_at: None,
    }]).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Generate keypair.
    state.repo.generate_keypair(&identity.id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Generate token.
    let kp = state.repo.load_keypair(&identity.id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "clock error"))?
        .as_micros() as i64;
    let clamped_hours = body.expiry_hours.min(8760) as i64; // Max 1 year
    let expiry = now + (clamped_hours * 3_600_000_000);
    let token_scopes = TokenScopes::decode(&body.scope);
    let token = generate_token_v2(identity.id, &kp.signing_key, expiry, &token_scopes);

    // Optionally claim exploration approach.
    let (goal_out, approach_out, branch_out) = if let Some(ref gid_prefix) = body.goal_id {
        let goals = state.repo.list_goals()
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let matched: Vec<_> = goals.iter()
            .filter(|(id, _)| id.to_hex().starts_with(gid_prefix))
            .collect();
        if matched.is_empty() {
            return Err(err(StatusCode::NOT_FOUND, format!("no goal matching '{}'", gid_prefix)));
        }
        let (gid, _) = matched[0];
        let approach = body.approach.unwrap_or_else(|| agent_name.clone());
        match state.repo.create_approach(gid, &approach, identity.id) {
            Ok(ref_name) => (Some(gid.to_hex()[..16].to_string()), Some(approach), Some(ref_name)),
            Err(e) => return Err(err(StatusCode::CONFLICT, format!("could not claim approach: {}", e))),
        }
    } else {
        (None, None, None)
    };

    state.event_notify.notify_waiters();
    Ok(Json(ProvisionResponse {
        identity: identity.id.to_string(),
        name: agent_name,
        token,
        scopes: token_scopes.as_strings().to_vec(),
        expires_in_hours: body.expiry_hours,
        goal_id: goal_out,
        approach: approach_out,
        branch: branch_out,
    }))
}

#[derive(Deserialize)]
struct BatchProvisionRequest {
    count: usize,
    #[serde(default = "default_runtime")]
    runtime: String,
    #[serde(default = "default_expiry")]
    expiry_hours: u64,
    goal_id: String,
}

async fn provision_batch(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BatchProvisionRequest>,
) -> Result<Json<Vec<ProvisionResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let auth = validate_request(&state, &headers, true).map_err(|(s, m)| err(s, m))?;
    let (_, scopes) = auth.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "auth required"))?;
    if !scopes.allows_identity() {
        return Err(err(StatusCode::FORBIDDEN, "token lacks identity scope"));
    }

    if body.count == 0 || body.count > 100 {
        return Err(err(StatusCode::BAD_REQUEST, "count must be 1-100"));
    }

    // Find goal (require unique match to prevent wrong-goal assignment).
    let goals = state.repo.list_goals()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let matched: Vec<_> = goals.iter()
        .filter(|(id, _)| id.to_hex().starts_with(&body.goal_id))
        .collect();
    match matched.len() {
        0 => return Err(err(StatusCode::NOT_FOUND, format!("no goal matching '{}'", body.goal_id))),
        1 => {}
        n => return Err(err(StatusCode::BAD_REQUEST, format!("ambiguous goal prefix '{}': {} matches — use a longer prefix", body.goal_id, n))),
    }
    let (goal_id, _) = matched[0];

    let mut results = Vec::new();
    for i in 0..body.count {
        let agent_name = format!("agent-{}", i);
        let approach_name = format!("approach-{}", i);

        let identity = state.repo.create_identity(
            &agent_name,
            IdentityKind::Agent { runtime: body.runtime.clone() },
        ).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.repo.grant_capabilities(&identity.id, &[Capability {
            scope: CapabilityScope::Global,
            permissions: Permissions::read_write(),
            expires_at: None,
        }]).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.repo.generate_keypair(&identity.id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let kp = state.repo.load_keypair(&identity.id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "clock error"))?
            .as_micros() as i64;
        let clamped_hours = body.expiry_hours.min(8760) as i64; // Max 1 year
    let expiry = now + (clamped_hours * 3_600_000_000);
        let token_scopes = TokenScopes::decode("read,write,attest");
        let token = generate_token_v2(identity.id, &kp.signing_key, expiry, &token_scopes);

        let branch = state.repo.create_approach(goal_id, &approach_name, identity.id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        results.push(ProvisionResponse {
            identity: identity.id.to_string(),
            name: agent_name,
            token,
            scopes: token_scopes.as_strings().to_vec(),
            expires_in_hours: body.expiry_hours,
            goal_id: Some(goal_id.to_hex()[..16].to_string()),
            approach: Some(approach_name),
            branch: Some(branch),
        });
    }

    state.event_notify.notify_waiters();
    Ok(Json(results))
}

// ── Goal creation via HTTP ────────────────────────────────────

#[derive(Deserialize)]
struct CreateGoalRequest {
    description: String,
    #[serde(default = "default_target")]
    target_branch: String,
    #[serde(default)]
    constraints: Vec<CreateConstraint>,
    #[serde(default)]
    max_approaches: u32,
}

fn default_target() -> String { "main".into() }

#[derive(Deserialize)]
struct CreateConstraint {
    kind: String,
    description: String,
}

async fn create_goal(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreateGoalRequest>,
) -> Result<Json<GoalResponse>, (StatusCode, Json<ErrorResponse>)> {
    let auth = validate_request(&state, &headers, true).map_err(|(s, m)| err(s, m))?;
    let (identity, scopes) = auth.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "auth required"))?;
    if !scopes.allows_write() {
        return Err(err(StatusCode::FORBIDDEN, "token lacks write scope"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "clock error"))?
        .as_micros() as i64;

    // Input validation.
    if body.description.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "description is required"));
    }
    if body.description.len() > 10_000 {
        return Err(err(StatusCode::BAD_REQUEST, "description too long (max 10,000 chars)"));
    }

    let constraints: Vec<Constraint> = body.constraints.iter().map(|c| {
        let kind = match c.kind.as_str() {
            "tests" | "TestsPass" => ConstraintKind::TestsPass,
            "lint" | "LintClean" => ConstraintKind::LintClean,
            "frozen" | "PathFrozen" => ConstraintKind::PathFrozen,
            "perf" | "PerformanceBound" => ConstraintKind::PerformanceBound,
            "compat" | "BackwardCompatible" => ConstraintKind::BackwardCompatible,
            _ => ConstraintKind::Custom,
        };
        Constraint { kind, description: c.description.clone(), check_command: None }
    }).collect();

    let goal = Goal {
        description: body.description,
        target_branch: body.target_branch,
        constraints,
        created_by: identity,
        created_at: now,
        max_approaches: body.max_approaches,
        time_budget_secs: 0,
    };

    let goal_id = state.repo.create_goal(&goal)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let summary = state.repo.goal_summary(&goal_id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.event_notify.notify_waiters();
    Ok(Json(goal_summary_to_response(&summary)))
}

// ── Dashboard ─────────────────────────────────────────────────

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

// ── Conversion helpers ─────────────────────────────────────────

fn ref_to_response(name: &str, reference: &Ref, repo: &Repository) -> RefResponse {
    match reference {
        Ref::Direct(id) => RefResponse {
            name: name.to_string(),
            kind: "direct".into(),
            target: Some(id.to_string()),
            resolved: Some(id.to_string()),
        },
        Ref::Symbolic(target) => {
            let resolved = repo.resolve_ref(name).ok().flatten().map(|id| id.to_string());
            RefResponse {
                name: name.to_string(),
                kind: "symbolic".into(),
                target: Some(target.clone()),
                resolved,
            }
        }
    }
}
