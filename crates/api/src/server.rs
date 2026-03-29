use std::collections::BTreeMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tokio_stream::StreamExt;
use gritgrub_core::*;
use gritgrub_store::Repository;
use crate::pb;
use crate::pb::repo_service_server::RepoService;
use crate::auth::{require_scope, require_auth_with_scopes, optional_auth};

/// Default max object size: 128 MB.
const DEFAULT_MAX_OBJECT_SIZE: usize = 128 * 1024 * 1024;

/// Hard cap on log entries to prevent OOM from unbounded queries.
const MAX_LOG_ENTRIES: usize = 10_000;

pub struct RepoServer {
    pub(crate) repo: Arc<Repository>,
    /// Maximum single object size in bytes (prevents disk exhaustion).
    max_object_size: usize,
    /// Whether reads require authentication.
    require_auth_for_reads: bool,
}

impl RepoServer {
    pub fn new(repo: Arc<Repository>) -> Self {
        Self {
            repo,
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
            require_auth_for_reads: false,
        }
    }

    /// Configure the max object size and auth requirements.
    pub fn with_limits(mut self, max_object_size: usize, require_auth_for_reads: bool) -> Self {
        if max_object_size > 0 {
            self.max_object_size = max_object_size;
        }
        self.require_auth_for_reads = require_auth_for_reads;
        self
    }

    pub fn into_service(self) -> pb::repo_service_server::RepoServiceServer<Self> {
        pb::repo_service_server::RepoServiceServer::new(self)
    }
}

// ── Conversion helpers ──────────────────────────────────────────────

fn to_pb_object_id(id: &ObjectId) -> pb::ObjectId {
    pb::ObjectId { hash: id.as_bytes().to_vec() }
}

fn from_pb_object_id(pb_id: &pb::ObjectId) -> Result<ObjectId, Status> {
    let bytes: [u8; 32] = pb_id.hash.as_slice().try_into()
        .map_err(|_| Status::invalid_argument("ObjectId must be 32 bytes"))?;
    Ok(ObjectId::from_bytes(bytes))
}

fn to_status(e: anyhow::Error) -> Status {
    Status::internal(e.to_string())
}

// ── Service implementation ──────────────────────────────────────────

#[tonic::async_trait]
impl RepoService for RepoServer {
    async fn get_object(
        &self,
        request: Request<pb::GetObjectRequest>,
    ) -> Result<Response<pb::GetObjectResponse>, Status> {
        let req = request.into_inner();
        let id = from_pb_object_id(req.id.as_ref().ok_or_else(|| Status::invalid_argument("missing id"))?)?;

        let obj = self.repo.get_object(&id).map_err(to_status)?
            .ok_or_else(|| Status::not_found(format!("object not found: {}", id)))?;

        let response = match obj {
            Object::Blob(blob) => pb::GetObjectResponse {
                object: Some(pb::get_object_response::Object::Blob(pb::Blob { data: blob.data })),
            },
            Object::Tree(tree) => {
                let entries = tree.entries.into_iter().map(|(name, entry)| {
                    (name, pb::TreeEntry {
                        id: Some(to_pb_object_id(&entry.id)),
                        kind: match entry.kind {
                            EntryKind::File => pb::EntryKind::File as i32,
                            EntryKind::Directory => pb::EntryKind::Directory as i32,
                            EntryKind::Symlink => pb::EntryKind::Symlink as i32,
                        },
                        executable: entry.executable,
                    })
                }).collect();
                pb::GetObjectResponse {
                    object: Some(pb::get_object_response::Object::Tree(pb::Tree { entries })),
                }
            }
            Object::Changeset(cs) => {
                let pb_cs = changeset_to_pb(&cs);
                pb::GetObjectResponse {
                    object: Some(pb::get_object_response::Object::Changeset(pb_cs)),
                }
            }
            Object::Envelope(env) => {
                // Serialize envelope payload as a blob for now.
                // Full attestation RPC support comes later.
                pb::GetObjectResponse {
                    object: Some(pb::get_object_response::Object::Blob(pb::Blob { data: env.payload })),
                }
            }
        };

        Ok(Response::new(response))
    }

    async fn put_object(
        &self,
        request: Request<pb::PutObjectRequest>,
    ) -> Result<Response<pb::PutObjectResponse>, Status> {
        require_scope(&request, |s| s.allows_write(), "write")?;
        let req = request.into_inner();
        let obj = match req.object {
            Some(pb::put_object_request::Object::Blob(blob)) => {
                Object::Blob(Blob { data: blob.data })
            }
            Some(pb::put_object_request::Object::Tree(tree)) => {
                let entries = tree.entries.into_iter().map(|(name, entry)| {
                    let id = entry.id.as_ref()
                        .and_then(|id| from_pb_object_id(id).ok())
                        .unwrap_or(ObjectId::ZERO);
                    let kind = match pb::EntryKind::try_from(entry.kind) {
                        Ok(pb::EntryKind::Directory) => EntryKind::Directory,
                        Ok(pb::EntryKind::Symlink) => EntryKind::Symlink,
                        _ => EntryKind::File,
                    };
                    (name, TreeEntry { id, kind, executable: entry.executable })
                }).collect();
                Object::Tree(Tree { entries })
            }
            _ => return Err(Status::invalid_argument("missing or unsupported object type")),
        };

        let id = self.repo.put_object(&obj).map_err(to_status)?;
        Ok(Response::new(pb::PutObjectResponse { id: Some(to_pb_object_id(&id)) }))
    }

    async fn has_object(
        &self,
        request: Request<pb::HasObjectRequest>,
    ) -> Result<Response<pb::HasObjectResponse>, Status> {
        let req = request.into_inner();
        let id = from_pb_object_id(req.id.as_ref().ok_or_else(|| Status::invalid_argument("missing id"))?)?;
        // Check existence by attempting get (we don't expose has_object on Repository directly).
        let exists = self.repo.get_object(&id).map_err(to_status)?.is_some();
        Ok(Response::new(pb::HasObjectResponse { exists }))
    }

    async fn get_ref(
        &self,
        request: Request<pb::GetRefRequest>,
    ) -> Result<Response<pb::GetRefResponse>, Status> {
        let req = request.into_inner();
        let name = &req.name;

        // Get the raw ref.
        let refs = self.repo.list_refs("").map_err(to_status)?;
        let raw_ref = refs.into_iter().find(|(n, _)| n == name).map(|(_, r)| r);

        let value = raw_ref.as_ref().map(|r| match r {
            Ref::Direct(id) => pb::RefValue {
                value: Some(pb::ref_value::Value::Direct(to_pb_object_id(id))),
            },
            Ref::Symbolic(target) => pb::RefValue {
                value: Some(pb::ref_value::Value::Symbolic(target.clone())),
            },
        });

        // Also resolve fully.
        let resolved = self.repo.resolve_ref(name).map_err(to_status)?
            .map(|id| to_pb_object_id(&id));

        Ok(Response::new(pb::GetRefResponse { value, resolved }))
    }

    async fn set_ref(
        &self,
        request: Request<pb::SetRefRequest>,
    ) -> Result<Response<pb::SetRefResponse>, Status> {
        // Extract auth before consuming request.
        let auth = require_auth_with_scopes(&request)?.clone();
        if !auth.scopes.allows_write() {
            return Err(Status::permission_denied(
                "token lacks required scope 'write' — generate a new token with this scope"
            ));
        }

        let req = request.into_inner();

        // Check ref-specific scope.
        if !auth.scopes.allows_ref(&req.name) {
            return Err(Status::permission_denied(format!(
                "token lacks scope for ref '{}' — add ref:{} scope to token",
                req.name, req.name
            )));
        }

        let reference = match req.value.and_then(|v| v.value) {
            Some(pb::ref_value::Value::Direct(id)) => Ref::Direct(from_pb_object_id(&id)?),
            Some(pb::ref_value::Value::Symbolic(target)) => Ref::Symbolic(target),
            None => return Err(Status::invalid_argument("missing ref value")),
        };

        // SE-7: Enforce ref policies.
        let target_id = match &reference {
            Ref::Direct(id) => Some(id),
            Ref::Symbolic(_) => None,
        };
        // Determine if this is a force push (non-fast-forward).
        let is_force = if let Some(new_id) = target_id {
            match self.repo.resolve_ref(&req.name).map_err(to_status)? {
                Some(old_id) => old_id != *new_id, // simplified; proper FF check needs ancestor walk
                None => false, // new ref, not a force push
            }
        } else {
            false
        };
        if let Some(denial) = self.repo.check_ref_policy(
            &req.name, &auth.identity, target_id, is_force
        ).map_err(to_status)? {
            return Err(Status::permission_denied(denial.to_string()));
        }

        self.repo.set_ref(&req.name, &reference).map_err(to_status)?;
        Ok(Response::new(pb::SetRefResponse {}))
    }

    async fn list_refs(
        &self,
        request: Request<pb::ListRefsRequest>,
    ) -> Result<Response<pb::ListRefsResponse>, Status> {
        let req = request.into_inner();
        let refs = self.repo.list_refs(&req.prefix).map_err(to_status)?;
        let entries: Vec<pb::RefEntry> = refs.into_iter().map(|(name, reference)| {
            let value = match reference {
                Ref::Direct(id) => pb::RefValue {
                    value: Some(pb::ref_value::Value::Direct(to_pb_object_id(&id))),
                },
                Ref::Symbolic(target) => pb::RefValue {
                    value: Some(pb::ref_value::Value::Symbolic(target)),
                },
            };
            pb::RefEntry { name, value: Some(value) }
        }).collect();
        Ok(Response::new(pb::ListRefsResponse { refs: entries }))
    }

    async fn create_changeset(
        &self,
        request: Request<pb::CreateChangesetRequest>,
    ) -> Result<Response<pb::CreateChangesetResponse>, Status> {
        let author = require_scope(&request, |s| s.allows_write(), "write")?;
        let req = request.into_inner();
        let tree = from_pb_object_id(
            req.tree.as_ref().ok_or_else(|| Status::invalid_argument("missing tree"))?
        )?;
        let parents: Vec<ObjectId> = req.parents.iter()
            .map(|p| from_pb_object_id(p))
            .collect::<Result<Vec<_>, _>>()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Status::internal("system clock before UNIX epoch"))?
            .as_micros() as i64;

        let intent = req.intent.map(|i| intent_from_pb(&i));

        let changeset = Changeset {
            parents,
            tree,
            author,
            timestamp,
            message: req.message,
            intent,
            metadata: req.metadata.into_iter().collect::<BTreeMap<_, _>>(),
        };

        let id = self.repo.put_object(&Object::Changeset(changeset)).map_err(to_status)?;
        Ok(Response::new(pb::CreateChangesetResponse { id: Some(to_pb_object_id(&id)) }))
    }

    async fn get_changeset(
        &self,
        request: Request<pb::GetChangesetRequest>,
    ) -> Result<Response<pb::GetChangesetResponse>, Status> {
        let req = request.into_inner();
        let id = from_pb_object_id(req.id.as_ref().ok_or_else(|| Status::invalid_argument("missing id"))?)?;

        match self.repo.get_object(&id).map_err(to_status)? {
            Some(Object::Changeset(cs)) => {
                Ok(Response::new(pb::GetChangesetResponse {
                    changeset: Some(changeset_to_pb(&cs)),
                }))
            }
            _ => Err(Status::not_found("changeset not found")),
        }
    }

    type LogStream = tokio_stream::wrappers::ReceiverStream<Result<pb::LogEntry, Status>>;

    async fn log(
        &self,
        request: Request<pb::LogRequest>,
    ) -> Result<Response<Self::LogStream>, Status> {
        let req = request.into_inner();
        let max_count = if req.max_count == 0 { 100 } else { (req.max_count as usize).min(MAX_LOG_ENTRIES) };

        let entries = self.repo.log(max_count).map_err(to_status)?;

        let (tx, rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            for (id, cs) in entries {
                let entry = pb::LogEntry {
                    id: Some(to_pb_object_id(&id)),
                    changeset: Some(changeset_to_pb(&cs)),
                };
                if tx.send(Ok(entry)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn create_identity(
        &self,
        request: Request<pb::CreateIdentityRequest>,
    ) -> Result<Response<pb::CreateIdentityResponse>, Status> {
        require_scope(&request, |s| s.allows_identity(), "identity")?;
        let req = request.into_inner();
        let kind = match pb::IdentityKind::try_from(req.kind) {
            Ok(pb::IdentityKind::Agent) => IdentityKind::Agent { runtime: "unknown".into() },
            _ => IdentityKind::Human,
        };
        let identity = self.repo.create_identity(&req.name, kind).map_err(to_status)?;
        Ok(Response::new(pb::CreateIdentityResponse {
            identity: Some(identity_to_pb(&identity)),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<pb::GetIdentityRequest>,
    ) -> Result<Response<pb::GetIdentityResponse>, Status> {
        let req = request.into_inner();
        let pb_id = req.id.ok_or_else(|| Status::invalid_argument("missing id"))?;
        let uuid_bytes: [u8; 16] = pb_id.uuid.as_slice().try_into()
            .map_err(|_| Status::invalid_argument("identity id must be 16 bytes"))?;
        let id = IdentityId::from_bytes(uuid_bytes);

        match self.repo.get_identity(&id).map_err(to_status)? {
            Some(ident) => Ok(Response::new(pb::GetIdentityResponse {
                identity: Some(identity_to_pb(&ident)),
            })),
            None => Err(Status::not_found("identity not found")),
        }
    }

    // ── Sync RPCs ─────────────────────────────────────────────────────

    async fn cas_ref(
        &self,
        request: Request<pb::CasRefRequest>,
    ) -> Result<Response<pb::CasRefResponse>, Status> {
        let auth = require_auth_with_scopes(&request)?.clone();
        if !auth.scopes.allows_write() {
            return Err(Status::permission_denied("token lacks 'write' scope"));
        }
        let req = request.into_inner();

        if !auth.scopes.allows_ref(&req.name) {
            return Err(Status::permission_denied(format!(
                "token lacks scope for ref '{}'", req.name
            )));
        }

        let expected = match req.expected.and_then(|v| v.value) {
            Some(pb::ref_value::Value::Direct(id)) => Some(Ref::Direct(from_pb_object_id(&id)?)),
            Some(pb::ref_value::Value::Symbolic(t)) => Some(Ref::Symbolic(t)),
            None => None,
        };

        let new_ref = match req.new_value.and_then(|v| v.value) {
            Some(pb::ref_value::Value::Direct(id)) => Ref::Direct(from_pb_object_id(&id)?),
            Some(pb::ref_value::Value::Symbolic(t)) => Ref::Symbolic(t),
            None => return Err(Status::invalid_argument("missing new_value")),
        };

        let success = self.repo.cas_ref(&req.name, expected.as_ref(), &new_ref)
            .map_err(to_status)?;

        let current = if !success {
            // Return current value so caller can retry.
            let refs = self.repo.list_refs("").map_err(to_status)?;
            refs.into_iter()
                .find(|(n, _)| *n == req.name)
                .map(|(_, r)| ref_to_pb(&r))
        } else {
            None
        };

        Ok(Response::new(pb::CasRefResponse { success, current }))
    }

    async fn push_objects(
        &self,
        request: Request<tonic::Streaming<pb::PushObjectChunk>>,
    ) -> Result<Response<pb::PushObjectsResponse>, Status> {
        // #1: push_objects requires write scope.
        require_scope(&request, |s| s.allows_write(), "write")?;

        let mut stream = request.into_inner();
        let mut received = 0u32;
        let max_size = self.max_object_size;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if chunk.data.is_empty() {
                continue;
            }
            // #3: enforce object size limit.
            if chunk.data.len() > max_size {
                return Err(Status::invalid_argument(format!(
                    "object too large: {} bytes (max {})",
                    chunk.data.len(), max_size
                )));
            }
            let obj = Object::from_tagged_bytes(&chunk.data)
                .map_err(|e| Status::invalid_argument(format!("invalid object: {}", e)))?;
            self.repo.put_object(&obj).map_err(to_status)?;
            received += 1;
        }

        Ok(Response::new(pb::PushObjectsResponse { received }))
    }

    type FetchObjectsStream = tokio_stream::wrappers::ReceiverStream<Result<pb::FetchObjectChunk, Status>>;

    async fn fetch_objects(
        &self,
        request: Request<pb::FetchObjectsRequest>,
    ) -> Result<Response<Self::FetchObjectsStream>, Status> {
        // #2: fetch_objects respects require_auth_for_reads.
        if self.require_auth_for_reads {
            optional_auth(&request)
                .ok_or_else(|| Status::unauthenticated("authentication required for reads"))?;
        }

        let req = request.into_inner();
        let repo = self.repo.clone();

        let want_ids: Vec<ObjectId> = req.want.iter()
            .map(from_pb_object_id)
            .collect::<Result<Vec<_>, _>>()?;

        let have_ids: std::collections::HashSet<ObjectId> = req.have.iter()
            .map(from_pb_object_id)
            .collect::<Result<std::collections::HashSet<_>, _>>()?;

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            // Walk from each wanted object, sending everything the client doesn't have.
            let mut sent = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::from_iter(want_ids);

            while let Some(id) = queue.pop_front() {
                if have_ids.contains(&id) || !sent.insert(id) {
                    continue;
                }
                match repo.get_object(&id) {
                    Ok(Some(obj)) => {
                        // If it's a changeset, enqueue parents and tree.
                        if let Object::Changeset(ref cs) = obj {
                            queue.extend(cs.parents.iter().copied());
                            queue.push_back(cs.tree);
                        }
                        // If it's a tree, enqueue child objects.
                        if let Object::Tree(ref tree) = obj {
                            for entry in tree.entries.values() {
                                queue.push_back(entry.id);
                            }
                        }

                        let data = obj.to_tagged_bytes();
                        let chunk = pb::FetchObjectChunk {
                            id: Some(to_pb_object_id(&id)),
                            data,
                        };
                        if tx.send(Ok(chunk)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {} // Object not found, skip.
                    Err(e) => {
                        let _ = tx.send(Err(to_status(e))).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn negotiate_refs(
        &self,
        _request: Request<pb::NegotiateRefsRequest>,
    ) -> Result<Response<pb::NegotiateRefsResponse>, Status> {
        // Return all server refs so the client can determine what to fetch/push.
        let refs = self.repo.list_refs("").map_err(to_status)?;
        let entries: Vec<pb::RefEntry> = refs.into_iter().map(|(name, reference)| {
            pb::RefEntry {
                name,
                value: Some(ref_to_pb(&reference)),
            }
        }).collect();
        Ok(Response::new(pb::NegotiateRefsResponse { server_refs: entries }))
    }
}

// ── Proto conversion helpers ────────────────────────────────────────

fn changeset_to_pb(cs: &Changeset) -> pb::Changeset {
    pb::Changeset {
        parents: cs.parents.iter().map(|p| to_pb_object_id(p)).collect(),
        tree: Some(to_pb_object_id(&cs.tree)),
        author_id: cs.author.as_bytes().to_vec(),
        timestamp_micros: cs.timestamp,
        message: cs.message.clone(),
        intent: cs.intent.as_ref().map(intent_to_pb),
        metadata: cs.metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    }
}

fn intent_to_pb(intent: &Intent) -> pb::Intent {
    pb::Intent {
        kind: match intent.kind {
            IntentKind::Feature => pb::IntentKind::Feature as i32,
            IntentKind::Bugfix => pb::IntentKind::Bugfix as i32,
            IntentKind::Refactor => pb::IntentKind::Refactor as i32,
            IntentKind::AgentTask => pb::IntentKind::AgentTask as i32,
            IntentKind::Exploration => pb::IntentKind::Exploration as i32,
            IntentKind::Dependency => pb::IntentKind::Dependency as i32,
            IntentKind::Documentation => pb::IntentKind::Documentation as i32,
        },
        affected_paths: intent.affected_paths.clone(),
        rationale: intent.rationale.clone(),
        context_ref: intent.context_ref.as_ref().map(|id| to_pb_object_id(id)),
        verifications: intent.verifications.iter().map(|v| pb::Verification {
            kind: match v.kind {
                VerificationKind::TestPass => pb::VerificationKind::TestPass as i32,
                VerificationKind::LintClean => pb::VerificationKind::LintClean as i32,
                VerificationKind::TypeCheck => pb::VerificationKind::TypeCheck as i32,
                VerificationKind::ManualReview => pb::VerificationKind::ManualReview as i32,
            },
            status: match v.status {
                VerificationStatus::Pending => pb::VerificationStatus::Pending as i32,
                VerificationStatus::Passed => pb::VerificationStatus::Passed as i32,
                VerificationStatus::Failed => pb::VerificationStatus::Failed as i32,
                VerificationStatus::Skipped => pb::VerificationStatus::Skipped as i32,
            },
            details: v.details.clone(),
        }).collect(),
    }
}

fn intent_from_pb(pb: &pb::Intent) -> Intent {
    Intent {
        kind: match pb::IntentKind::try_from(pb.kind) {
            Ok(pb::IntentKind::Feature) => IntentKind::Feature,
            Ok(pb::IntentKind::Bugfix) => IntentKind::Bugfix,
            Ok(pb::IntentKind::Refactor) => IntentKind::Refactor,
            Ok(pb::IntentKind::AgentTask) => IntentKind::AgentTask,
            Ok(pb::IntentKind::Exploration) => IntentKind::Exploration,
            Ok(pb::IntentKind::Dependency) => IntentKind::Dependency,
            Ok(pb::IntentKind::Documentation) => IntentKind::Documentation,
            _ => IntentKind::Feature,
        },
        affected_paths: pb.affected_paths.clone(),
        rationale: pb.rationale.clone(),
        context_ref: pb.context_ref.as_ref().and_then(|id| {
            from_pb_object_id(id).ok()
        }),
        verifications: vec![],
    }
}

fn ref_to_pb(r: &Ref) -> pb::RefValue {
    match r {
        Ref::Direct(id) => pb::RefValue {
            value: Some(pb::ref_value::Value::Direct(to_pb_object_id(id))),
        },
        Ref::Symbolic(target) => pb::RefValue {
            value: Some(pb::ref_value::Value::Symbolic(target.clone())),
        },
    }
}

fn identity_to_pb(ident: &Identity) -> pb::Identity {
    pb::Identity {
        id: Some(pb::IdentityId { uuid: ident.id.as_bytes().to_vec() }),
        kind: match &ident.kind {
            IdentityKind::Human => pb::IdentityKind::Human as i32,
            IdentityKind::Agent { .. } => pb::IdentityKind::Agent as i32,
        },
        name: ident.name.clone(),
        public_keys: vec![],
        capabilities: vec![],
        created_at_micros: ident.created_at,
    }
}
