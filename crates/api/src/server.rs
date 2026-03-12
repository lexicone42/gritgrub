use std::collections::BTreeMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use gritgrub_core::*;
use gritgrub_store::Repository;
use crate::pb;
use crate::pb::repo_service_server::RepoService;

pub struct RepoServer {
    repo: Arc<Repository>,
}

impl RepoServer {
    pub fn new(repo: Repository) -> Self {
        Self { repo: Arc::new(repo) }
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
        };

        Ok(Response::new(response))
    }

    async fn put_object(
        &self,
        request: Request<pb::PutObjectRequest>,
    ) -> Result<Response<pb::PutObjectResponse>, Status> {
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
        let req = request.into_inner();
        let reference = match req.value.and_then(|v| v.value) {
            Some(pb::ref_value::Value::Direct(id)) => Ref::Direct(from_pb_object_id(&id)?),
            Some(pb::ref_value::Value::Symbolic(target)) => Ref::Symbolic(target),
            None => return Err(Status::invalid_argument("missing ref value")),
        };
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
        let req = request.into_inner();
        let tree = from_pb_object_id(
            req.tree.as_ref().ok_or_else(|| Status::invalid_argument("missing tree"))?
        )?;
        let parents: Vec<ObjectId> = req.parents.iter()
            .map(|p| from_pb_object_id(p))
            .collect::<Result<Vec<_>, _>>()?;

        let author = self.repo.local_identity().map_err(to_status)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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
        let max_count = if req.max_count == 0 { 100 } else { req.max_count as usize };

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
