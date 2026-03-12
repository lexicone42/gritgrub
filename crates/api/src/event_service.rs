use std::sync::Arc;
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};
use gritgrub_store::Repository;
use crate::pb;
use crate::pb::event_service_server::EventService;

/// An event that can be broadcast to subscribers.
#[derive(Debug, Clone)]
pub struct RepoEvent {
    pub event: pb::Event,
}

pub struct EventServer {
    sender: broadcast::Sender<RepoEvent>,
    #[allow(dead_code)]
    repo: Option<Arc<Repository>>,
}

impl EventServer {
    pub fn new() -> (Self, EventBroadcaster) {
        let (sender, _) = broadcast::channel(256);
        let broadcaster = EventBroadcaster { sender: sender.clone(), repo: None };
        (Self { sender, repo: None }, broadcaster)
    }

    /// Create with repository for persistent event storage + replay.
    pub fn with_repo(repo: Arc<Repository>) -> (Self, EventBroadcaster) {
        let (sender, _) = broadcast::channel(256);
        let broadcaster = EventBroadcaster {
            sender: sender.clone(),
            repo: Some(repo.clone()),
        };
        (Self { sender, repo: Some(repo) }, broadcaster)
    }

    pub fn into_service(self) -> pb::event_service_server::EventServiceServer<Self> {
        pb::event_service_server::EventServiceServer::new(self)
    }
}

/// Handle for server code to broadcast events.
#[derive(Clone)]
pub struct EventBroadcaster {
    sender: broadcast::Sender<RepoEvent>,
    repo: Option<Arc<Repository>>,
}

impl EventBroadcaster {
    /// Create a disconnected broadcaster (no subscribers possible).
    pub fn noop() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self { sender, repo: None }
    }

    /// Broadcast an event to live subscribers and persist it.
    pub fn broadcast(&self, event: pb::Event) {
        // Persist to event log if repository is available (SE-22: log errors).
        if let Some(repo) = &self.repo {
            match serde_json::to_vec(&SerializableEvent::from(&event)) {
                Ok(json) => {
                    if let Err(e) = repo.log_event(&json) {
                        eprintln!("warning: failed to persist event: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("warning: failed to serialize event: {}", e);
                }
            }
        }
        let _ = self.sender.send(RepoEvent { event });
    }
}

/// Serializable event wrapper (pb::Event isn't directly serde-compatible).
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableEvent {
    kind: i32,
    timestamp_micros: i64,
    actor_uuid: Vec<u8>,
    detail: String,
}

impl SerializableEvent {
    fn from(event: &pb::Event) -> Self {
        let detail = match &event.payload {
            Some(pb::event::Payload::ChangesetCreated(e)) => {
                format!("changeset_created branch={}", e.branch)
            }
            Some(pb::event::Payload::RefUpdated(e)) => {
                format!("ref_updated ref={}", e.ref_name)
            }
            Some(pb::event::Payload::ReviewRequested(_)) => {
                "review_requested".to_string()
            }
            None => "unknown".to_string(),
        };
        Self {
            kind: event.kind,
            timestamp_micros: event.timestamp_micros,
            actor_uuid: event.actor.as_ref()
                .map(|a| a.uuid.clone())
                .unwrap_or_default(),
            detail,
        }
    }
}

#[tonic::async_trait]
impl EventService for EventServer {
    type SubscribeStream = tokio_stream::wrappers::ReceiverStream<Result<pb::Event, Status>>;

    async fn subscribe(
        &self,
        request: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let filter = request.into_inner();
        let mut rx = self.sender.subscribe();

        let (tx, stream_rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(repo_event) => {
                        let event = &repo_event.event;

                        // Apply filters (kinds are i32 enums).
                        if !filter.kinds.is_empty() {
                            if !filter.kinds.contains(&event.kind) {
                                continue;
                            }
                        }

                        if !filter.branches.is_empty() {
                            let event_branch = match &event.payload {
                                Some(pb::event::Payload::ChangesetCreated(e)) => Some(&e.branch),
                                Some(pb::event::Payload::RefUpdated(e)) => Some(&e.ref_name),
                                _ => None,
                            };
                            if let Some(branch) = event_branch {
                                if !filter.branches.iter().any(|b| branch.contains(b)) {
                                    continue;
                                }
                            }
                        }

                        if tx.send(Ok(repo_event.event)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("event subscriber lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(stream_rx)))
    }
}
