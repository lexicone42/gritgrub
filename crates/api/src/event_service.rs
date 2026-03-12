use tokio::sync::broadcast;
use tonic::{Request, Response, Status};
use crate::pb;
use crate::pb::event_service_server::EventService;

/// An event that can be broadcast to subscribers.
#[derive(Debug, Clone)]
pub struct RepoEvent {
    pub event: pb::Event,
}

pub struct EventServer {
    sender: broadcast::Sender<RepoEvent>,
}

impl EventServer {
    pub fn new() -> (Self, EventBroadcaster) {
        let (sender, _) = broadcast::channel(256);
        let broadcaster = EventBroadcaster { sender: sender.clone() };
        (Self { sender }, broadcaster)
    }

    pub fn into_service(self) -> pb::event_service_server::EventServiceServer<Self> {
        pb::event_service_server::EventServiceServer::new(self)
    }
}

/// Handle for server code to broadcast events.
#[derive(Clone)]
pub struct EventBroadcaster {
    sender: broadcast::Sender<RepoEvent>,
}

impl EventBroadcaster {
    pub fn broadcast(&self, event: pb::Event) {
        let _ = self.sender.send(RepoEvent { event });
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

                        // Apply filters.
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
