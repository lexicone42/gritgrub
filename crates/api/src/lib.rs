pub mod proto {
    pub mod gritgrub {
        pub mod v1 {
            tonic::include_proto!("gritgrub.v1");
        }
    }
}

pub use proto::gritgrub::v1 as pb;

mod server;
mod auth;
mod attestation_service;
mod event_service;
pub mod config;
pub mod rate_limit;
mod serve;

pub use server::RepoServer;
pub use auth::{auth_interceptor, require_auth, require_scope, optional_auth, AuthenticatedRequest};
pub use attestation_service::AttestationServer;
pub use event_service::{EventServer, EventBroadcaster};
pub use config::ServerConfig;
pub use serve::ForgeServer;
