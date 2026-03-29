// Generated protobuf code and tonic::Status have large variants — not our concern.
#![allow(clippy::large_enum_variant, clippy::result_large_err, clippy::type_complexity)]

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
pub mod client;
pub mod config;
pub mod rate_limit;
mod serve;
pub mod http_gateway;

pub use server::RepoServer;
pub use auth::{auth_interceptor, require_auth, require_scope, optional_auth, AuthenticatedRequest};
pub use attestation_service::AttestationServer;
pub use event_service::{EventServer, EventBroadcaster};
pub use config::ServerConfig;
pub use serve::ForgeServer;
pub use client::ForgeClient;
