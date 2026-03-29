//! Server assembly — builds and runs the complete gRPC + HTTP server.
//!
//! Owns all cloud-ready concerns: TLS, health checks, reflection,
//! rate limiting, keepalive tuning, and graceful shutdown.

use std::sync::Arc;
use tonic::transport::Server;
use gritgrub_store::Repository;

use crate::config::ServerConfig;
use crate::server::RepoServer;
use crate::attestation_service::AttestationServer;
use crate::event_service::{EventServer, EventBroadcaster};
use crate::auth::auth_interceptor;
use crate::rate_limit::RateLimiter;
use crate::http_gateway;

/// File descriptor set for gRPC reflection.
const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("gritgrub_descriptor");

/// Assembled server ready to run.
pub struct ForgeServer {
    config: ServerConfig,
    repo: Arc<Repository>,
    broadcaster: EventBroadcaster,
}

impl ForgeServer {
    /// Create a new server from config and repository.
    /// The broadcaster is initialized immediately and is live from creation (SE-13).
    pub fn new(config: ServerConfig, repo: Arc<Repository>) -> Self {
        let (_event_server_unused, broadcaster) = EventServer::with_repo(repo.clone());
        Self {
            config,
            repo,
            broadcaster,
        }
    }

    /// Get a handle to broadcast events into the EventService stream.
    pub fn broadcaster(&self) -> EventBroadcaster {
        self.broadcaster.clone()
    }

    /// Run the server, blocking until shutdown signal.
    pub async fn run(self) -> anyhow::Result<()> {
        let grpc_addr = resolve_addr(&self.config.listen.grpc_addr)?;

        // accept_http1 enables grpc-web (HTTP/1.1) alongside native gRPC (HTTP/2).
        let mut builder = Server::builder().accept_http1(true);

        // ── TLS ──────────────────────────────────────────────────────
        if self.config.tls.enabled {
            let cert = std::fs::read(&self.config.tls.cert_path)
                .map_err(|e| anyhow::anyhow!("TLS cert '{}': {}", self.config.tls.cert_path, e))?;
            let key = std::fs::read(&self.config.tls.key_path)
                .map_err(|e| anyhow::anyhow!("TLS key '{}': {}", self.config.tls.key_path, e))?;

            let mut tls = tonic::transport::ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert, key));

            if !self.config.tls.ca_cert_path.is_empty() {
                let ca = std::fs::read(&self.config.tls.ca_cert_path)
                    .map_err(|e| anyhow::anyhow!("CA cert '{}': {}", self.config.tls.ca_cert_path, e))?;
                tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(ca));
            }

            builder = builder.tls_config(tls)?;
        }

        // ── HTTP/2 tuning ────────────────────────────────────────────
        if self.config.limits.keepalive_interval_secs > 0 {
            builder = builder
                .http2_keepalive_interval(Some(
                    std::time::Duration::from_secs(self.config.limits.keepalive_interval_secs)
                ))
                .http2_keepalive_timeout(Some(
                    std::time::Duration::from_secs(self.config.limits.keepalive_timeout_secs)
                ));
        }
        if self.config.limits.max_concurrent_streams > 0 {
            builder = builder.concurrency_limit_per_connection(
                self.config.limits.max_concurrent_streams as usize
            );
        }

        // ── Services ─────────────────────────────────────────────────
        let rate_limiter = RateLimiter::new(
            self.config.limits.default_rate_limit_ops,
            self.config.limits.default_rate_limit_window_secs,
        );

        let repo_server = RepoServer::new(self.repo.clone())
            .with_limits(
                self.config.limits.max_message_size,
                self.config.auth.require_auth_for_reads,
            );
        let attest_server = AttestationServer::new(self.repo.clone());
        let (event_server, _broadcaster) = EventServer::with_repo(self.repo.clone());

        let interceptor = auth_interceptor(
            self.repo.clone(),
            rate_limiter.clone(),
            self.config.auth.require_auth_for_reads,
            self.config.auth.max_token_lifetime_hours,
        );

        // gRPC health service.
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter.set_serving::<crate::pb::repo_service_server::RepoServiceServer<RepoServer>>().await;
        health_reporter.set_serving::<crate::pb::attestation_service_server::AttestationServiceServer<AttestationServer>>().await;
        health_reporter.set_serving::<crate::pb::event_service_server::EventServiceServer<EventServer>>().await;

        // gRPC reflection (lets tools like grpcurl discover services).
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()?;

        // ── Banner ───────────────────────────────────────────────────
        let tls_label = if self.config.tls.enabled {
            if !self.config.tls.ca_cert_path.is_empty() { "TLS + mTLS" } else { "TLS" }
        } else {
            "plaintext"
        };

        let rate_label = if self.config.limits.default_rate_limit_ops > 0 {
            format!("{} ops/{} s", self.config.limits.default_rate_limit_ops, self.config.limits.default_rate_limit_window_secs)
        } else {
            "unlimited".to_string()
        };

        println!("forge server listening on {} ({})", grpc_addr, tls_label);
        if !self.config.tls.enabled {
            eprintln!("  WARNING: TLS is disabled — bearer tokens will be sent in plaintext!");
            eprintln!("  WARNING: Enable TLS for production use (see forge serve --init-config)");
        }
        println!("  gRPC                 {}", grpc_addr);
        println!("  RepoService          objects, refs, changesets, identity");
        println!("  AttestationService   create, list, verify, SLSA check");
        println!("  EventService         subscribe to repo events");
        println!("  grpc-web             HTTP/1.1 browser clients");

        // ── HTTP/JSON gateway ────────────────────────────────────────
        let http_handle = if !self.config.listen.http_addr.is_empty() {
            let http_addr = resolve_addr(&self.config.listen.http_addr)?;
            let http_state = http_gateway::HttpState {
                repo: self.repo.clone(),
                rate_limiter: rate_limiter.clone(),
                require_auth_for_reads: self.config.auth.require_auth_for_reads,
                max_token_lifetime_hours: self.config.auth.max_token_lifetime_hours,
                max_object_size: self.config.limits.max_message_size,
            };
            let app = http_gateway::router(http_state);
            let listener = tokio::net::TcpListener::bind(http_addr).await
                .map_err(|e| anyhow::anyhow!("HTTP bind '{}': {}", http_addr, e))?;
            println!("  HTTP/JSON            http://{}/api/v1/", http_addr);
            Some(tokio::spawn(async move {
                axum::serve(listener, app).await.ok();
            }))
        } else {
            None
        };

        println!();
        println!("  Rate limit: {}", rate_label);
        println!("  Auth: Bearer token in 'authorization' header");
        println!("  Generate: forge identity token");

        // ── Shutdown ─────────────────────────────────────────────────
        let shutdown = graceful_shutdown();

        // ── Serve gRPC ───────────────────────────────────────────────
        builder
            .layer(tonic::service::interceptor(interceptor))
            .add_service(health_service)
            .add_service(reflection)
            .add_service(tonic_web::enable(repo_server.into_service()))
            .add_service(tonic_web::enable(attest_server.into_service()))
            .add_service(tonic_web::enable(event_server.into_service()))
            .serve_with_shutdown(grpc_addr, shutdown)
            .await
            .map_err(|e| anyhow::anyhow!("server error: {}", e))?;

        // Clean up HTTP task.
        if let Some(handle) = http_handle {
            handle.abort();
        }

        Ok(())
    }
}

/// Resolve an address string like "localhost:50051" to a SocketAddr.
/// Accepts both IP:port ("127.0.0.1:50051", "[::1]:50051") and hostname:port ("localhost:50051").
fn resolve_addr(addr: &str) -> anyhow::Result<std::net::SocketAddr> {
    // Try parsing directly as a SocketAddr first (handles IP:port).
    if let Ok(sa) = addr.parse() {
        return Ok(sa);
    }
    // Otherwise resolve as hostname:port.
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve address '{}'", addr))
}

/// Wait for SIGINT or SIGTERM.
async fn graceful_shutdown() {
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate()
    ).expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nReceived SIGINT, shutting down...");
        }
        _ = sigterm.recv() => {
            println!("\nReceived SIGTERM, shutting down...");
        }
    }
}
