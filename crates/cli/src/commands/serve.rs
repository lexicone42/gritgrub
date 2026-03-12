use std::path::Path;
use std::sync::Arc;
use anyhow::Result;
use gritgrub_store::Repository;
use gritgrub_api::{RepoServer, AttestationServer, EventServer, auth_interceptor};

pub fn run(addr: &str) -> Result<()> {
    let repo = Arc::new(Repository::discover(Path::new("."))?);

    let repo_server = RepoServer::new(repo.clone());
    let attest_server = AttestationServer::new(repo.clone());
    let (event_server, _broadcaster) = EventServer::new();

    let interceptor = auth_interceptor(repo.clone());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr = addr.parse().map_err(|e| anyhow::anyhow!("invalid address: {}", e))?;

        println!("forge server listening on {}", addr);
        println!("  RepoService:        objects, refs, changesets, identity");
        println!("  AttestationService:  create, list, verify, SLSA check");
        println!("  EventService:        subscribe to repo events");
        println!();
        println!("  Auth: pass Bearer token in 'authorization' metadata");
        println!("  Generate token: forge identity token");

        tonic::transport::Server::builder()
            .layer(tonic::service::interceptor(interceptor))
            .add_service(repo_server.into_service())
            .add_service(attest_server.into_service())
            .add_service(event_server.into_service())
            .serve(addr)
            .await
            .map_err(|e| anyhow::anyhow!("server error: {}", e))
    })
}
