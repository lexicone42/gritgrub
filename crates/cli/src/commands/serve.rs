use std::path::Path;
use anyhow::Result;
use gritgrub_store::Repository;
use gritgrub_api::RepoServer;

pub fn run(addr: &str) -> Result<()> {
    let repo = Repository::discover(Path::new("."))?;
    let server = RepoServer::new(repo);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr = addr.parse().map_err(|e| anyhow::anyhow!("invalid address: {}", e))?;
        println!("forge server listening on {}", addr);
        tonic::transport::Server::builder()
            .add_service(server.into_service())
            .serve(addr)
            .await
            .map_err(|e| anyhow::anyhow!("server error: {}", e))
    })
}
