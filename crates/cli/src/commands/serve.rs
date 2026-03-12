use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::Result;
use gritgrub_store::Repository;
use gritgrub_api::{ServerConfig, ForgeServer};

pub fn run(addr: Option<&str>, config_path: Option<&str>, init_config: bool) -> Result<()> {
    // --init-config: write a default config file and exit.
    if init_config {
        let path = config_path.unwrap_or(".forge/server.toml");
        let config = ServerConfig::default();
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, config.to_toml())?;
        println!("Wrote default config to {}", path);
        return Ok(());
    }

    // Load config: file → env vars → CLI overrides.
    let cfg_path: Option<PathBuf> = config_path
        .map(PathBuf::from)
        .or_else(|| {
            let default = PathBuf::from(".forge/server.toml");
            default.exists().then_some(default)
        });
    let mut config = ServerConfig::load(cfg_path.as_deref())
        .map_err(|e| anyhow::anyhow!("config error: {}", e))?;

    // CLI --addr overrides config.
    if let Some(a) = addr {
        config.listen.grpc_addr = a.to_string();
    }

    let repo_path = config.repo_path();
    let repo = Arc::new(Repository::discover(&repo_path)?);

    let server = ForgeServer::new(config, repo);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(server.run())
}
