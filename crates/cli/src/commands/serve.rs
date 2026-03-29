use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::{bail, Result};
use gritgrub_store::Repository;
use gritgrub_api::{ServerConfig, ForgeServer};

pub fn run(addr: Option<&str>, http_addr: Option<&str>, config_path: Option<&str>, init_config: bool) -> Result<()> {
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

    // CLI overrides.
    if let Some(a) = addr {
        config.listen.grpc_addr = a.to_string();
    }
    if let Some(a) = http_addr {
        config.listen.http_addr = a.to_string();
    }

    // Auto-generate TLS certs via mkcert if not configured.
    if !config.tls.enabled {
        let tls_dir = PathBuf::from(".forge/tls");
        let cert_path = tls_dir.join("cert.pem");
        let key_path = tls_dir.join("key.pem");

        if cert_path.exists() && key_path.exists() {
            // Certs exist from a previous run — use them.
            config.tls.enabled = true;
            config.tls.cert_path = cert_path.to_string_lossy().to_string();
            config.tls.key_path = key_path.to_string_lossy().to_string();
            eprintln!("Using existing TLS certs from .forge/tls/");
        } else if which_mkcert() {
            // Generate certs via mkcert.
            std::fs::create_dir_all(&tls_dir)?;

            // Parse the listen address to get the host for mkcert.
            let host = parse_host(&config.listen.grpc_addr);

            let status = std::process::Command::new("mkcert")
                .args([
                    "-cert-file", &cert_path.to_string_lossy(),
                    "-key-file", &key_path.to_string_lossy(),
                    &host, "localhost", "::1", "127.0.0.1",
                ])
                .status()?;

            if !status.success() {
                bail!("mkcert failed — install it with your package manager or set TLS paths manually");
            }

            config.tls.enabled = true;
            config.tls.cert_path = cert_path.to_string_lossy().to_string();
            config.tls.key_path = key_path.to_string_lossy().to_string();
            eprintln!("Generated TLS certs via mkcert in .forge/tls/");
        } else {
            eprintln!("WARNING: mkcert not found — running without TLS.");
            eprintln!("  Install mkcert for automatic TLS: https://github.com/FiloSottile/mkcert");
            eprintln!("  Or set tls.cert_path and tls.key_path in .forge/server.toml");
        }
    }

    let repo_path = config.repo_path();
    let repo = Arc::new(Repository::discover(&repo_path)?);

    let server = ForgeServer::new(config, repo);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(server.run())
}

/// Check if mkcert is available on PATH.
fn which_mkcert() -> bool {
    std::process::Command::new("mkcert")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Extract host from "[::1]:50051" or "0.0.0.0:50051" style addresses.
fn parse_host(addr: &str) -> String {
    // Handle IPv6 bracket notation: [::1]:port
    if let Some(bracket_end) = addr.find(']') {
        return addr[1..bracket_end].to_string();
    }
    // Handle host:port
    if let Some(colon) = addr.rfind(':') {
        return addr[..colon].to_string();
    }
    addr.to_string()
}
