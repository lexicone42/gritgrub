//! Server configuration — TOML file + environment variable overrides.
//!
//! Config resolution order (last wins):
//! 1. Built-in defaults
//! 2. Config file (.forge/server.toml or --config path)
//! 3. Environment variables (FORGE_*)
//!
//! This makes it easy to deploy:
//! - Locally: just `forge serve` with defaults
//! - Docker: env vars in docker-compose.yml
//! - K8s: ConfigMap mounted as server.toml + env var secrets for TLS

use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

/// Complete server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ServerConfig {
    pub listen: ListenConfig,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
    pub limits: LimitsConfig,
    pub repo: RepoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ListenConfig {
    /// gRPC listen address.
    pub grpc_addr: String,
    /// HTTP/JSON gateway address (empty = disabled).
    pub http_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct TlsConfig {
    /// Enable TLS. When true, cert_path and key_path must be set.
    pub enabled: bool,
    /// Path to PEM-encoded certificate chain.
    pub cert_path: String,
    /// Path to PEM-encoded private key.
    pub key_path: String,
    /// Path to CA cert for client certificate verification (mTLS).
    /// Empty = no client cert required.
    pub ca_cert_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AuthConfig {
    /// Require authentication for all RPCs (not just writes).
    pub require_auth_for_reads: bool,
    /// Maximum token remaining lifetime in hours (0 = no limit).
    /// Rejects tokens whose expiry is more than this many hours in the future.
    /// Also rejects non-expiring tokens when set.
    pub max_token_lifetime_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum message size in bytes (default 16MB).
    pub max_message_size: usize,
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Keepalive interval in seconds (0 = disabled).
    pub keepalive_interval_secs: u64,
    /// Keepalive timeout in seconds.
    pub keepalive_timeout_secs: u64,
    /// Default rate limit: max operations per window (0 = unlimited).
    pub default_rate_limit_ops: u32,
    /// Default rate limit window in seconds.
    pub default_rate_limit_window_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct RepoConfig {
    /// Path to the repository root. Empty = discover from CWD.
    pub path: String,
}

// ── Defaults ───────────────────────────────────────────────────────


impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            grpc_addr: "localhost:50051".into(),
            http_addr: String::new(),
        }
    }
}



impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_size: 16 * 1024 * 1024, // 16MB
            max_concurrent_streams: 200,
            keepalive_interval_secs: 30,
            keepalive_timeout_secs: 10,
            default_rate_limit_ops: 100,
            default_rate_limit_window_secs: 60,
        }
    }
}


// ── Loading ────────────────────────────────────────────────────────

impl ServerConfig {
    /// Load config from file, then apply env var overrides.
    /// Returns an error if the config file exists but is malformed — we refuse to
    /// silently fall back to insecure defaults (SE-3).
    pub fn load(config_path: Option<&Path>) -> Result<Self, String> {
        let mut config = match config_path {
            Some(path) => Self::from_file(path)?,
            None => Self::default(),
        };
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Load from a TOML file. Returns an error if the file exists but can't be parsed —
    /// silent fallback to defaults would create an insecure server.
    fn from_file(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(content) => toml::from_str(&content)
                .map_err(|e| format!("failed to parse {}: {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("failed to read {}: {}", path.display(), e)),
        }
    }

    /// Validate the config for internal consistency. Call after loading.
    pub fn validate(&self) -> Result<(), String> {
        if self.tls.enabled {
            if self.tls.cert_path.is_empty() {
                return Err("tls.enabled = true but tls.cert_path is empty".into());
            }
            if self.tls.key_path.is_empty() {
                return Err("tls.enabled = true but tls.key_path is empty".into());
            }
        }
        Ok(())
    }

    /// Override config values from FORGE_* environment variables.
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("FORGE_GRPC_ADDR") { self.listen.grpc_addr = v; }
        if let Ok(v) = std::env::var("FORGE_HTTP_ADDR") { self.listen.http_addr = v; }
        if let Ok(v) = std::env::var("FORGE_TLS_CERT") { self.tls.cert_path = v; self.tls.enabled = true; }
        if let Ok(v) = std::env::var("FORGE_TLS_KEY") { self.tls.key_path = v; }
        if let Ok(v) = std::env::var("FORGE_TLS_CA") { self.tls.ca_cert_path = v; }
        if let Ok(v) = std::env::var("FORGE_REPO_PATH") { self.repo.path = v; }
        if let Ok(v) = std::env::var("FORGE_REQUIRE_AUTH") { self.auth.require_auth_for_reads = v == "1" || v == "true"; }
        if let Ok(v) = std::env::var("FORGE_MAX_MESSAGE_SIZE") && let Ok(n) = v.parse() { self.limits.max_message_size = n; }
    }

    /// Resolve the repo path — use config, then discover from CWD.
    pub fn repo_path(&self) -> PathBuf {
        if self.repo.path.is_empty() {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        } else {
            PathBuf::from(&self.repo.path)
        }
    }

    /// Generate a default config file as TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}
