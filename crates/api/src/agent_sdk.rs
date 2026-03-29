//! Agent SDK — HTTP client library for multi-agent coordination.
//!
//! This is what agents import to interact with a forge server. It wraps
//! the HTTP/JSON API with typed Rust methods for the exploration workflow.
//!
//! # Usage
//!
//! ```rust,ignore
//! use gritgrub_api::agent_sdk::AgentSession;
//!
//! fn main() {
//!     let session = AgentSession::from_env().unwrap();
//!     let goal = session.goal_status().unwrap();
//!     println!("Goal: {}", goal.description);
//! }
//! ```
//!
//! # minimal.dev integration
//!
//! The orchestrator provisions agents via HTTP:
//! ```bash
//! curl -X POST http://server/api/v1/provision/batch \
//!   -d '{"count": 5, "goal_id": "abc123"}'
//! ```
//!
//! Each agent's sandbox receives the JSON config as an environment variable
//! (FORGE_AGENT_CONFIG). The SDK reads it automatically via `from_env()`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Environment variable containing the agent's JSON config.
pub const AGENT_CONFIG_ENV: &str = "FORGE_AGENT_CONFIG";

/// An active agent session connected to a forge server.
pub struct AgentSession {
    config: AgentConfig,
    http: reqwest_lite::Client,
}

/// Agent configuration — output of `forge provision`.
///
/// Contains everything an agent needs to connect and start working.
/// The `server_url` is the gRPC endpoint for push/pull.
/// The `http_url` is the HTTP endpoint for coordination APIs.
/// If `http_url` is not set, it's derived from `server_url` by
/// replacing the port with 8080.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    #[serde(default)]
    pub http_url: Option<String>,
    pub token: String,
    pub identity: String,
    pub name: String,
    #[serde(default)]
    pub goal_id: Option<String>,
    #[serde(default)]
    pub approach: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
}

/// Goal status from the server.
#[derive(Debug, Clone, Deserialize)]
pub struct GoalStatus {
    pub id: String,
    pub description: String,
    pub target_branch: String,
    pub approaches: Vec<ApproachStatus>,
    pub claims: Vec<ClaimInfo>,
    pub promoted: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproachStatus {
    pub name: String,
    pub tip: Option<String>,
    pub changeset_count: usize,
    pub latest_message: Option<String>,
    pub verification: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaimInfo {
    pub agent: String,
    pub approach: String,
    pub intent: String,
    pub heartbeat: u64,
}

/// Pipeline execution result from the server.
#[derive(Debug, Clone, Deserialize)]
pub struct PipelineStatus {
    pub pipeline: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub stages: Vec<StageStatus>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StageStatus {
    pub name: String,
    pub passed: bool,
    pub summary: String,
    pub tests_passed: u32,
    pub tests_failed: u32,
}

/// Overview of the entire repository state.
#[derive(Debug, Clone, Deserialize)]
pub struct Overview {
    pub branch: Option<String>,
    pub head: Option<String>,
    pub goals: Vec<GoalStatus>,
}

/// Minimal HTTP client that doesn't pull in reqwest (too heavy).
/// Uses ureq-style blocking or hand-rolled async.
mod reqwest_lite {
    pub struct Client {
        base_url: String,
        token: Option<String>,
    }

    #[derive(Debug)]
    pub struct Response {
        pub status: u16,
        pub body: String,
    }

    impl Client {
        pub fn new(base_url: &str, token: Option<&str>) -> Self {
            Self {
                base_url: base_url.trim_end_matches('/').to_string(),
                token: token.map(String::from),
            }
        }

        /// GET request. Uses std::process::Command to call curl for simplicity.
        /// In production, this would use hyper or reqwest.
        pub fn get(&self, path: &str) -> Result<Response, String> {
            self.request("GET", path, None)
        }

        /// POST request with JSON body.
        pub fn post(&self, path: &str, body: &str) -> Result<Response, String> {
            self.request("POST", path, Some(body))
        }

        fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<Response, String> {
            let url = format!("{}{}", self.base_url, path);
            let mut cmd = std::process::Command::new("curl");
            cmd.args(["-s", "-w", "\n%{http_code}", "-X", method]);
            cmd.args(["-H", "Content-Type: application/json"]);

            if let Some(token) = &self.token {
                cmd.args(["-H", &format!("Authorization: Bearer {}", token)]);
            }

            if let Some(body) = body {
                cmd.args(["-d", body]);
            }

            cmd.arg(&url);
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::null());

            let output = cmd.output().map_err(|e| format!("curl failed: {}", e))?;
            let raw = String::from_utf8_lossy(&output.stdout).to_string();

            // Last line is the HTTP status code.
            let lines: Vec<&str> = raw.trim().rsplitn(2, '\n').collect();
            if lines.len() < 2 {
                return Err("no response from server".into());
            }
            let status: u16 = lines[0].parse().unwrap_or(0);
            let body = lines[1].to_string();

            Ok(Response { status, body })
        }
    }
}

impl AgentSession {
    /// Create a session from a JSON config string (output of `forge provision`).
    pub fn from_config(json: &str) -> Result<Self> {
        let config: AgentConfig = serde_json::from_str(json)
            .context("failed to parse agent config JSON")?;
        // Derive HTTP URL from gRPC URL if not explicitly set.
        let http_base = config.http_url.clone().unwrap_or_else(|| {
            // https://server:50051 → http://server:8080
            config.server_url
                .replace("https://", "http://")
                .replace(":50051", ":8080")
        });
        let http = reqwest_lite::Client::new(&http_base, Some(&config.token));
        Ok(Self { config, http })
    }

    /// Create a session from the FORGE_AGENT_CONFIG environment variable.
    pub fn from_env() -> Result<Self> {
        let json = std::env::var(AGENT_CONFIG_ENV)
            .context(format!("set {} with the JSON config from `forge provision`", AGENT_CONFIG_ENV))?;
        Self::from_config(&json)
    }

    /// Create a session with explicit URL and token.
    pub fn new(server_url: &str, token: &str, identity: &str) -> Self {
        let config = AgentConfig {
            server_url: server_url.to_string(),
            http_url: None,
            token: token.to_string(),
            identity: identity.to_string(),
            name: String::new(),
            goal_id: None,
            approach: None,
            branch: None,
        };
        let http = reqwest_lite::Client::new(server_url, Some(token));
        Self { config, http }
    }

    /// Get the agent's identity.
    pub fn identity(&self) -> &str { &self.config.identity }

    /// Get the agent's assigned goal ID.
    pub fn goal_id(&self) -> Option<&str> { self.config.goal_id.as_deref() }

    /// Get the agent's assigned approach.
    pub fn approach(&self) -> Option<&str> { self.config.approach.as_deref() }

    /// Get the full repository overview.
    pub fn overview(&self) -> Result<Overview> {
        let resp = self.http.get("/api/v1/overview")
            .map_err(|e| anyhow::anyhow!("request failed: {}", e))?;
        if resp.status != 200 {
            bail!("overview failed ({}): {}", resp.status, resp.body);
        }
        Ok(serde_json::from_str(&resp.body)?)
    }

    /// Get the status of the assigned goal.
    pub fn goal_status(&self) -> Result<GoalStatus> {
        let goal_id = self.config.goal_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("no goal assigned to this agent"))?;
        let resp = self.http.get(&format!("/api/v1/explore/goals/{}", goal_id))
            .map_err(|e| anyhow::anyhow!("request failed: {}", e))?;
        if resp.status != 200 {
            bail!("goal status failed ({}): {}", resp.status, resp.body);
        }
        Ok(serde_json::from_str(&resp.body)?)
    }

    /// Get pipeline results for a changeset.
    pub fn pipeline_results(&self, changeset_id: &str) -> Result<Vec<PipelineStatus>> {
        let resp = self.http.get(&format!("/api/v1/pipeline/{}", changeset_id))
            .map_err(|e| anyhow::anyhow!("request failed: {}", e))?;
        if resp.status != 200 {
            bail!("pipeline results failed ({}): {}", resp.status, resp.body);
        }
        Ok(serde_json::from_str(&resp.body)?)
    }

    /// Get recent changeset log.
    pub fn log(&self, count: usize) -> Result<Vec<serde_json::Value>> {
        let resp = self.http.get(&format!("/api/v1/log?count={}", count))
            .map_err(|e| anyhow::anyhow!("request failed: {}", e))?;
        if resp.status != 200 {
            bail!("log failed ({}): {}", resp.status, resp.body);
        }
        Ok(serde_json::from_str(&resp.body)?)
    }

    /// Create a new exploration goal.
    pub fn create_goal(&self, description: &str, target_branch: &str) -> Result<GoalStatus> {
        let body = serde_json::json!({
            "description": description,
            "target_branch": target_branch,
        });
        let resp = self.http.post("/api/v1/explore/goals", &body.to_string())
            .map_err(|e| anyhow::anyhow!("request failed: {}", e))?;
        if resp.status != 200 {
            bail!("create goal failed ({}): {}", resp.status, resp.body);
        }
        Ok(serde_json::from_str(&resp.body)?)
    }

    /// Provision a sub-agent (requires identity scope).
    pub fn provision_agent(&self, name: &str, goal_id: Option<&str>, approach: Option<&str>) -> Result<AgentConfig> {
        let mut body = serde_json::json!({
            "name": name,
            "runtime": "claude-code",
        });
        if let Some(gid) = goal_id {
            body["goal_id"] = serde_json::json!(gid);
        }
        if let Some(a) = approach {
            body["approach"] = serde_json::json!(a);
        }
        let resp = self.http.post("/api/v1/provision", &body.to_string())
            .map_err(|e| anyhow::anyhow!("request failed: {}", e))?;
        if resp.status != 200 {
            bail!("provision failed ({}): {}", resp.status, resp.body);
        }
        Ok(serde_json::from_str(&resp.body)?)
    }

    /// Get the raw HTTP base URL (for agents that need custom requests).
    pub fn base_url(&self) -> &str { &self.config.server_url }

    /// Get the bearer token (for agents that need custom requests).
    pub fn token(&self) -> &str { &self.config.token }
}
