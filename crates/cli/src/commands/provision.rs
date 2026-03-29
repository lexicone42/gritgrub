//! Agent provisioning — one command to create everything an agent needs.
//!
//! `forge agent provision` creates:
//! 1. Agent identity with appropriate capabilities
//! 2. Ed25519 signing keypair
//! 3. Scoped bearer token (time-limited)
//! 4. (Optional) Claim on an exploration approach
//!
//! Output is a JSON config that agents consume directly — no manual steps.

use anyhow::{bail, Context, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;
use serde::Serialize;

/// JSON config output — everything an agent needs to connect and work.
#[derive(Serialize)]
pub struct AgentConfig {
    /// Server URL to connect to.
    pub server_url: String,
    /// Bearer token for authentication.
    pub token: String,
    /// Agent's identity UUID.
    pub identity: String,
    /// Agent's display name.
    pub name: String,
    /// Token expiry (ISO 8601 or "never").
    pub token_expires: String,
    /// Scopes granted to the token.
    pub scopes: Vec<String>,
    /// Exploration goal ID (if assigned).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,
    /// Exploration approach name (if assigned).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approach: Option<String>,
    /// Branch to work on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// Provision a single agent.
pub fn provision(
    name: Option<&str>,
    runtime: &str,
    server_url: &str,
    expiry_hours: u64,
    scope_str: &str,
    goal_id: Option<&str>,
    approach_name: Option<&str>,
) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let default_name = format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let agent_name = name.unwrap_or(&default_name);

    // 1. Create agent identity.
    let identity = repo.create_identity(
        agent_name,
        IdentityKind::Agent { runtime: runtime.to_string() },
    )?;
    eprintln!("Created identity: {} ({})", agent_name, identity.id);

    // 2. Grant capabilities.
    let caps = if scope_str == "*" {
        vec![Capability {
            scope: CapabilityScope::Global,
            permissions: Permissions::all(),
            expires_at: None,
        }]
    } else {
        // Parse scopes to determine capabilities.
        let mut caps = vec![Capability {
            scope: CapabilityScope::Global,
            permissions: Permissions::read_only(),
            expires_at: None,
        }];
        if scope_str.contains("write") {
            caps.push(Capability {
                scope: CapabilityScope::Global,
                permissions: Permissions::read_write(),
                expires_at: None,
            });
        }
        caps
    };
    repo.grant_capabilities(&identity.id, &caps)?;

    // 3. Generate keypair.
    repo.generate_keypair(&identity.id)?;
    eprintln!("Generated keypair");

    // 4. Generate scoped token.
    let kp = repo.load_keypair(&identity.id)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock error")?
        .as_micros() as i64;

    let expiry_micros = if expiry_hours == 0 { 0 } else {
        now + (expiry_hours as i64 * 3_600_000_000)
    };

    let scopes = TokenScopes::decode(scope_str);
    let token = if scopes.is_admin() {
        generate_token(identity.id, &kp.signing_key, expiry_micros)
    } else {
        generate_token_v2(identity.id, &kp.signing_key, expiry_micros, &scopes)
    };
    eprintln!("Generated token (expires in {}h)", expiry_hours);

    // 5. Optionally claim exploration approach.
    let (goal_out, approach_out, branch_out) = if let Some(gid_prefix) = goal_id {
        let goals = repo.list_goals()?;
        let matched: Vec<_> = goals.iter()
            .filter(|(id, _)| id.to_hex().starts_with(gid_prefix))
            .collect();
        if matched.is_empty() {
            bail!("no goal matching '{}'", gid_prefix);
        }
        let (gid, _goal) = matched[0];

        let approach = approach_name.unwrap_or(agent_name);
        match repo.create_approach(gid, approach, identity.id) {
            Ok(ref_name) => {
                eprintln!("Claimed approach '{}' on goal {}", approach, &gid.to_hex()[..12]);
                (Some(gid.to_hex()[..16].to_string()), Some(approach.to_string()), Some(ref_name))
            }
            Err(e) => {
                eprintln!("Warning: could not claim approach: {}", e);
                (Some(gid.to_hex()[..16].to_string()), None, None)
            }
        }
    } else {
        (None, None, None)
    };

    // 6. Output JSON config.
    let expires_str = if expiry_hours == 0 {
        "never".to_string()
    } else {
        format!("{}h from now", expiry_hours)
    };

    let config = AgentConfig {
        server_url: server_url.to_string(),
        token,
        identity: identity.id.to_string(),
        name: agent_name.to_string(),
        token_expires: expires_str,
        scopes: scopes.as_strings().to_vec(),
        goal_id: goal_out,
        approach: approach_out,
        branch: branch_out,
    };

    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

/// Provision multiple agents for a goal, each with its own approach.
pub fn provision_batch(
    count: usize,
    runtime: &str,
    server_url: &str,
    expiry_hours: u64,
    goal_prefix: &str,
) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    // Find goal.
    let goals = repo.list_goals()?;
    let matched: Vec<_> = goals.iter()
        .filter(|(id, _)| id.to_hex().starts_with(goal_prefix))
        .collect();
    if matched.is_empty() {
        bail!("no goal matching '{}'", goal_prefix);
    }
    let (goal_id, goal) = matched[0];
    eprintln!("Goal: {} ({})", goal.description, &goal_id.to_hex()[..12]);

    let mut configs = Vec::new();
    for i in 0..count {
        let agent_name = format!("agent-{}", i);
        let approach_name = format!("approach-{}", i);

        // Create identity.
        let identity = repo.create_identity(
            &agent_name,
            IdentityKind::Agent { runtime: runtime.to_string() },
        )?;

        // Grant capabilities.
        repo.grant_capabilities(&identity.id, &[
            Capability {
                scope: CapabilityScope::Global,
                permissions: Permissions::read_write(),
                expires_at: None,
            },
        ])?;

        // Generate keypair.
        repo.generate_keypair(&identity.id)?;

        // Generate token.
        let kp = repo.load_keypair(&identity.id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock error")?
            .as_micros() as i64;
        let expiry_micros = now + (expiry_hours as i64 * 3_600_000_000);
        let scopes = TokenScopes::decode("read,write,attest");
        let token = generate_token_v2(identity.id, &kp.signing_key, expiry_micros, &scopes);

        // Claim approach.
        let branch = match repo.create_approach(goal_id, &approach_name, identity.id) {
            Ok(ref_name) => Some(ref_name),
            Err(e) => {
                eprintln!("Warning: agent-{} could not claim approach: {}", i, e);
                None
            }
        };

        configs.push(AgentConfig {
            server_url: server_url.to_string(),
            token,
            identity: identity.id.to_string(),
            name: agent_name,
            token_expires: format!("{}h from now", expiry_hours),
            scopes: scopes.as_strings().to_vec(),
            goal_id: Some(goal_id.to_hex()[..16].to_string()),
            approach: Some(approach_name),
            branch,
        });

        eprintln!("Provisioned agent-{}", i);
    }

    println!("{}", serde_json::to_string_pretty(&configs)?);
    eprintln!("\n{} agents provisioned for goal '{}'", count, goal.description);
    Ok(())
}
