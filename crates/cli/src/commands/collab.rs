//! Multi-agent collaboration — spawn agents on branches, track tasks, review work.
//!
//! Workflow:
//! 1. `forge collab spawn --task "add auth" [--branch feature/auth]`
//!    Creates agent identity + branch + keygen + token + writes task to scratchpad
//! 2. Agent works on its branch (commits, reads/writes scratchpad)
//! 3. `forge collab list` — shows all active agent tasks
//! 4. `forge collab review <branch>` — shows what the agent did
//! 5. `forge merge <branch>` — merge the agent's work

use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

/// Spawn a new agent on a dedicated branch.
pub fn spawn(task: &str, branch: Option<&str>, runtime: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    // Generate a branch name from the task if not provided.
    let branch_name = match branch {
        Some(b) => b.to_string(),
        None => {
            let slug: String = task.chars()
                .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
                .collect::<String>()
                .trim_matches('-')
                .to_string();
            let short = if slug.len() > 40 { &slug[..40] } else { &slug };
            format!("agent/{}", short.trim_end_matches('-'))
        }
    };

    // Check branch doesn't already exist.
    let ref_name = format!("refs/heads/{}", branch_name);
    if repo.resolve_ref(&ref_name)?.is_some() {
        bail!("branch '{}' already exists", branch_name);
    }

    // Create agent identity.
    let rt = runtime.unwrap_or("claude-code");
    let agent_name = format!("agent-{}", &branch_name.replace('/', "-"));
    let identity = repo.create_identity(&agent_name, IdentityKind::Agent { runtime: rt.to_string() })?;

    // Create the branch at current HEAD.
    let head = repo.resolve_head()?
        .ok_or_else(|| anyhow::anyhow!("no commits yet — make an initial commit first"))?;
    repo.set_ref(&ref_name, &Ref::Direct(head))?;

    // Generate keypair for the agent.
    repo.generate_keypair(&identity.id)?;

    // Write the task assignment to the agent's scratchpad (as a ref → blob).
    let task_json = serde_json::json!({
        "task": task,
        "branch": branch_name,
        "identity": identity.id.to_string(),
        "status": "active",
        "spawned_at": chrono::Utc::now().to_rfc3339(),
        "spawned_from": repo.head_branch()?.unwrap_or_else(|| "unknown".into()),
    });
    let blob = Object::Blob(Blob { data: task_json.to_string().into_bytes() });
    let blob_id = repo.put_object(&blob)?;
    repo.set_ref(&format!("refs/agent/{}/task", identity.id), &Ref::Direct(blob_id))?;

    // Store cross-reference for `collab list`.
    repo.set_config(
        &format!("collab.agents.{}", branch_name.replace('/', ".")),
        &identity.id.to_string(),
    )?;

    // Generate a scoped token for the agent.
    let kp = repo.load_keypair(&identity.id)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock before UNIX epoch"))?
        .as_micros() as i64;
    let expiry = now + 24 * 3600 * 1_000_000; // 24 hours
    let scope_str = format!("read,write,ref:refs/heads/{}", branch_name);
    let scopes = TokenScopes::decode(&scope_str);
    let token = generate_token_v2(identity.id, &kp.signing_key, expiry, &scopes);

    println!("Spawned agent for task: {}", task);
    println!("  identity:  {} ({})", identity.id, agent_name);
    println!("  branch:    {}", branch_name);
    println!("  runtime:   {}", rt);
    println!("  token:     {}", token);
    println!();
    println!("The agent should:");
    println!("  1. forge checkout {}", branch_name);
    println!("  2. Work on the task: {}", task);
    println!("  3. forge commit -m \"done\" --intent agent-task");
    println!();
    println!("Then review with: forge collab review {}", branch_name);

    Ok(())
}

/// List all active agent collaborations.
pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let all_configs = repo.list_config_prefix("collab.agents.")?;

    if all_configs.is_empty() {
        println!("No active agent collaborations.");
        println!("Spawn one with: forge collab spawn --task \"description\"");
        return Ok(());
    }

    println!("{:<30} {:<12} {:<18} TASK", "BRANCH", "STATUS", "IDENTITY");
    println!("{}", "-".repeat(90));

    for (key, identity_id_str) in &all_configs {
        let branch = key.strip_prefix("collab.agents.")
            .unwrap_or(key)
            .replace('.', "/");

        // Read the task scratchpad entry for this agent.
        let (status, task_desc) = read_agent_task(&repo, identity_id_str);

        // Check if branch still exists.
        let branch_ref = format!("refs/heads/{}", branch);
        let exists = repo.resolve_ref(&branch_ref).ok().flatten().is_some();
        let display_status = if !exists { "merged" } else { &status };

        let short_id = &identity_id_str[..16.min(identity_id_str.len())];
        let short_task = if task_desc.len() > 40 {
            format!("{}...", &task_desc[..37])
        } else {
            task_desc
        };

        println!("{:<30} {:<12} {:<18} {}", branch, display_status, short_id, short_task);
    }

    Ok(())
}

/// Review an agent's work — show commits since branch point.
pub fn review(branch: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let branch_ref = format!("refs/heads/{}", branch);
    let branch_head = repo.resolve_ref(&branch_ref)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch))?;

    let main_branch = repo.head_branch()?.unwrap_or_else(|| "main".into());
    let main_ref = format!("refs/heads/{}", main_branch);
    let main_head = repo.resolve_ref(&main_ref)?
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {}", main_branch))?;

    // Show agent task info.
    let agent_id_str = repo.get_config(&format!("collab.agents.{}", branch.replace('/', ".")))?;
    if let Some(ref id_str) = agent_id_str {
        let (_, task_desc) = read_agent_task(&repo, id_str);
        if task_desc != "-" {
            println!("Task: {}", task_desc);
            println!();
        }
    }

    // Find common ancestor.
    let ancestor = repo.find_merge_base(&main_head, &branch_head)?;

    // List commits on the branch since the common ancestor.
    println!("Commits on '{}':", branch);
    let mut current = branch_head;
    let mut count = 0;
    loop {
        if ancestor.is_some() && Some(current) == ancestor {
            break;
        }
        if count > 50 {
            println!("  ... (truncated)");
            break;
        }
        match repo.get_object(&current)? {
            Some(Object::Changeset(cs)) => {
                let short = &current.to_string()[..16];
                let first_line = cs.message.lines().next().unwrap_or("");
                println!("  {} {}", short, first_line);
                current = match cs.parents.first() {
                    Some(p) => *p,
                    None => break,
                };
                count += 1;
            }
            _ => break,
        }
    }

    if count == 0 {
        println!("  (no new commits)");
    }
    println!();
    println!("To merge: forge merge {}", branch);

    Ok(())
}

/// Mark a collaboration as complete.
pub fn complete(branch: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let config_key = format!("collab.agents.{}", branch.replace('/', "."));
    let agent_id_str = repo.get_config(&config_key)?;

    if let Some(ref id_str) = agent_id_str {
        if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
            let id = IdentityId::from_bytes(*uuid.as_bytes());
            // Update the task status in the scratchpad.
            let task_ref = format!("refs/agent/{}/task", id);
            if let Some(blob_id) = repo.resolve_ref(&task_ref)?
                && let Some(Object::Blob(blob)) = repo.get_object(&blob_id)?
                    && let Ok(text) = std::str::from_utf8(&blob.data)
                        && let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) {
                            v["status"] = serde_json::json!("completed");
                            let updated = Object::Blob(Blob { data: v.to_string().into_bytes() });
                            let new_id = repo.put_object(&updated)?;
                            repo.set_ref(&task_ref, &Ref::Direct(new_id))?;
                        }
        }
    } else {
        bail!("no agent collaboration found for branch '{}'", branch);
    }

    println!("Marked '{}' as completed", branch);
    Ok(())
}

/// Read the task description and status from an agent's scratchpad.
fn read_agent_task(repo: &Repository, identity_id_str: &str) -> (String, String) {
    let uuid = match uuid::Uuid::parse_str(identity_id_str) {
        Ok(u) => u,
        Err(_) => return ("unknown".into(), "-".into()),
    };
    let id = IdentityId::from_bytes(*uuid.as_bytes());
    let task_ref = format!("refs/agent/{}/task", id);

    let blob_id = match repo.resolve_ref(&task_ref) {
        Ok(Some(id)) => id,
        _ => return ("unknown".into(), "-".into()),
    };

    let blob = match repo.get_object(&blob_id) {
        Ok(Some(Object::Blob(b))) => b,
        _ => return ("unknown".into(), "-".into()),
    };

    let text = match std::str::from_utf8(&blob.data) {
        Ok(t) => t,
        Err(_) => return ("unknown".into(), "-".into()),
    };

    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return ("unknown".into(), "-".into()),
    };

    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();
    let task = v.get("task").and_then(|s| s.as_str()).unwrap_or("-").to_string();
    (status, task)
}
