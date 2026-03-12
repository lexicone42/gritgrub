use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let active_id = repo.local_identity()?;
    let identities = repo.list_identities()?;

    if identities.is_empty() {
        println!("No identities registered");
        println!("  Active (config-only): {} ({})",
            active_id,
            repo.get_config("identity.name")?.unwrap_or_default(),
        );
        return Ok(());
    }

    for ident in &identities {
        let marker = if ident.id == active_id { "* " } else { "  " };
        let caps = repo.get_capabilities(&ident.id)?;
        let cap_summary = if caps.is_empty() {
            "no capabilities".to_string()
        } else {
            caps.iter().map(|c| format!("{}", c.permissions)).collect::<Vec<_>>().join(", ")
        };
        println!("{}{:36}  {:16}  {}  [{}]", marker, ident.id, ident.kind, ident.name, cap_summary);
    }

    Ok(())
}

pub fn create(name: &str, kind: &str, runtime: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let identity_kind = match kind {
        "human" => IdentityKind::Human,
        "agent" => {
            let rt = runtime.unwrap_or("unknown");
            IdentityKind::Agent { runtime: rt.to_string() }
        }
        _ => bail!("unknown identity kind '{}' — use 'human' or 'agent'", kind),
    };

    let identity = repo.create_identity(name, identity_kind)?;
    println!("Created identity:");
    println!("  id:    {}", identity.id);
    println!("  name:  {}", identity.name);
    println!("  kind:  {}", identity.kind);
    println!();
    println!("  Hint: grant capabilities with `forge identity grant {}`", identity.id);

    Ok(())
}

pub fn show(id_str: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let uuid = uuid::Uuid::parse_str(id_str)
        .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
    let id = IdentityId(uuid);

    match repo.get_identity(&id)? {
        Some(ident) => {
            let active_id = repo.local_identity()?;
            let active = if ident.id == active_id { " (active)" } else { "" };

            println!("id    {}{}", ident.id, active);
            println!("name  {}", ident.name);
            println!("kind  {}", ident.kind);

            if let Some(dt) = chrono::DateTime::from_timestamp_micros(ident.created_at) {
                println!("created  {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
            }

            let caps = repo.get_capabilities(&id)?;
            if caps.is_empty() {
                println!("\nNo capabilities granted");
            } else {
                println!("\nCapabilities:");
                for cap in &caps {
                    let scope_str = match &cap.scope {
                        CapabilityScope::Global => "global".to_string(),
                        CapabilityScope::Repository(r) => format!("repo:{}", r),
                        CapabilityScope::Path { repo, pattern } => format!("path:{}:{}", repo, pattern),
                        CapabilityScope::Branch { repo, pattern } => format!("branch:{}:{}", repo, pattern),
                    };
                    let expiry = match cap.expires_at {
                        Some(t) => chrono::DateTime::from_timestamp_micros(t)
                            .map(|dt| dt.format(" (expires %Y-%m-%d)").to_string())
                            .unwrap_or_default(),
                        None => String::new(),
                    };
                    println!("  {} scope={}{}", cap.permissions, scope_str, expiry);
                }
            }
        }
        None => bail!("identity not found: {}", id),
    }

    Ok(())
}

pub fn gen_token(id_str: Option<&str>, expiry_hours: u64, scope_str: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let id = match id_str {
        Some(s) => {
            let uuid = uuid::Uuid::parse_str(s)
                .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
            IdentityId(uuid)
        }
        None => repo.local_identity()?,
    };

    let kp = repo.load_keypair(&id)?;

    let expiry_micros = if expiry_hours == 0 {
        0
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        now + (expiry_hours as i64 * 3_600_000_000)
    };

    let scopes = TokenScopes::decode(scope_str);

    // SE-17: Warn if scopes are empty (deny-all token is useless).
    if scopes.as_strings().is_empty() {
        bail!("no valid scopes specified — use '*' for admin or specify: read, write, attest, identity, ref:<pattern>");
    }

    let token = if scopes.is_admin() {
        // Use v1 format for admin tokens (simpler, backward compat).
        generate_token(id, &kp.signing_key, expiry_micros)
    } else {
        generate_token_v2(id, &kp.signing_key, expiry_micros, &scopes)
    };

    // Print info to stderr, token to stdout (capturable: TOKEN=$(forge identity token)).
    if scopes.is_admin() {
        if expiry_hours == 0 {
            eprintln!("Generated non-expiring admin token for {}", id);
        } else {
            eprintln!("Generated admin token for {} (expires in {}h)", id, expiry_hours);
        }
    } else {
        eprintln!("Generated scoped token for {} (scopes: {})", id, scope_str);
        if expiry_hours > 0 {
            eprintln!("  expires in {}h", expiry_hours);
        }
    }
    println!("{}", token);

    Ok(())
}

pub fn keygen(id_str: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let id = match id_str {
        Some(s) => {
            let uuid = uuid::Uuid::parse_str(s)
                .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
            IdentityId(uuid)
        }
        None => repo.local_identity()?,
    };

    let kp = repo.generate_keypair(&id)?;
    let pub_hex: String = kp.public_bytes().iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("Generated Ed25519 signing keypair for {}", id);
    println!("  public key:  {}", pub_hex);
    println!("  secret key:  stored in .forge/keys/{}.secret", id);
    println!("  public ref:  refs/keys/{}", id);

    Ok(())
}

pub fn activate(id_str: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let uuid = uuid::Uuid::parse_str(id_str)
        .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
    let id = IdentityId(uuid);

    match repo.get_identity(&id)? {
        Some(ident) => {
            repo.set_active_identity(&id)?;
            repo.set_config("identity.name", &ident.name)?;
            println!("Active identity: {} ({})", ident.id, ident.name);
        }
        None => bail!("identity not found: {}", id),
    }

    Ok(())
}

pub fn grant(id_str: &str, scope_str: &str, perm_str: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let uuid = uuid::Uuid::parse_str(id_str)
        .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
    let id = IdentityId(uuid);

    // Verify identity exists.
    if repo.get_identity(&id)?.is_none() {
        bail!("identity not found: {}", id);
    }

    let scope = match scope_str {
        "global" => CapabilityScope::Global,
        s if s.starts_with("branch:") => {
            let pattern = s.strip_prefix("branch:").unwrap();
            CapabilityScope::Branch {
                repo: String::new(), // local repo
                pattern: pattern.to_string(),
            }
        }
        s if s.starts_with("path:") => {
            let pattern = s.strip_prefix("path:").unwrap();
            CapabilityScope::Path {
                repo: String::new(),
                pattern: pattern.to_string(),
            }
        }
        _ => bail!("unknown scope '{}' — use global, branch:<pattern>, or path:<pattern>", scope_str),
    };

    let permissions = match perm_str {
        "r" => Permissions::read_only(),
        "rw" => Permissions::read_write(),
        "admin" => Permissions::all(),
        "rwcd" => Permissions(Permissions::READ | Permissions::WRITE | Permissions::CREATE | Permissions::DELETE),
        _ => bail!("unknown permissions '{}' — use r, rw, rwcd, or admin", perm_str),
    };

    let cap = Capability {
        scope,
        permissions,
        expires_at: None,
    };

    repo.grant_capabilities(&id, &[cap])?;
    println!("Granted {} (scope: {}) to {}", permissions, scope_str, id);

    Ok(())
}

pub fn capabilities(id_str: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let id = match id_str {
        Some(s) => {
            let uuid = uuid::Uuid::parse_str(s)
                .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
            IdentityId(uuid)
        }
        None => repo.local_identity()?,
    };

    let caps = repo.get_capabilities(&id)?;
    if caps.is_empty() {
        println!("No capabilities for {}", id);
        println!("  Grant with: forge identity grant {}", id);
        return Ok(());
    }

    println!("Capabilities for {}:", id);
    for cap in &caps {
        let scope_str = match &cap.scope {
            CapabilityScope::Global => "global".to_string(),
            CapabilityScope::Repository(r) => format!("repo:{}", r),
            CapabilityScope::Path { pattern, .. } => format!("path:{}", pattern),
            CapabilityScope::Branch { pattern, .. } => format!("branch:{}", pattern),
        };
        println!("  {} scope={}", cap.permissions, scope_str);
    }

    Ok(())
}

pub fn revoke_token(token: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    repo.revoke_token(token)?;
    println!("Token revoked");
    Ok(())
}
