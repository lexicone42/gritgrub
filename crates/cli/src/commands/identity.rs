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
        println!("{}{:36}  {:16}  {}", marker, ident.id, ident.kind, ident.name);
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
        }
        None => bail!("identity not found: {}", id),
    }

    Ok(())
}

pub fn activate(id_str: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let uuid = uuid::Uuid::parse_str(id_str)
        .map_err(|e| anyhow::anyhow!("invalid UUID: {}", e))?;
    let id = IdentityId(uuid);

    // Verify identity exists.
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
