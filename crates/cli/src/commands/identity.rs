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

pub fn gen_token(id_str: Option<&str>, expiry_hours: u64) -> Result<()> {
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
        0 // non-expiring
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        now + (expiry_hours as i64 * 3_600_000_000)
    };

    let token = gritgrub_core::generate_token(id, &kp.signing_key, expiry_micros);

    if expiry_hours == 0 {
        eprintln!("Generated non-expiring token for {}", id);
    } else {
        eprintln!("Generated token for {} (expires in {}h)", id, expiry_hours);
    }
    // Print only the token to stdout so it can be captured: `TOKEN=$(forge identity token)`
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
