use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

/// Write a key-value entry to the agent scratchpad.
/// Stored as a blob in the object store, referenced via refs/agent/<identity>/<key>.
pub fn write(key: &str, value: Option<&str>, file: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let identity = repo.local_identity()?;

    let data = match (value, file) {
        (Some(v), _) => v.as_bytes().to_vec(),
        (None, Some(f)) => std::fs::read(f)?,
        (None, None) => {
            // Read from stdin.
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    let blob = Object::Blob(Blob { data });
    let id = repo.put_object(&blob)?;

    let ref_name = format!("refs/agent/{}/{}", identity, key);
    repo.set_ref(&ref_name, &Ref::Direct(id))?;

    println!("Wrote '{}' ({} bytes) -> {}", key, id, ref_name);
    Ok(())
}

/// Read a scratchpad entry.
pub fn read(key: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let identity = repo.local_identity()?;

    let ref_name = format!("refs/agent/{}/{}", identity, key);
    let id = repo.resolve_ref(&ref_name)?
        .ok_or_else(|| anyhow::anyhow!("no scratchpad entry '{}'", key))?;

    match repo.get_object(&id)? {
        Some(Object::Blob(blob)) => {
            match std::str::from_utf8(&blob.data) {
                Ok(text) => print!("{}", text),
                Err(_) => {
                    use std::io::Write;
                    std::io::stdout().write_all(&blob.data)?;
                }
            }
        }
        _ => bail!("scratchpad ref points to non-blob: {}", id),
    }

    Ok(())
}

/// List all scratchpad entries for the active identity.
pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let identity = repo.local_identity()?;

    let prefix = format!("refs/agent/{}/", identity);
    let refs = repo.list_refs(&prefix)?;

    if refs.is_empty() {
        println!("No scratchpad entries for {}", identity);
        return Ok(());
    }

    println!("Scratchpad entries for {}:", identity);
    for (ref_name, reference) in &refs {
        let key = ref_name.strip_prefix(&prefix).unwrap_or(ref_name);
        let id = match reference {
            Ref::Direct(id) => *id,
            _ => continue,
        };

        // Show size.
        let size = match repo.get_object(&id)? {
            Some(Object::Blob(b)) => format!("{} bytes", b.data.len()),
            _ => "?".into(),
        };

        println!("  {:24} {} ({})", key, id, size);
    }

    Ok(())
}
