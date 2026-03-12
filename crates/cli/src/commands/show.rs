use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

/// Show changeset header + diff against parent (like git show).
pub fn run(id_prefix: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let (id, obj) = match id_prefix {
        Some(prefix) => repo.find_by_prefix(prefix)?,
        None => {
            let head = repo.resolve_head()?
                .ok_or_else(|| anyhow::anyhow!("no changesets yet"))?;
            let obj = repo.get_object(&head)?
                .ok_or_else(|| anyhow::anyhow!("HEAD object missing"))?;
            (head, obj)
        }
    };

    let cs = match obj {
        Object::Changeset(cs) => cs,
        Object::Blob(_) => bail!("{} is a blob, not a changeset", id),
        Object::Tree(_) => bail!("{} is a tree, not a changeset", id),
        Object::Envelope(_) => bail!("{} is an attestation envelope, not a changeset", id),
    };

    // Header.
    let branch = repo.head_branch()?;
    let author_name = repo.get_config("identity.name")?.unwrap_or_default();

    if let Some(ref b) = branch {
        if repo.resolve_head()? == Some(id) {
            println!("changeset  {}  ({})", id, b);
        } else {
            println!("changeset  {}", id);
        }
    } else {
        println!("changeset  {}", id);
    }

    println!("author     {} ({})", cs.author, author_name);

    if let Some(dt) = chrono::DateTime::from_timestamp_micros(cs.timestamp) {
        println!("date       {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    if let Some(ref intent) = cs.intent {
        println!("intent     {}", intent.kind);
        if !intent.rationale.is_empty() {
            println!("rationale  {}", intent.rationale);
        }
    }

    for (k, v) in &cs.metadata {
        println!("meta.{}  {}", k, v);
    }

    println!();
    for line in cs.message.lines() {
        println!("    {}", line);
    }
    println!();

    // Diff against parent.
    let parent_tree = if let Some(pid) = cs.parents.first() {
        match repo.get_object(pid)? {
            Some(Object::Changeset(pcs)) => Some(pcs.tree),
            _ => None,
        }
    } else {
        None
    };

    // Re-use diff logic.
    super::diff::diff_changeset_trees(&repo, parent_tree.as_ref(), &cs.tree)?;

    Ok(())
}
