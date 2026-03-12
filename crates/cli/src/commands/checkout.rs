use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run(target: &str, create_branch: bool) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    if create_branch {
        // Create new branch at HEAD, then switch to it.
        let head = repo.resolve_head()?
            .ok_or_else(|| anyhow::anyhow!("no changesets yet — commit first"))?;

        let branch_ref = format!("refs/heads/{}", target);
        repo.set_ref(&branch_ref, &Ref::Direct(head))?;
        repo.set_ref("HEAD", &Ref::Symbolic(branch_ref))?;
        println!("Created and switched to branch '{}'", target);
        return Ok(());
    }

    // Try as branch name first.
    let branch_ref = format!("refs/heads/{}", target);
    if let Some(id) = repo.resolve_ref(&branch_ref)? {
        let cs = match repo.get_object(&id)? {
            Some(Object::Changeset(cs)) => cs,
            _ => bail!("branch '{}' points to a non-changeset object", target),
        };

        // Only restore tree if HEAD points to a different changeset.
        let current_head = repo.resolve_head()?;
        if current_head != Some(id) {
            repo.checkout_tree(&cs.tree)?;
        }

        repo.set_ref("HEAD", &Ref::Symbolic(branch_ref))?;
        println!("Switched to branch '{}'", target);
        return Ok(());
    }

    // Try as a changeset ID prefix — detached HEAD.
    let (id, obj) = repo.find_by_prefix(target)?;
    match obj {
        Object::Changeset(cs) => {
            repo.checkout_tree(&cs.tree)?;
            repo.set_ref("HEAD", &Ref::Direct(id))?;
            println!("HEAD detached at {}", id);
        }
        _ => bail!("{} is not a changeset", id),
    }

    Ok(())
}
