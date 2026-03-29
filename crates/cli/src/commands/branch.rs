use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run(name: Option<&str>, delete: bool) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    if delete {
        let branch_name = name.ok_or_else(|| anyhow::anyhow!("branch name required for -d"))?;
        let current = repo.head_branch()?;
        if current.as_deref() == Some(branch_name) {
            bail!("cannot delete the current branch '{}'", branch_name);
        }
        let ref_name = format!("refs/heads/{}", branch_name);
        if !repo.delete_ref(&ref_name)? {
            bail!("branch '{}' not found", branch_name);
        }
        println!("Deleted branch '{}'", branch_name);
        return Ok(());
    }

    match name {
        // List branches.
        None => {
            let current = repo.head_branch()?;
            let refs = repo.list_refs("refs/heads/")?;

            if refs.is_empty() {
                println!("No branches (no changesets yet)");
                return Ok(());
            }

            for (ref_name, reference) in &refs {
                let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
                let marker = if Some(branch.to_string()) == current { "* " } else { "  " };

                let id = match reference {
                    Ref::Direct(id) => format!("{}", id),
                    Ref::Symbolic(target) => format!("-> {}", target),
                };

                println!("{}{:16} {}", marker, branch, id);
            }
        }
        // Create a new branch at HEAD.
        Some(branch_name) => {
            let head = repo.resolve_head()?
                .ok_or_else(|| anyhow::anyhow!("cannot create branch: no changesets yet"))?;

            let ref_name = format!("refs/heads/{}", branch_name);
            repo.set_ref(&ref_name, &Ref::Direct(head))?;
            println!("Created branch '{}' at {}", branch_name, head);
        }
    }

    Ok(())
}
