use anyhow::Result;
use gritgrub_core::Object;
use gritgrub_store::{Repository, MergeResult};

pub fn run(branch: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let author = repo.local_identity()?;

    match repo.merge(branch, author)? {
        MergeResult::FastForward(id) => {
            if let Some(Object::Changeset(cs)) = repo.get_object(&id)? {
                repo.force_checkout_tree(&cs.tree)?;
            }
            println!("Fast-forward to {}", id);
        }
        MergeResult::AlreadyUpToDate => {
            println!("Already up to date.");
        }
        MergeResult::Merged(id) => {
            if let Some(Object::Changeset(cs)) = repo.get_object(&id)? {
                repo.force_checkout_tree(&cs.tree)?;
            }
            println!("Merge made: {}", id);
        }
        MergeResult::Conflict(paths) => {
            println!("CONFLICT — automatic merge failed.");
            println!("Conflicting paths:");
            for p in &paths {
                println!("  {}", p);
            }
            anyhow::bail!("fix conflicts and commit the result");
        }
    }
    Ok(())
}
