use anyhow::Result;
use gritgrub_store::Repository;

pub fn run() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let branch = repo.head_branch()?.unwrap_or_else(|| "detached".into());
    let has_head = repo.resolve_head()?.is_some();

    if !has_head {
        println!("On branch {} (no changesets yet)", branch);
    } else {
        println!("On branch {}", branch);
    }

    let status = repo.status()?;

    if status.is_clean() {
        if has_head {
            println!("No changes");
        } else {
            println!("No files in working directory");
        }
        return Ok(());
    }

    println!();
    for path in &status.added {
        println!("  + {}", path);
    }
    for path in &status.modified {
        println!("  ~ {}", path);
    }
    for path in &status.deleted {
        println!("  - {}", path);
    }

    Ok(())
}
