use anyhow::Result;
use gritgrub_store::Repository;

pub fn add(name: &str, url: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    repo.add_remote(name, url)?;
    println!("Added remote '{}' -> {}", name, url);
    Ok(())
}

pub fn remove(name: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    repo.remove_remote(name)?;
    println!("Removed remote '{}'", name);
    Ok(())
}

pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let remotes = repo.list_remotes()?;
    if remotes.is_empty() {
        println!("No remotes configured.");
    } else {
        for (name, url) in &remotes {
            println!("{:16} {}", name, url);
        }
    }
    Ok(())
}
