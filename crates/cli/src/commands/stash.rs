use anyhow::Result;
use gritgrub_store::Repository;

pub fn save(message: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let idx = repo.stash_save(message.unwrap_or(""))?;
    println!("Saved working directory to stash@{{{}}}", idx);
    Ok(())
}

pub fn pop() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let id = repo.stash_pop()?;
    println!("Applied stash and restored working tree ({})", id);
    Ok(())
}

pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let entries = repo.stash_list()?;
    if entries.is_empty() {
        println!("No stash entries.");
    }
    for (idx, msg) in &entries {
        println!("stash@{{{}}}  {}", idx, msg);
    }
    Ok(())
}
