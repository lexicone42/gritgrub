use anyhow::Result;
use gritgrub_store::Repository;

pub fn run(target: &str, hard: bool) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let (id, _) = repo.find_by_prefix(target)?;
    repo.reset(&id, hard)?;
    if hard {
        println!("HEAD reset to {} (working tree updated)", id);
    } else {
        println!("HEAD reset to {} (soft — working tree unchanged)", id);
    }
    Ok(())
}
