use anyhow::Result;
use gritgrub_store::Repository;

pub fn get(key: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    match repo.get_config(key)? {
        Some(val) => println!("{}", val),
        None => println!("(not set)"),
    }
    Ok(())
}

pub fn set(key: &str, value: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    repo.set_config(key, value)?;
    Ok(())
}
