use anyhow::Result;
use gritgrub_store::Repository;

pub fn run(name: Option<&str>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repository::init(&cwd)?;

    if let Some(name) = name {
        repo.set_config("identity.name", name)?;
    }

    let identity = repo.local_identity()?;
    let author_name = repo.get_config("identity.name")?.unwrap_or_default();

    println!(
        "Initialized forge repository in {}",
        cwd.join(".forge").display()
    );
    println!("  identity: {} ({})", identity, author_name);

    Ok(())
}
