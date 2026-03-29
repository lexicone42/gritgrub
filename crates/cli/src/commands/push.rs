use anyhow::Result;
use gritgrub_store::Repository;
use gritgrub_api::ForgeClient;

pub fn run(remote_name: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let remote = remote_name.unwrap_or("origin");

    let url = repo.get_remote_url(remote)?
        .ok_or_else(|| anyhow::anyhow!("remote '{}' not found", remote))?;

    // Resolve the current branch.
    let branch = repo.head_branch()?
        .ok_or_else(|| anyhow::anyhow!("HEAD is detached — checkout a branch first"))?;
    let local_ref = format!("refs/heads/{}", branch);
    let remote_ref = local_ref.clone();

    // Load token from config.
    let token = repo.get_config(&format!("remote.{}.token", remote))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut client = ForgeClient::connect(&url, token.as_deref()).await?;
        client.push(&repo, &local_ref, &remote_ref).await?;
        println!("Pushed {} -> {}:{}", branch, remote, branch);
        Ok(())
    })
}
