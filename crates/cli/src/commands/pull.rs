use anyhow::Result;
use gritgrub_core::Object;
use gritgrub_store::Repository;
use gritgrub_api::ForgeClient;

pub fn run(remote_name: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let remote = remote_name.unwrap_or("origin");

    let url = repo.get_remote_url(remote)?
        .ok_or_else(|| anyhow::anyhow!("remote '{}' not found", remote))?;

    let branch = repo.head_branch()?
        .ok_or_else(|| anyhow::anyhow!("HEAD is detached — checkout a branch first"))?;
    let ref_name = format!("refs/heads/{}", branch);

    let token = repo.get_config(&format!("remote.{}.token", remote))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut client = ForgeClient::connect(&url, token.as_deref()).await?;
        let id = client.pull(&repo, &ref_name, &ref_name).await?;

        // Update working tree.
        if let Some(Object::Changeset(cs)) = repo.get_object(&id)? {
            repo.force_checkout_tree(&cs.tree)?;
        }

        println!("Updated {} to {}", branch, id);
        Ok(())
    })
}
