use anyhow::Result;
use gritgrub_api::ForgeClient;

pub fn run(url: &str, path: Option<&str>) -> Result<()> {
    // Default path: last segment of URL or "repo".
    let default_name = url
        .rsplit('/')
        .next()
        .unwrap_or("repo")
        .trim_end_matches(".git");
    let target = std::path::Path::new(path.unwrap_or(default_name));

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        ForgeClient::clone_repo(url, target, None).await?;
        println!("Cloned into '{}'", target.display());
        Ok(())
    })
}
