use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    if !repo.root().join(".git").exists() {
        bail!("no .git directory found at {}", repo.root().display());
    }

    // Get all forge changesets (newest first from log, we'll reverse).
    let mut entries = repo.log(usize::MAX)?;
    entries.reverse(); // oldest first for export

    // Build mapping of forge IDs that already have a git SHA (imported from git).
    let mut forge_to_git: HashMap<ObjectId, String> = HashMap::new();
    for (id, cs) in &entries {
        if let Some(sha) = cs.metadata.get("git.sha") {
            forge_to_git.insert(*id, sha.clone());
        }
    }

    let to_export: Vec<&(ObjectId, Changeset)> = entries
        .iter()
        .filter(|(_, cs)| !cs.metadata.contains_key("git.sha"))
        .collect();

    if to_export.is_empty() {
        println!("Nothing to export (all changesets originated from git)");
        return Ok(());
    }

    println!("Exporting {} forge-native changesets to git...", to_export.len());

    let root = repo.root().to_path_buf();

    for (i, (forge_id, cs)) in to_export.iter().enumerate() {
        // Recursively write the forge tree into git's object store.
        let git_tree = write_forge_tree_to_git(&repo, &root, &cs.tree)?;

        // Map parent forge IDs to git SHAs.
        let parent_args: Vec<String> = cs
            .parents
            .iter()
            .filter_map(|p| forge_to_git.get(p))
            .flat_map(|sha| ["-p".to_string(), sha.clone()])
            .collect();

        let timestamp_secs = cs.timestamp / 1_000_000;
        let git_sha = git_commit_tree(&root, &git_tree, &parent_args, &cs.message, timestamp_secs)?;

        forge_to_git.insert(*forge_id, git_sha.clone());

        let short_msg: String = cs.message.chars().take(60).collect();
        println!(
            "  [{}/{}] {} -> {} {}",
            i + 1,
            to_export.len(),
            forge_id,
            &git_sha[..10.min(git_sha.len())],
            short_msg,
        );
    }

    // Update git branch to point at the latest exported commit.
    if let Some((forge_id, _)) = to_export.last() {
        if let Some(git_sha) = forge_to_git.get(forge_id) {
            let branch = git_current_branch(&root)?;
            let refname = format!("refs/heads/{}", branch);
            git_update_ref(&root, &refname, git_sha)?;
            println!("\ngit {} -> {}", branch, &git_sha[..10.min(git_sha.len())]);
        }
    }

    println!("Exported {} changesets to git", to_export.len());
    Ok(())
}

// ── Recursive tree writer ──────────────────────────────────────────

fn write_forge_tree_to_git(repo: &Repository, root: &Path, tree_id: &ObjectId) -> Result<String> {
    let obj = repo
        .get_object(tree_id)?
        .ok_or_else(|| anyhow::anyhow!("tree not found: {}", tree_id))?;

    let tree = match obj {
        Object::Tree(t) => t,
        _ => bail!("expected tree object, got something else for {}", tree_id),
    };

    let mut mktree_input = String::new();
    for (name, entry) in &tree.entries {
        match entry.kind {
            EntryKind::File | EntryKind::Symlink => {
                let mode = match entry.kind {
                    EntryKind::Symlink => "120000",
                    _ if entry.executable => "100755",
                    _ => "100644",
                };
                let blob_obj = repo
                    .get_object(&entry.id)?
                    .ok_or_else(|| anyhow::anyhow!("blob not found: {}", entry.id))?;
                let data = match blob_obj {
                    Object::Blob(b) => b.data,
                    _ => bail!("expected blob for file entry {}", name),
                };
                let hash = git_hash_object(root, &data)?;
                mktree_input.push_str(&format!("{} blob {}\t{}\n", mode, hash, name));
            }
            EntryKind::Directory => {
                let hash = write_forge_tree_to_git(repo, root, &entry.id)?;
                mktree_input.push_str(&format!("040000 tree {}\t{}\n", hash, name));
            }
        }
    }

    git_mktree(root, &mktree_input)
}

// ── Git plumbing wrappers ──────────────────────────────────────────

fn git_current_branch(root: &Path) -> Result<String> {
    let out = Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        return Ok("main".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn git_hash_object(root: &Path, data: &[u8]) -> Result<String> {
    let mut child = Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    use std::io::Write;
    child.stdin.take().unwrap().write_all(data)?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("git hash-object failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn git_mktree(root: &Path, input: &str) -> Result<String> {
    let mut child = Command::new("git")
        .args(["mktree"])
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    use std::io::Write;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("git mktree failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn git_commit_tree(
    root: &Path,
    tree_hash: &str,
    parent_args: &[String],
    message: &str,
    timestamp_secs: i64,
) -> Result<String> {
    let date = format!("{} +0000", timestamp_secs);
    let mut cmd = Command::new("git");
    cmd.args(["commit-tree", tree_hash])
        .args(parent_args)
        .args(["-m", message])
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date)
        .current_dir(root);

    let out = cmd.output()?;
    if !out.status.success() {
        bail!("git commit-tree failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn git_update_ref(root: &Path, refname: &str, sha: &str) -> Result<()> {
    let out = Command::new("git")
        .args(["update-ref", refname, sha])
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        bail!("git update-ref failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}
