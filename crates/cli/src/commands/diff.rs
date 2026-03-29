use std::collections::BTreeMap;
use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

/// Show diff between two changesets, or between HEAD and working tree.
pub fn run(from: Option<&str>, to: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    match (from, to) {
        // No args: diff HEAD against working tree (same as status but with content diff).
        (None, None) => {
            let head_id = repo.resolve_head()?
                .ok_or_else(|| anyhow::anyhow!("no changesets yet"))?;
            let (_, head_cs) = repo.find_by_prefix(&head_id.to_hex())?;
            let head_tree = match head_cs {
                Object::Changeset(cs) => cs.tree,
                _ => bail!("HEAD is not a changeset"),
            };
            diff_tree_vs_working(&repo, &head_tree, repo.root())?;
        }
        // One arg: diff that changeset against its parent(s).
        (Some(id), None) => {
            let (_, obj) = repo.find_by_prefix(id)?;
            match obj {
                Object::Changeset(cs) => {
                    let parent_tree = if let Some(pid) = cs.parents.first() {
                        match repo.get_object(pid)? {
                            Some(Object::Changeset(pcs)) => Some(pcs.tree),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    diff_trees(&repo, parent_tree.as_ref(), &cs.tree, String::new())?;
                }
                _ => bail!("object is not a changeset"),
            }
        }
        // Two args: diff from..to.
        (Some(from_id), Some(to_id)) => {
            let (_, from_obj) = repo.find_by_prefix(from_id)?;
            let (_, to_obj) = repo.find_by_prefix(to_id)?;
            let from_tree = match from_obj {
                Object::Changeset(cs) => cs.tree,
                _ => bail!("'from' is not a changeset"),
            };
            let to_tree = match to_obj {
                Object::Changeset(cs) => cs.tree,
                _ => bail!("'to' is not a changeset"),
            };
            diff_trees(&repo, Some(&from_tree), &to_tree, String::new())?;
        }
        _ => bail!("usage: forge diff [<from>] [<to>]"),
    }

    Ok(())
}

/// Public entry point for other commands (e.g., `forge show`).
pub fn diff_changeset_trees(
    repo: &Repository,
    old_tree_id: Option<&ObjectId>,
    new_tree_id: &ObjectId,
) -> Result<()> {
    diff_trees(repo, old_tree_id, new_tree_id, String::new())
}

/// Compare two trees and print file-level diffs.
fn diff_trees(
    repo: &Repository,
    old_tree_id: Option<&ObjectId>,
    new_tree_id: &ObjectId,
    prefix: String,
) -> Result<()> {
    let old_entries = match old_tree_id {
        Some(id) => match repo.get_object(id)? {
            Some(Object::Tree(t)) => t.entries,
            _ => BTreeMap::new(),
        },
        None => BTreeMap::new(),
    };

    let new_entries = match repo.get_object(new_tree_id)? {
        Some(Object::Tree(t)) => t.entries,
        _ => BTreeMap::new(),
    };

    // Added and modified.
    for (name, new_entry) in &new_entries {
        let path = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };

        match old_entries.get(name) {
            Some(old_entry) if old_entry.id == new_entry.id => {
                // Unchanged — skip.
            }
            Some(old_entry) => {
                // Modified.
                match (old_entry.kind, new_entry.kind) {
                    (EntryKind::Directory, EntryKind::Directory) => {
                        diff_trees(repo, Some(&old_entry.id), &new_entry.id, path)?;
                    }
                    (EntryKind::File, EntryKind::File) => {
                        print_file_diff(repo, &path, Some(&old_entry.id), Some(&new_entry.id))?;
                    }
                    _ => {
                        println!("--- a/{}", path);
                        println!("+++ b/{}", path);
                        println!("  (type changed)");
                    }
                }
            }
            None => {
                // Added.
                match new_entry.kind {
                    EntryKind::Directory => {
                        diff_trees(repo, None, &new_entry.id, path)?;
                    }
                    EntryKind::File => {
                        print_file_diff(repo, &path, None, Some(&new_entry.id))?;
                    }
                    EntryKind::Symlink => {
                        println!("+++ b/{} (symlink)", path);
                    }
                }
            }
        }
    }

    // Deleted.
    for (name, old_entry) in &old_entries {
        if !new_entries.contains_key(name) {
            let path = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };
            match old_entry.kind {
                EntryKind::Directory => {
                    print_deleted_tree(repo, &old_entry.id, &path)?;
                }
                EntryKind::File => {
                    print_file_diff(repo, &path, Some(&old_entry.id), None)?;
                }
                EntryKind::Symlink => {
                    println!("--- a/{} (symlink)", path);
                }
            }
        }
    }

    Ok(())
}

fn print_file_diff(
    repo: &Repository,
    path: &str,
    old_id: Option<&ObjectId>,
    new_id: Option<&ObjectId>,
) -> Result<()> {
    let old_text = match old_id {
        Some(id) => match repo.get_object(id)? {
            Some(Object::Blob(b)) => String::from_utf8(b.data).ok(),
            _ => None,
        },
        None => None,
    };

    let new_text = match new_id {
        Some(id) => match repo.get_object(id)? {
            Some(Object::Blob(b)) => String::from_utf8(b.data).ok(),
            _ => None,
        },
        None => None,
    };

    match (&old_text, &new_text) {
        (None, Some(new)) => {
            println!("--- /dev/null");
            println!("+++ b/{}", path);
            for line in new.lines() {
                println!("+{}", line);
            }
            println!();
        }
        (Some(old), None) => {
            println!("--- a/{}", path);
            println!("+++ /dev/null");
            for line in old.lines() {
                println!("-{}", line);
            }
            println!();
        }
        (Some(old), Some(new)) if old != new => {
            println!("--- a/{}", path);
            println!("+++ b/{}", path);
            // Simple line-by-line diff (not a proper unified diff, but functional).
            let old_lines: Vec<&str> = old.lines().collect();
            let new_lines: Vec<&str> = new.lines().collect();
            print_simple_diff(&old_lines, &new_lines);
            println!();
        }
        _ => {
            // Binary or unchanged.
        }
    }

    Ok(())
}

/// Minimal diff: show removed and added lines. Not a proper LCS diff,
/// but enough to see what changed. We'll add a real diff algorithm later.
fn print_simple_diff(old: &[&str], new: &[&str]) {
    // Use a simple longest-common-subsequence approach for small files.
    // For large files, fall back to just showing - and + sections.
    if old.len() + new.len() > 2000 {
        for line in old {
            println!("-{}", line);
        }
        for line in new {
            println!("+{}", line);
        }
        return;
    }

    let lcs = lcs_diff(old, new);
    for op in &lcs {
        match op {
            DiffOp::Equal(line) => println!(" {}", line),
            DiffOp::Remove(line) => println!("-{}", line),
            DiffOp::Add(line) => println!("+{}", line),
        }
    }
}

enum DiffOp<'a> {
    Equal(&'a str),
    Remove(&'a str),
    Add(&'a str),
}

fn lcs_diff<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<DiffOp<'a>> {
    let m = old.len();
    let n = new.len();

    // Build LCS table.
    let mut table = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if old[i - 1] == new[j - 1] {
                table[i][j] = table[i - 1][j - 1] + 1;
            } else {
                table[i][j] = table[i - 1][j].max(table[i][j - 1]);
            }
        }
    }

    // Backtrack to produce diff.
    let mut ops = Vec::new();
    let (mut i, mut j) = (m, n);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            ops.push(DiffOp::Equal(old[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[i][j - 1] >= table[i - 1][j]) {
            ops.push(DiffOp::Add(new[j - 1]));
            j -= 1;
        } else {
            ops.push(DiffOp::Remove(old[i - 1]));
            i -= 1;
        }
    }

    ops.reverse();
    ops
}

fn diff_tree_vs_working(repo: &Repository, tree_id: &ObjectId, root: &std::path::Path) -> Result<()> {
    let status = repo.status()?;

    if status.is_clean() {
        println!("No changes");
        return Ok(());
    }

    // For modified files, show actual content diff.
    for path in &status.modified {
        let file_path = root.join(path);
        let new_content = std::fs::read(&file_path)?;

        // Find old blob by walking the tree.
        let old_blob_id = find_blob_in_tree(repo, tree_id, path)?;
        let old_text = old_blob_id.and_then(|id| {
            repo.get_object(&id).ok().flatten().and_then(|obj| match obj {
                Object::Blob(b) => String::from_utf8(b.data).ok(),
                _ => None,
            })
        });

        let new_text = String::from_utf8(new_content).ok();

        if let (Some(old), Some(new)) = (&old_text, &new_text) {
            println!("--- a/{}", path);
            println!("+++ b/{}", path);
            let old_lines: Vec<&str> = old.lines().collect();
            let new_lines: Vec<&str> = new.lines().collect();
            print_simple_diff(&old_lines, &new_lines);
            println!();
        }
    }

    for path in &status.added {
        println!("--- /dev/null");
        println!("+++ b/{}", path);
        if let Ok(content) = std::fs::read_to_string(root.join(path)) {
            for line in content.lines() {
                println!("+{}", line);
            }
        }
        println!();
    }

    for path in &status.deleted {
        println!("--- a/{}", path);
        println!("+++ /dev/null");
        if let Some(id) = find_blob_in_tree(repo, tree_id, path)?
            && let Some(Object::Blob(b)) = repo.get_object(&id)?
                && let Ok(text) = String::from_utf8(b.data) {
                    for line in text.lines() {
                        println!("-{}", line);
                    }
                }
        println!();
    }

    Ok(())
}

fn find_blob_in_tree(repo: &Repository, tree_id: &ObjectId, path: &str) -> Result<Option<ObjectId>> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut current_tree_id = *tree_id;

    for (i, part) in parts.iter().enumerate() {
        match repo.get_object(&current_tree_id)? {
            Some(Object::Tree(tree)) => {
                match tree.entries.get(*part) {
                    Some(entry) if i == parts.len() - 1 => {
                        return Ok(Some(entry.id));
                    }
                    Some(entry) if entry.kind == EntryKind::Directory => {
                        current_tree_id = entry.id;
                    }
                    _ => return Ok(None),
                }
            }
            _ => return Ok(None),
        }
    }

    Ok(None)
}

fn print_deleted_tree(repo: &Repository, tree_id: &ObjectId, prefix: &str) -> Result<()> {
    if let Some(Object::Tree(tree)) = repo.get_object(tree_id)? {
        for (name, entry) in &tree.entries {
            let path = format!("{}/{}", prefix, name);
            match entry.kind {
                EntryKind::File => {
                    print_file_diff(repo, &path, Some(&entry.id), None)?;
                }
                EntryKind::Directory => {
                    print_deleted_tree(repo, &entry.id, &path)?;
                }
                EntryKind::Symlink => {
                    println!("--- a/{} (symlink)", path);
                }
            }
        }
    }
    Ok(())
}
