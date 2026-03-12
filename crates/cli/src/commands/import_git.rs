use std::collections::{BTreeMap, HashMap};
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

    let git_branch = git_current_branch(repo.root())?;
    let commits = git_log(repo.root())?;

    if commits.is_empty() {
        println!("No git commits to import");
        return Ok(());
    }

    println!("Importing {} commits from git ({})...", commits.len(), git_branch);

    let author = repo.local_identity()?;
    let mut sha_to_forge: HashMap<String, ObjectId> = HashMap::new();
    let mut blob_cache: HashMap<String, ObjectId> = HashMap::new();

    for (i, commit) in commits.iter().enumerate() {
        let files = git_ls_tree(repo.root(), &commit.hash)?;

        // Create blobs, deduplicating by git SHA.
        let mut path_entries: BTreeMap<String, (ObjectId, bool)> = BTreeMap::new();
        for file in &files {
            let forge_id = if let Some(&cached) = blob_cache.get(&file.hash) {
                cached
            } else {
                let content = git_cat_file_blob(repo.root(), &file.hash)?;
                let id = repo.put_object(&Object::Blob(Blob { data: content }))?;
                blob_cache.insert(file.hash.clone(), id);
                id
            };
            path_entries.insert(file.path.clone(), (forge_id, file.executable));
        }

        // Build tree hierarchy from flat paths.
        let tree_id = build_tree_from_paths(&repo, &path_entries)?;

        // Map parent git SHAs → forge ObjectIds.
        let parents: Vec<ObjectId> = commit
            .parents
            .iter()
            .filter_map(|p| sha_to_forge.get(p).copied())
            .collect();

        let intent = infer_intent(&commit.subject);

        let changeset = Changeset {
            parents,
            tree: tree_id,
            author,
            timestamp: commit.timestamp * 1_000_000, // seconds → micros
            message: commit.subject.clone(),
            intent,
            metadata: BTreeMap::from([
                ("git.sha".into(), commit.hash.clone()),
                ("git.author".into(), commit.author.clone()),
            ]),
        };

        let cs_id = repo.put_object(&Object::Changeset(changeset))?;
        sha_to_forge.insert(commit.hash.clone(), cs_id);

        let short_msg: String = commit.subject.chars().take(60).collect();
        println!("  [{}/{}] {} -> {} {}", i + 1, commits.len(), &commit.hash[..10], cs_id, short_msg);
    }

    // Point forge branch at the imported tip.
    if let Some(latest) = commits.last() {
        if let Some(&forge_id) = sha_to_forge.get(&latest.hash) {
            let branch_ref = format!("refs/heads/{}", git_branch);
            repo.set_ref(&branch_ref, &Ref::Direct(forge_id))?;
            repo.set_ref("HEAD", &Ref::Symbolic(branch_ref))?;
            println!("\n{} -> {}", git_branch, forge_id);
        }
    }

    println!("Imported {} commits, {} unique blobs", commits.len(), blob_cache.len());
    Ok(())
}

// ── Git CLI wrappers ────────────────────────────────────────────────

struct GitCommit {
    hash: String,
    parents: Vec<String>,
    author: String,
    timestamp: i64,
    subject: String,
}

struct GitFile {
    hash: String,
    path: String,
    executable: bool,
}

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

fn git_log(root: &Path) -> Result<Vec<GitCommit>> {
    let out = Command::new("git")
        .args(["log", "--format=%H%x00%P%x00%an%x00%at%x00%s", "--reverse", "--topo-order", "HEAD"])
        .current_dir(root)
        .output()?;

    if !out.status.success() {
        bail!("git log failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    String::from_utf8(out.stdout)?
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let p: Vec<&str> = line.splitn(5, '\0').collect();
            if p.len() < 5 {
                bail!("malformed git log line");
            }
            Ok(GitCommit {
                hash: p[0].into(),
                parents: p[1].split_whitespace().map(String::from).collect(),
                author: p[2].into(),
                timestamp: p[3].parse().unwrap_or(0),
                subject: p[4].into(),
            })
        })
        .collect()
}

fn git_ls_tree(root: &Path, commit: &str) -> Result<Vec<GitFile>> {
    let out = Command::new("git")
        .args(["ls-tree", "-r", "--full-tree", commit])
        .current_dir(root)
        .output()?;

    if !out.status.success() {
        bail!("git ls-tree failed for {}", commit);
    }

    String::from_utf8(out.stdout)?
        .lines()
        .filter_map(|line| {
            let (meta, path) = line.split_once('\t')?;
            let parts: Vec<&str> = meta.split_whitespace().collect();
            if parts.len() < 3 || parts[1] != "blob" {
                return None;
            }
            Some(GitFile {
                hash: parts[2].into(),
                path: path.into(),
                executable: parts[0] == "100755",
            })
        })
        .map(Ok)
        .collect()
}

fn git_cat_file_blob(root: &Path, hash: &str) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .args(["cat-file", "blob", hash])
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        bail!("git cat-file blob {} failed", hash);
    }
    Ok(out.stdout)
}

// ── Tree building from flat paths ───────────────────────────────────

fn build_tree_from_paths(
    repo: &Repository,
    files: &BTreeMap<String, (ObjectId, bool)>,
) -> Result<ObjectId> {
    let mut root = DirNode::new();
    for (path, &(id, executable)) in files {
        let parts: Vec<&str> = path.split('/').collect();
        root.insert(&parts, id, executable);
    }
    root.flush(repo)
}

struct DirNode {
    files: BTreeMap<String, TreeEntry>,
    dirs: BTreeMap<String, DirNode>,
}

impl DirNode {
    fn new() -> Self {
        Self { files: BTreeMap::new(), dirs: BTreeMap::new() }
    }

    fn insert(&mut self, parts: &[&str], id: ObjectId, executable: bool) {
        match parts {
            [name] => {
                self.files.insert(
                    (*name).into(),
                    TreeEntry { id, kind: EntryKind::File, executable },
                );
            }
            [dir, rest @ ..] => {
                self.dirs
                    .entry((*dir).into())
                    .or_insert_with(DirNode::new)
                    .insert(rest, id, executable);
            }
            [] => {}
        }
    }

    fn flush(self, repo: &Repository) -> Result<ObjectId> {
        let mut entries = BTreeMap::new();

        for (name, entry) in self.files {
            entries.insert(name, entry);
        }
        for (name, dir) in self.dirs {
            let id = dir.flush(repo)?;
            entries.insert(name, TreeEntry { id, kind: EntryKind::Directory, executable: false });
        }

        repo.put_object(&Object::Tree(Tree { entries }))
    }
}

// ── Intent inference from conventional commits ──────────────────────

fn infer_intent(subject: &str) -> Option<Intent> {
    let lower = subject.to_lowercase();
    let kind = if lower.starts_with("feat") {
        IntentKind::Feature
    } else if lower.starts_with("fix") {
        IntentKind::Bugfix
    } else if lower.starts_with("refactor") {
        IntentKind::Refactor
    } else if lower.starts_with("doc") {
        IntentKind::Documentation
    } else if lower.starts_with("dep") || lower.contains("dependency") {
        IntentKind::Dependency
    } else {
        return None;
    };

    Some(Intent {
        kind,
        affected_paths: vec![],
        rationale: String::new(),
        context_ref: None,
        verifications: vec![],
    })
}
