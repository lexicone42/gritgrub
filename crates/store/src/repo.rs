use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use gritgrub_core::*;
use crate::backend::{ObjectStore, RefStore};
use crate::redb_backend::RedbBackend;

const FORGE_DIR: &str = ".forge";
const STORE_FILE: &str = "store.redb";

pub struct Repository {
    root: PathBuf,
    backend: RedbBackend,
}

impl Repository {
    /// Create a new repository at `path`.
    pub fn init(path: &Path) -> Result<Self> {
        let root = path.to_path_buf();
        let forge_dir = root.join(FORGE_DIR);

        if forge_dir.exists() {
            bail!("repository already initialized at {}", root.display());
        }

        std::fs::create_dir_all(&forge_dir)?;
        let backend = RedbBackend::create(&forge_dir.join(STORE_FILE))?;

        // HEAD starts as a symbolic ref to the default branch.
        backend.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into()))?;

        // Generate a local identity.
        let id = IdentityId::new();
        backend.set_config("identity.id", &id.0.to_string())?;

        let name = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "anonymous".to_string());
        backend.set_config("identity.name", &name)?;

        Ok(Self { root, backend })
    }

    /// Open an existing repository at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let root = path.to_path_buf();
        let forge_dir = root.join(FORGE_DIR);
        if !forge_dir.exists() {
            bail!("not a forge repository: {}", root.display());
        }
        let backend = RedbBackend::open(&forge_dir.join(STORE_FILE))?;
        Ok(Self { root, backend })
    }

    /// Walk up from `from` to find the nearest `.forge` directory.
    pub fn discover(from: &Path) -> Result<Self> {
        let from = from.canonicalize().context("canonicalize path")?;
        let mut current = from.as_path();
        loop {
            if current.join(FORGE_DIR).is_dir() {
                return Self::open(current);
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => bail!("not a forge repository (or any parent up to /)"),
            }
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Config ──────────────────────────────────────────────────────

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        self.backend.get_config(key)
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.backend.set_config(key, value)
    }

    /// Get the local identity for this repository.
    pub fn local_identity(&self) -> Result<IdentityId> {
        if let Some(id_str) = self.backend.get_config("identity.id")? {
            let uuid = uuid::Uuid::parse_str(&id_str)?;
            return Ok(IdentityId(uuid));
        }
        let id = IdentityId::new();
        self.backend.set_config("identity.id", &id.0.to_string())?;
        Ok(id)
    }

    // ── Refs ────────────────────────────────────────────────────────

    /// Resolve a ref name to a changeset ID, following symbolic refs (depth-limited).
    pub fn resolve_ref(&self, name: &str) -> Result<Option<ObjectId>> {
        let mut current = name.to_string();
        for _ in 0..10 {
            match self.backend.get_ref(&current)? {
                Some(Ref::Direct(id)) => return Ok(Some(id)),
                Some(Ref::Symbolic(target)) => current = target,
                None => return Ok(None),
            }
        }
        bail!("symbolic ref resolution depth exceeded for '{}'", name)
    }

    /// Resolve HEAD to a changeset ID.
    pub fn resolve_head(&self) -> Result<Option<ObjectId>> {
        self.resolve_ref("HEAD")
    }

    /// Get the branch name HEAD points to, if HEAD is symbolic.
    pub fn head_branch(&self) -> Result<Option<String>> {
        match self.backend.get_ref("HEAD")? {
            Some(Ref::Symbolic(target)) => {
                Ok(Some(
                    target
                        .strip_prefix("refs/heads/")
                        .unwrap_or(&target)
                        .to_string(),
                ))
            }
            _ => Ok(None),
        }
    }

    /// Update HEAD (or the branch it points to) to a new changeset.
    fn update_head(&self, id: &ObjectId) -> Result<()> {
        match self.backend.get_ref("HEAD")? {
            Some(Ref::Symbolic(branch)) => {
                self.backend.set_ref(&branch, &Ref::Direct(*id))?;
            }
            _ => {
                self.backend.set_ref("HEAD", &Ref::Direct(*id))?;
            }
        }
        Ok(())
    }

    // ── Objects ─────────────────────────────────────────────────────

    pub fn put_object(&self, object: &Object) -> Result<ObjectId> {
        self.backend.put_object(object)
    }

    pub fn get_object(&self, id: &ObjectId) -> Result<Option<Object>> {
        self.backend.get_object(id)
    }

    /// Find an object by hex prefix (at least 8 chars).
    pub fn find_by_prefix(&self, hex_prefix: &str) -> Result<(ObjectId, Object)> {
        // Full ID — direct lookup.
        if hex_prefix.len() == 64 {
            let id = ObjectId::from_hex(hex_prefix)?;
            return match self.get_object(&id)? {
                Some(obj) => Ok((id, obj)),
                None => bail!("object not found: {}", id),
            };
        }

        let matches = self.backend.find_objects_by_prefix(hex_prefix)?;
        match matches.len() {
            0 => bail!("no object matching prefix '{}'", hex_prefix),
            1 => Ok(matches.into_iter().next().unwrap()),
            _ => bail!(
                "ambiguous prefix '{}': matches {} and {}",
                hex_prefix,
                matches[0].0,
                matches[1].0,
            ),
        }
    }

    /// Set a ref directly (used by import, branch management, etc.).
    pub fn set_ref(&self, name: &str, reference: &Ref) -> Result<()> {
        self.backend.set_ref(name, reference)
    }

    /// List refs with the given prefix (e.g., "refs/heads/").
    pub fn list_refs(&self, prefix: &str) -> Result<Vec<(String, Ref)>> {
        self.backend.list_refs(prefix)
    }

    // ── High-level operations ───────────────────────────────────────

    /// Snapshot the working directory and create a new changeset.
    pub fn commit(
        &self,
        message: &str,
        author: IdentityId,
        intent: Option<Intent>,
    ) -> Result<ObjectId> {
        let tree_id = self.snapshot_tree(&self.root)?;

        let parents = match self.resolve_head()? {
            Some(head) => vec![head],
            None => vec![],
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let changeset = Changeset {
            parents,
            tree: tree_id,
            author,
            timestamp,
            message: message.to_string(),
            intent,
            metadata: BTreeMap::new(),
        };

        let cs_id = self.put_object(&Object::Changeset(changeset))?;
        self.update_head(&cs_id)?;
        Ok(cs_id)
    }

    /// Walk changeset history from HEAD, most recent first.
    pub fn log(&self, max_count: usize) -> Result<Vec<(ObjectId, Changeset)>> {
        let head = match self.resolve_head()? {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        let mut result = Vec::new();
        let mut queue = vec![head];
        let mut seen = std::collections::HashSet::new();

        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            match self.get_object(&id)? {
                Some(Object::Changeset(cs)) => {
                    for parent in &cs.parents {
                        queue.push(*parent);
                    }
                    result.push((id, cs));
                }
                _ => bail!("ref points to non-changeset object: {}", id),
            }
        }

        // Most recent first.
        result.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp));
        result.truncate(max_count);
        Ok(result)
    }

    /// Compare working tree against HEAD and report changes.
    pub fn status(&self) -> Result<StatusResult> {
        let head_tree = match self.resolve_head()? {
            Some(head_id) => match self.get_object(&head_id)? {
                Some(Object::Changeset(cs)) => Some(cs.tree),
                _ => None,
            },
            None => None,
        };

        let mut result = StatusResult::default();
        self.diff_tree(&self.root, head_tree.as_ref(), &mut result, String::new())?;
        Ok(result)
    }

    // ── Internals ───────────────────────────────────────────────────

    /// Recursively snapshot a directory into Blob and Tree objects.
    fn snapshot_tree(&self, dir: &Path) -> Result<ObjectId> {
        let mut entries = BTreeMap::new();

        let mut dir_entries: Vec<_> = std::fs::read_dir(dir)?
            .collect::<Result<Vec<_>, _>>()?;
        dir_entries.sort_by_key(|e| e.file_name());

        for entry in dir_entries {
            let name = entry.file_name().to_string_lossy().to_string();
            if self.should_ignore(&name, dir) {
                continue;
            }

            let path = entry.path();
            let ft = entry.file_type()?;

            if ft.is_file() {
                let data = std::fs::read(&path)?;
                let blob = Object::Blob(Blob { data });
                let id = self.put_object(&blob)?;

                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    entry.metadata()?.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;

                entries.insert(name, TreeEntry { id, kind: EntryKind::File, executable });
            } else if ft.is_dir() {
                let id = self.snapshot_tree(&path)?;
                entries.insert(name, TreeEntry { id, kind: EntryKind::Directory, executable: false });
            } else if ft.is_symlink() {
                let target = std::fs::read_link(&path)?;
                let data = target.to_string_lossy().as_bytes().to_vec();
                let blob = Object::Blob(Blob { data });
                let id = self.put_object(&blob)?;
                entries.insert(name, TreeEntry { id, kind: EntryKind::Symlink, executable: false });
            }
        }

        let tree = Object::Tree(Tree { entries });
        self.put_object(&tree)
    }

    fn should_ignore(&self, name: &str, dir: &Path) -> bool {
        // Always ignore these anywhere in the tree.
        if matches!(name, "target" | "node_modules" | ".git" | ".claude") {
            return true;
        }
        // Only ignore .forge at the repo root.
        if name == ".forge" && dir == self.root {
            return true;
        }
        // Check .forgeignore at the repo root.
        if let Ok(patterns) = self.forgeignore_patterns() {
            for pattern in &patterns {
                if pattern == name {
                    return true;
                }
            }
        }
        false
    }

    fn forgeignore_patterns(&self) -> Result<Vec<String>> {
        let path = self.root.join(".forgeignore");
        if !path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect())
    }

    fn diff_tree(
        &self,
        dir: &Path,
        tree_id: Option<&ObjectId>,
        result: &mut StatusResult,
        prefix: String,
    ) -> Result<()> {
        let stored: BTreeMap<String, TreeEntry> = match tree_id {
            Some(id) => match self.get_object(id)? {
                Some(Object::Tree(tree)) => tree.entries,
                _ => BTreeMap::new(),
            },
            None => BTreeMap::new(),
        };

        let mut working = BTreeMap::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if self.should_ignore(&name, dir) {
                    continue;
                }
                working.insert(name, entry);
            }
        }

        // New or modified files.
        for (name, entry) in &working {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };

            let ft = entry.file_type()?;

            if ft.is_file() {
                match stored.get(name) {
                    Some(stored_entry) if stored_entry.kind == EntryKind::File => {
                        let data = std::fs::read(entry.path())?;
                        let current_id = Object::Blob(Blob { data }).id();
                        if current_id != stored_entry.id {
                            result.modified.push(path);
                        }
                    }
                    _ => {
                        result.added.push(path);
                    }
                }
            } else if ft.is_dir() {
                let sub_tree_id = stored
                    .get(name)
                    .filter(|e| e.kind == EntryKind::Directory)
                    .map(|e| &e.id);
                self.diff_tree(&entry.path(), sub_tree_id, result, path)?;
            }
        }

        // Deleted files.
        for (name, stored_entry) in &stored {
            if !working.contains_key(name) {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", prefix, name)
                };
                match stored_entry.kind {
                    EntryKind::File | EntryKind::Symlink => {
                        result.deleted.push(path);
                    }
                    EntryKind::Directory => {
                        self.collect_tree_files(&stored_entry.id, &mut result.deleted, &path)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn collect_tree_files(
        &self,
        tree_id: &ObjectId,
        files: &mut Vec<String>,
        prefix: &str,
    ) -> Result<()> {
        if let Some(Object::Tree(tree)) = self.get_object(tree_id)? {
            for (name, entry) in &tree.entries {
                let path = format!("{}/{}", prefix, name);
                match entry.kind {
                    EntryKind::File | EntryKind::Symlink => files.push(path),
                    EntryKind::Directory => {
                        self.collect_tree_files(&entry.id, files, &path)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct StatusResult {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

impl StatusResult {
    pub fn is_clean(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }
}
