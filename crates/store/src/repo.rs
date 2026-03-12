use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use gritgrub_core::*;
use gritgrub_core::attestation::*;
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

    /// Get the active identity for this repository.
    pub fn local_identity(&self) -> Result<IdentityId> {
        if let Some(id_str) = self.backend.get_config("identity.id")? {
            let uuid = uuid::Uuid::parse_str(&id_str)?;
            return Ok(IdentityId(uuid));
        }
        let id = IdentityId::new();
        self.backend.set_config("identity.id", &id.0.to_string())?;
        Ok(id)
    }

    /// Set the active identity for commits.
    pub fn set_active_identity(&self, id: &IdentityId) -> Result<()> {
        self.backend.set_config("identity.id", &id.0.to_string())
    }

    // ── Identities ──────────────────────────────────────────────────

    pub fn create_identity(&self, name: &str, kind: IdentityKind) -> Result<Identity> {
        let identity = Identity {
            id: IdentityId::new(),
            kind,
            name: name.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
        };
        self.backend.put_identity(&identity)?;
        Ok(identity)
    }

    pub fn get_identity(&self, id: &IdentityId) -> Result<Option<Identity>> {
        self.backend.get_identity(id)
    }

    pub fn list_identities(&self) -> Result<Vec<Identity>> {
        self.backend.list_identities()
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

    /// Restore the working directory to match a tree object.
    /// Requires a clean working tree (no uncommitted changes).
    pub fn checkout_tree(&self, tree_id: &ObjectId) -> Result<()> {
        let status = self.status()?;
        if !status.is_clean() {
            bail!(
                "working tree has uncommitted changes ({} added, {} modified, {} deleted)",
                status.added.len(),
                status.modified.len(),
                status.deleted.len(),
            );
        }
        self.clean_working_dir()?;
        self.write_tree(tree_id, &self.root)
    }

    /// Delete all non-ignored files in the working directory.
    fn clean_working_dir(&self) -> Result<()> {
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if self.should_ignore(&name, &self.root) {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
        Ok(())
    }

    /// Write a tree object to a directory on disk.
    fn write_tree(&self, tree_id: &ObjectId, dir: &Path) -> Result<()> {
        let tree = match self.get_object(tree_id)? {
            Some(Object::Tree(t)) => t,
            _ => bail!("expected tree object: {}", tree_id),
        };

        for (name, entry) in &tree.entries {
            let path = dir.join(name);
            match entry.kind {
                EntryKind::File => {
                    if let Some(Object::Blob(blob)) = self.get_object(&entry.id)? {
                        std::fs::write(&path, &blob.data)?;
                        #[cfg(unix)]
                        if entry.executable {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
                        }
                    }
                }
                EntryKind::Directory => {
                    std::fs::create_dir_all(&path)?;
                    self.write_tree(&entry.id, &path)?;
                }
                EntryKind::Symlink => {
                    if let Some(Object::Blob(blob)) = self.get_object(&entry.id)? {
                        #[cfg(unix)]
                        {
                            let target = String::from_utf8_lossy(&blob.data);
                            std::os::unix::fs::symlink(target.as_ref(), &path)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ── Key management ────────────────────────────────────────────

    /// Directory where secret keys live (never in the object store).
    fn keys_dir(&self) -> PathBuf {
        self.root.join(FORGE_DIR).join("keys")
    }

    /// Generate and store a keypair for an identity.
    pub fn generate_keypair(&self, identity: &IdentityId) -> Result<IdentityKeyPair> {
        let kp = IdentityKeyPair::generate(*identity);

        // Store secret key locally.
        let keys_dir = self.keys_dir();
        std::fs::create_dir_all(&keys_dir)?;
        let secret_path = keys_dir.join(format!("{}.secret", identity));
        std::fs::write(&secret_path, kp.secret_bytes())?;

        // Store public key as a ref (so it can sync to remotes).
        let public_blob = Object::Blob(Blob { data: kp.public_bytes().to_vec() });
        let blob_id = self.put_object(&public_blob)?;
        self.set_ref(
            &format!("refs/keys/{}", identity),
            &Ref::Direct(blob_id),
        )?;

        Ok(kp)
    }

    /// Load the keypair for an identity (requires local secret key).
    pub fn load_keypair(&self, identity: &IdentityId) -> Result<IdentityKeyPair> {
        let secret_path = self.keys_dir().join(format!("{}.secret", identity));
        if !secret_path.exists() {
            bail!("no signing key for identity {} (run `forge identity keygen`)", identity);
        }
        let secret_bytes: [u8; 32] = std::fs::read(&secret_path)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("corrupt key file for {}", identity))?;
        Ok(IdentityKeyPair::from_secret_bytes(*identity, &secret_bytes))
    }

    /// Load the keypair for the active identity.
    pub fn load_active_keypair(&self) -> Result<IdentityKeyPair> {
        let id = self.local_identity()?;
        self.load_keypair(&id)
    }

    /// Get the public key for any identity (from the object store).
    pub fn get_public_key(&self, identity: &IdentityId) -> Result<Option<[u8; 32]>> {
        let ref_name = format!("refs/keys/{}", identity);
        let blob_id = match self.resolve_ref(&ref_name)? {
            Some(id) => id,
            None => return Ok(None),
        };
        match self.get_object(&blob_id)? {
            Some(Object::Blob(blob)) => {
                let bytes: [u8; 32] = blob.data.try_into()
                    .map_err(|_| anyhow::anyhow!("corrupt public key blob for {}", identity))?;
                Ok(Some(bytes))
            }
            _ => Ok(None),
        }
    }

    // ── Attestations ─────────────────────────────────────────────

    /// Create and sign an attestation envelope for a changeset.
    pub fn attest(
        &self,
        changeset_id: &ObjectId,
        statement: &Statement,
    ) -> Result<ObjectId> {
        let kp = self.load_active_keypair()?;
        let envelope = kp.sign_envelope(statement, "application/vnd.in-toto+json");
        let env_id = self.put_object(&Object::Envelope(envelope))?;

        // Store a ref so we can find attestations for this changeset.
        let short_id = &changeset_id.to_hex()[..16];
        let existing = self.list_attestation_refs(changeset_id)?;
        let index = existing.len();
        let ref_name = format!("refs/attestations/{}/{}", short_id, index);
        self.set_ref(&ref_name, &Ref::Direct(env_id))?;

        Ok(env_id)
    }

    /// List all attestation envelope IDs for a changeset.
    pub fn list_attestation_refs(&self, changeset_id: &ObjectId) -> Result<Vec<(String, ObjectId)>> {
        let prefix = format!("refs/attestations/{}/", &changeset_id.to_hex()[..16]);
        let refs = self.list_refs(&prefix)?;
        let mut result = Vec::new();
        for (name, reference) in refs {
            if let Ref::Direct(id) = reference {
                result.push((name, id));
            }
        }
        Ok(result)
    }

    /// Get all attestation envelopes for a changeset.
    pub fn get_attestations(&self, changeset_id: &ObjectId) -> Result<Vec<(ObjectId, Envelope)>> {
        let refs = self.list_attestation_refs(changeset_id)?;
        let mut envelopes = Vec::new();
        for (_name, env_id) in refs {
            match self.get_object(&env_id)? {
                Some(Object::Envelope(env)) => envelopes.push((env_id, env)),
                _ => {} // skip corrupt refs
            }
        }
        Ok(envelopes)
    }

    /// Verify all attestations for a changeset against known public keys.
    pub fn verify_attestations(&self, changeset_id: &ObjectId) -> Result<Vec<VerificationResult>> {
        let envelopes = self.get_attestations(changeset_id)?;
        let mut results = Vec::new();

        for (env_id, envelope) in &envelopes {
            // Parse the statement to get the predicate type.
            let statement: Statement = serde_json::from_slice(&envelope.payload)
                .map_err(|e| anyhow::anyhow!("malformed statement in {}: {}", env_id, e))?;

            for (sig_idx, sig) in envelope.signatures.iter().enumerate() {
                let public_key = self.get_public_key(&sig.keyid)?;
                let verified = match public_key {
                    Some(pk) => verify_envelope_signature(envelope, sig_idx, &pk)
                        .unwrap_or(false),
                    None => false,
                };

                results.push(VerificationResult {
                    envelope_id: *env_id,
                    predicate_type: statement.predicate_type.clone(),
                    signer: sig.keyid,
                    verified,
                    key_found: public_key.is_some(),
                });
            }
        }

        Ok(results)
    }

    /// Check if a changeset meets a given SLSA level.
    pub fn check_slsa_level(&self, changeset_id: &ObjectId, required: SlsaLevel) -> Result<bool> {
        if required == SlsaLevel::L0 {
            return Ok(true);
        }

        let verifications = self.verify_attestations(changeset_id)?;

        // L1: at least one verified SLSA provenance attestation.
        let has_provenance = verifications.iter().any(|v| {
            v.verified && v.predicate_type == SLSA_PROVENANCE_V1
        });

        if required == SlsaLevel::L1 {
            return Ok(has_provenance);
        }

        if !has_provenance {
            return Ok(false);
        }

        // L2: provenance signed by a builder identity distinct from the author.
        let cs = match self.get_object(changeset_id)? {
            Some(Object::Changeset(cs)) => cs,
            _ => return Ok(false),
        };

        let has_independent_provenance = verifications.iter().any(|v| {
            v.verified
                && v.predicate_type == SLSA_PROVENANCE_V1
                && v.signer != cs.author
        });

        if required == SlsaLevel::L2 {
            return Ok(has_independent_provenance);
        }

        // L3: would require hermetic build verification — not yet implemented.
        Ok(false)
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
