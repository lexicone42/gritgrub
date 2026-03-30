use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use gritgrub_core::*;
use gritgrub_core::attestation::*;
use gritgrub_core::exploration;
use gritgrub_core::pipeline;
use gritgrub_core::events::{RepoEvent, EventKind};
use crate::backend::{ObjectStore, RefStore, ConfigStore, IdentityStore, EventStore, RevocationStore};
use crate::redb_backend::RedbBackend;

const FORGE_DIR: &str = ".forge";

/// Simple glob match for .forgeignore patterns.
/// Supports `*` (any chars except `/`), `?` (single char), and exact match.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pat: &[u8], txt: &[u8]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let (mut star_p, mut star_t) = (usize::MAX, 0);
    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == b'?' {
            // ? matches any single char except /
            if txt[ti] == b'/' {
                return false;
            }
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_p = pi;
            star_t = ti;
            pi += 1;
        } else if pi < pat.len() && pat[pi] == txt[ti] {
            pi += 1;
            ti += 1;
        } else if star_p != usize::MAX {
            // Backtrack: star matches one more char (but not /)
            star_t += 1;
            if txt[star_t - 1] == b'/' {
                return false;
            }
            pi = star_p + 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Result of a tree-to-tree diff.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct DiffResult {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

/// Result of a merge operation.
#[derive(Debug)]
pub enum MergeResult {
    /// Theirs was strictly ahead — HEAD moved forward.
    FastForward(ObjectId),
    /// Ours is already up to date (theirs is ancestor of ours).
    AlreadyUpToDate,
    /// Three-way merge succeeded — new merge changeset created.
    Merged(ObjectId),
    /// Three-way merge has conflicts at these paths.
    Conflict(Vec<String>),
}
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

        let name = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "anonymous".to_string());

        let repo = Self { root, backend };

        // SE-5: Create the initial identity WITH admin capabilities.
        let identity = repo.create_identity_with_capabilities(
            &name,
            IdentityKind::Human,
            vec![Capability {
                scope: CapabilityScope::Global,
                permissions: Permissions::all(),
                expires_at: None,
            }],
        )?;

        repo.backend.set_config("identity.id", &identity.id.0.to_string())?;
        repo.backend.set_config("identity.name", &name)?;

        Ok(repo)
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

    /// List all config entries with the given prefix.
    pub fn list_config_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        self.backend.list_config_prefix(prefix)
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
                .context("system clock before UNIX epoch")?
                .as_micros() as i64,
        };
        self.backend.put_identity(&identity)?;

        // New identities get no capabilities by default.
        // The repo owner must explicitly grant access.
        Ok(identity)
    }

    /// Create an identity with initial capabilities (used by init for the owner).
    pub fn create_identity_with_capabilities(
        &self,
        name: &str,
        kind: IdentityKind,
        capabilities: Vec<Capability>,
    ) -> Result<Identity> {
        let identity = self.create_identity(name, kind)?;
        self.backend.set_capabilities(&identity.id, &capabilities)?;
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

    /// Update HEAD (or the branch it points to) to a new changeset, atomically.
    ///
    /// Uses compare-and-swap to prevent lost updates when multiple writers
    /// race to advance HEAD. If `expected` doesn't match the current ref
    /// value, the update fails with an error instead of silently overwriting.
    ///
    /// Note: the HEAD→branch indirection read is a separate transaction from
    /// the CAS on the branch. This is safe in practice because HEAD's symbolic
    /// target changes only during checkout (rare), not during normal commits.
    fn update_head_cas(&self, expected: Option<&ObjectId>, new_id: &ObjectId) -> Result<()> {
        let expected_ref = expected.map(|id| Ref::Direct(*id));
        let ref_name = match self.backend.get_ref("HEAD")? {
            Some(Ref::Symbolic(branch)) => branch,
            _ => "HEAD".to_string(),
        };
        if self.backend.cas_ref(&ref_name, expected_ref.as_ref(), &Ref::Direct(*new_id))? {
            Ok(())
        } else {
            bail!("concurrent modification: ref '{}' was updated by another operation — retry", ref_name)
        }
    }

    /// Force-update HEAD without CAS. Only for operations that intentionally
    /// overwrite (e.g., branch checkout, import).
    fn update_head_force(&self, id: &ObjectId) -> Result<()> {
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

    /// Compare-and-swap ref update. Returns Ok(true) if the swap succeeded.
    /// This is the primitive for lock-free concurrent ref updates:
    /// agents read the current value, do their work, then CAS to update.
    /// If another agent updated the ref in the meantime, CAS fails and
    /// the agent can rebase and retry.
    pub fn cas_ref(&self, name: &str, expected: Option<&Ref>, new: &Ref) -> Result<bool> {
        self.backend.cas_ref(name, expected, new)
    }

    /// Delete a ref.
    pub fn delete_ref(&self, name: &str) -> Result<bool> {
        self.backend.delete_ref(name)
    }

    /// Check if an object exists in the store.
    pub fn has_object(&self, id: &ObjectId) -> Result<bool> {
        self.backend.has_object(id)
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

        let previous_head = self.resolve_head()?;
        let parents: Vec<ObjectId> = previous_head.into_iter().collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_micros() as i64;

        let changeset = Changeset {
            parents: parents.clone(),
            tree: tree_id,
            author,
            timestamp,
            message: message.to_string(),
            intent,
            metadata: BTreeMap::new(),
        };

        let cs_id = self.put_object(&Object::Changeset(changeset))?;
        self.update_head_cas(parents.first(), &cs_id)?;

        self.emit(EventKind::Commit {
            id: cs_id.to_string(),
            message: message.to_string(),
            branch: self.head_branch().ok().flatten(),
        }, Some(author));

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
        self.force_checkout_tree(tree_id)
    }

    /// Checkout without clean-check (used after merge/pull when HEAD was already updated).
    pub fn force_checkout_tree(&self, tree_id: &ObjectId) -> Result<()> {
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

        // Store secret key locally with restricted permissions (SE-18).
        let keys_dir = self.keys_dir();
        std::fs::create_dir_all(&keys_dir)?;
        let secret_path = keys_dir.join(format!("{}.secret", identity));
        std::fs::write(&secret_path, kp.secret_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
        }

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
        // Uses CAS loop to prevent index collisions under concurrent attestation.
        let short_id = &changeset_id.to_hex()[..16];
        loop {
            let existing = self.list_attestation_refs(changeset_id)?;
            let index = existing.len();
            let ref_name = format!("refs/attestations/{}/{}", short_id, index);
            if self.backend.cas_ref(&ref_name, None, &Ref::Direct(env_id))? {
                break;
            }
            // CAS failed — another writer claimed this index. Retry.
        }

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
            if let Some(Object::Envelope(env)) = self.get_object(&env_id)? {
                envelopes.push((env_id, env));
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

    // ── Capabilities ────────────────────────────────────────────────

    /// Grant capabilities to an identity (appends to existing).
    /// Uses a single write transaction to prevent lost-update races.
    pub fn grant_capabilities(&self, id: &IdentityId, new_caps: &[Capability]) -> Result<()> {
        self.backend.atomic_grant_capabilities(id, new_caps)
    }

    /// Replace all capabilities for an identity.
    pub fn set_capabilities(&self, id: &IdentityId, caps: &[Capability]) -> Result<()> {
        self.backend.set_capabilities(id, caps)
    }

    /// Get capabilities for an identity.
    pub fn get_capabilities(&self, id: &IdentityId) -> Result<Vec<Capability>> {
        self.backend.get_capabilities(id)
    }

    /// Check if an identity has a specific permission for a scope.
    pub fn check_permission(
        &self,
        id: &IdentityId,
        required_scope: &CapabilityScope,
        required_perm: u32,
    ) -> Result<bool> {
        let caps = self.backend.get_capabilities(id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_micros() as i64;

        for cap in &caps {
            // Skip expired capabilities.
            if let Some(exp) = cap.expires_at
                && now > exp {
                    continue;
                }
            // Check if scope matches.
            if scope_covers(&cap.scope, required_scope) && (cap.permissions.0 & required_perm != 0) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ── Ref policies ──────────────────────────────────────────────

    /// Load ref policies from config.
    pub fn get_ref_policies(&self) -> Result<Vec<RefPolicy>> {
        match self.backend.get_config("ref_policies")? {
            Some(json) => Ok(serde_json::from_str(&json)?),
            None => Ok(vec![]),
        }
    }

    /// Save ref policies to config.
    pub fn set_ref_policies(&self, policies: &[RefPolicy]) -> Result<()> {
        let json = serde_json::to_string(policies)?;
        self.backend.set_config("ref_policies", &json)
    }

    /// Check if a ref update is allowed by policies.
    /// Returns Ok(None) if allowed, Ok(Some(denial)) if denied.
    pub fn check_ref_policy(
        &self,
        ref_name: &str,
        identity: &IdentityId,
        target_changeset: Option<&ObjectId>,
        is_force_push: bool,
    ) -> Result<Option<PolicyDenial>> {
        let policies = self.get_ref_policies()?;

        for policy in &policies {
            if !policy.matches(ref_name) {
                continue;
            }

            // SE-4: Check force push restriction.
            if is_force_push && policy.forbid_force_push {
                return Ok(Some(PolicyDenial::ForcePushForbidden {
                    policy_pattern: policy.pattern.clone(),
                }));
            }

            // Check allowed writers.
            if !policy.allowed_writers.is_empty()
                && !policy.allowed_writers.contains(identity)
            {
                return Ok(Some(PolicyDenial::NotAllowedWriter {
                    policy_pattern: policy.pattern.clone(),
                    identity: *identity,
                }));
            }

            // Check attestation requirements on the target changeset.
            if let Some(cs_id) = target_changeset {
                if policy.require_review {
                    let verifications = self.verify_attestations(cs_id)?;
                    let has_review = verifications.iter().any(|v| {
                        v.verified && v.predicate_type == REVIEW_PREDICATE_V1
                    });
                    if !has_review {
                        return Ok(Some(PolicyDenial::MissingReview {
                            policy_pattern: policy.pattern.clone(),
                        }));
                    }
                }

                if let Some(required_slsa) = policy.require_slsa
                    && !self.check_slsa_level(cs_id, required_slsa)? {
                        let actual = if self.check_slsa_level(cs_id, SlsaLevel::L2)? {
                            SlsaLevel::L2
                        } else if self.check_slsa_level(cs_id, SlsaLevel::L1)? {
                            SlsaLevel::L1
                        } else {
                            SlsaLevel::L0
                        };
                        return Ok(Some(PolicyDenial::InsufficientSlsa {
                            policy_pattern: policy.pattern.clone(),
                            required: required_slsa,
                            actual,
                        }));
                    }
            }
        }

        Ok(None) // No policy denied the update.
    }

    // ── Pipelines ──────────────────────────────────────────────────

    /// Save a pipeline definition to repo config.
    pub fn save_pipeline(&self, pipeline: &Pipeline) -> Result<()> {
        let json = serde_json::to_string(pipeline)?;
        self.set_config(&format!("pipeline.{}", pipeline.name), &json)
    }

    /// Load a pipeline definition from repo config.
    pub fn get_pipeline(&self, name: &str) -> Result<Option<Pipeline>> {
        match self.get_config(&format!("pipeline.{}", name))? {
            Some(json) => {
                let p: Pipeline = serde_json::from_str(&json)?;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }

    /// List all defined pipelines.
    pub fn list_pipelines(&self) -> Result<Vec<Pipeline>> {
        let entries = self.list_config_prefix("pipeline.")?;
        let mut pipelines = Vec::new();
        for (_key, json) in entries {
            if let Ok(p) = serde_json::from_str::<Pipeline>(&json) {
                pipelines.push(p);
            }
        }
        Ok(pipelines)
    }

    /// Store a pipeline result as an attestation on a changeset.
    ///
    /// The pipeline result is serialized to JSON, wrapped in an in-toto
    /// Statement, and signed as a DSSE envelope. This creates a
    /// cryptographically verifiable proof that the pipeline ran and
    /// what the results were.
    pub fn attest_pipeline_result(&self, result: &PipelineResult) -> Result<ObjectId> {
        let result_value = serde_json::to_value(result)?;
        let subject = Subject::from_object_id("changeset", &result.changeset);
        let statement = Statement::new(
            vec![subject],
            pipeline::PIPELINE_PREDICATE,
            Predicate::Pipeline(result_value),
        );
        let env_id = self.attest(&result.changeset, &statement)?;

        self.emit(EventKind::PipelineCompleted {
            pipeline: result.pipeline.clone(),
            changeset_id: result.changeset.to_string(),
            passed: result.passed,
            duration_ms: result.duration_ms,
        }, Some(result.runner));

        Ok(env_id)
    }

    /// Find pipeline attestations for a changeset.
    /// Returns the parsed PipelineResults.
    pub fn get_pipeline_results(&self, changeset_id: &ObjectId) -> Result<Vec<PipelineResult>> {
        let attestations = self.get_attestations(changeset_id)?;
        let mut results = Vec::new();
        for (_id, env) in attestations {
            // Try to parse the payload as a Statement with a pipeline predicate.
            if let Ok(stmt) = serde_json::from_slice::<Statement>(&env.payload)
                && stmt.predicate_type == pipeline::PIPELINE_PREDICATE
                    && let Predicate::Pipeline(ref value) = stmt.predicate
                        && let Ok(pr) = serde_json::from_value::<PipelineResult>(value.clone()) {
                            results.push(pr);
                        }
        }
        Ok(results)
    }

    /// Check if a changeset has a passing attestation for a specific pipeline.
    pub fn has_passing_pipeline(&self, changeset_id: &ObjectId, pipeline_name: &str) -> Result<bool> {
        let results = self.get_pipeline_results(changeset_id)?;
        Ok(results.iter().any(|r| r.pipeline == pipeline_name && r.passed))
    }

    /// Compute the verification level of a changeset from its attestations.
    pub fn compute_verification_level(&self, changeset_id: &ObjectId) -> Result<VerificationLevel> {
        let results = self.get_pipeline_results(changeset_id)?;
        let attestations = self.get_attestations(changeset_id)?;

        if attestations.is_empty() {
            return Ok(VerificationLevel::Unknown);
        }

        // Check what we have.
        let has_tests = results.iter().any(|r| {
            r.passed && r.stages.iter().any(|s| s.name == "test" && s.passed)
        });
        let has_lint = results.iter().any(|r| {
            r.passed && r.stages.iter().any(|s| s.name == "lint" && s.passed)
        });
        let has_build = results.iter().any(|r| {
            r.stages.iter().any(|s| s.name == "build" && s.passed)
        });

        // Check for SLSA provenance and review attestations.
        let has_slsa = attestations.iter().any(|(_id, env)| {
            serde_json::from_slice::<Statement>(&env.payload)
                .map(|s| s.predicate_type.contains("slsa"))
                .unwrap_or(false)
        });
        let has_review = attestations.iter().any(|(_id, env)| {
            serde_json::from_slice::<Statement>(&env.payload)
                .map(|s| s.predicate_type.contains("review"))
                .unwrap_or(false)
        });

        // Compute level (monotonic — each level implies all lower levels).
        if has_slsa {
            return Ok(VerificationLevel::SlsaL1);
        }
        if has_review {
            return Ok(VerificationLevel::Reviewed);
        }
        if has_tests && has_lint {
            return Ok(VerificationLevel::Attested);
        }
        if has_tests {
            return Ok(VerificationLevel::Tested);
        }
        if has_build {
            return Ok(VerificationLevel::Builds);
        }

        Ok(VerificationLevel::Unknown)
    }

    // ── Events ──────────────────────────────────────────────────────

    /// Append a structured event to the persistent log.
    pub fn log_event(&self, event: &[u8]) -> Result<u64> {
        self.backend.append_event(event)
    }

    /// Read events from a sequence number (for replay / catch-up).
    pub fn read_events(&self, from_seq: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        self.backend.read_events(from_seq, limit)
    }

    /// Get the latest event sequence number.
    pub fn latest_event_seq(&self) -> Result<u64> {
        self.backend.latest_event_seq()
    }

    /// Emit a structured event. Best-effort — event emission failures
    /// don't fail the operation that triggered them.
    fn emit(&self, kind: EventKind, actor: Option<IdentityId>) {
        let event = RepoEvent::now(kind, actor);
        if let Ok(json) = serde_json::to_vec(&event) {
            let _ = self.backend.append_event(&json);
        }
    }

    // ── Token revocation ────────────────────────────────────────────

    /// Revoke a token by its BLAKE3 hash.
    pub fn revoke_token(&self, token: &str) -> Result<()> {
        let hash = blake3::hash(token.as_bytes());
        self.backend.revoke_token(hash.as_bytes())
    }

    /// Check if a token is revoked.
    pub fn is_token_revoked(&self, token: &str) -> Result<bool> {
        let hash = blake3::hash(token.as_bytes());
        self.backend.is_token_revoked(hash.as_bytes())
    }

    // ── Merge ────────────────────────────────────────────────────────

    /// Find the merge base (lowest common ancestor) of two changesets.
    /// Uses simultaneous BFS from both sides.
    pub fn find_merge_base(&self, a: &ObjectId, b: &ObjectId) -> Result<Option<ObjectId>> {
        use std::collections::HashSet;
        use std::collections::VecDeque;

        let mut seen_a = HashSet::new();
        let mut seen_b = HashSet::new();
        let mut queue_a = VecDeque::new();
        let mut queue_b = VecDeque::new();

        seen_a.insert(*a);
        seen_b.insert(*b);
        queue_a.push_back(*a);
        queue_b.push_back(*b);

        // Immediate check: same changeset.
        if a == b {
            return Ok(Some(*a));
        }

        loop {
            let progress_a = if let Some(id) = queue_a.pop_front() {
                if seen_b.contains(&id) {
                    return Ok(Some(id));
                }
                if let Some(Object::Changeset(cs)) = self.get_object(&id)? {
                    for p in &cs.parents {
                        if seen_a.insert(*p) {
                            if seen_b.contains(p) {
                                return Ok(Some(*p));
                            }
                            queue_a.push_back(*p);
                        }
                    }
                }
                true
            } else {
                false
            };

            let progress_b = if let Some(id) = queue_b.pop_front() {
                if seen_a.contains(&id) {
                    return Ok(Some(id));
                }
                if let Some(Object::Changeset(cs)) = self.get_object(&id)? {
                    for p in &cs.parents {
                        if seen_b.insert(*p) {
                            if seen_a.contains(p) {
                                return Ok(Some(*p));
                            }
                            queue_b.push_back(*p);
                        }
                    }
                }
                true
            } else {
                false
            };

            if !progress_a && !progress_b {
                return Ok(None); // Disjoint histories.
            }
        }
    }

    /// Check if `ancestor` is an ancestor of `descendant`.
    pub fn is_ancestor(&self, ancestor: &ObjectId, descendant: &ObjectId) -> Result<bool> {
        if ancestor == descendant {
            return Ok(true);
        }
        // BFS from descendant looking for ancestor.
        let mut queue = std::collections::VecDeque::new();
        let mut seen = std::collections::HashSet::new();
        queue.push_back(*descendant);
        seen.insert(*descendant);

        while let Some(id) = queue.pop_front() {
            if let Some(Object::Changeset(cs)) = self.get_object(&id)? {
                for p in &cs.parents {
                    if p == ancestor {
                        return Ok(true);
                    }
                    if seen.insert(*p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Merge a branch into the current branch.
    /// Returns the merge changeset ID, or a list of conflicting paths.
    pub fn merge(
        &self,
        branch_name: &str,
        author: IdentityId,
    ) -> Result<MergeResult> {
        let ours_id = self.resolve_head()?
            .ok_or_else(|| anyhow::anyhow!("HEAD has no commits"))?;
        let theirs_id = self.resolve_ref(&format!("refs/heads/{}", branch_name))?
            .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

        // Fast-forward: theirs is ahead of ours.
        if self.is_ancestor(&ours_id, &theirs_id)? {
            self.update_head_cas(Some(&ours_id), &theirs_id)?;
            self.emit(EventKind::Merge {
                into: self.head_branch().ok().flatten().unwrap_or_default(),
                from: branch_name.to_string(),
                result_id: theirs_id.to_string(),
            }, Some(author));
            return Ok(MergeResult::FastForward(theirs_id));
        }

        // Already up to date: ours is ahead of (or equal to) theirs.
        if self.is_ancestor(&theirs_id, &ours_id)? {
            return Ok(MergeResult::AlreadyUpToDate);
        }

        // Three-way merge.
        let base_id = self.find_merge_base(&ours_id, &theirs_id)?
            .ok_or_else(|| anyhow::anyhow!(
                "cannot merge: no common ancestor between HEAD and '{}'", branch_name
            ))?;

        let base_tree = self.changeset_tree(&base_id)?;
        let ours_tree = self.changeset_tree(&ours_id)?;
        let theirs_tree = self.changeset_tree(&theirs_id)?;

        let mut conflicts = Vec::new();
        let merged_tree_id = self.merge_trees(
            &base_tree, &ours_tree, &theirs_tree,
            &mut conflicts, String::new(),
        )?;

        if !conflicts.is_empty() {
            return Ok(MergeResult::Conflict(conflicts));
        }

        // Create merge changeset.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_micros() as i64;

        let changeset = Changeset {
            parents: vec![ours_id, theirs_id],
            tree: merged_tree_id,
            author,
            timestamp,
            message: format!("Merge branch '{}'", branch_name),
            intent: None,
            metadata: BTreeMap::new(),
        };

        let cs_id = self.put_object(&Object::Changeset(changeset))?;
        self.update_head_cas(Some(&ours_id), &cs_id)?;
        self.emit(EventKind::Merge {
            into: self.head_branch().ok().flatten().unwrap_or_default(),
            from: branch_name.to_string(),
            result_id: cs_id.to_string(),
        }, Some(author));
        Ok(MergeResult::Merged(cs_id))
    }

    /// Get the tree ID from a changeset.
    fn changeset_tree(&self, cs_id: &ObjectId) -> Result<ObjectId> {
        match self.get_object(cs_id)? {
            Some(Object::Changeset(cs)) => Ok(cs.tree),
            _ => bail!("expected changeset: {}", cs_id),
        }
    }

    /// Three-way merge of tree objects. Returns the merged tree ID.
    fn merge_trees(
        &self,
        base: &ObjectId,
        ours: &ObjectId,
        theirs: &ObjectId,
        conflicts: &mut Vec<String>,
        prefix: String,
    ) -> Result<ObjectId> {
        let base_entries = self.tree_entries(base)?;
        let ours_entries = self.tree_entries(ours)?;
        let theirs_entries = self.tree_entries(theirs)?;

        // Collect all entry names.
        let mut all_names: Vec<String> = base_entries.keys()
            .chain(ours_entries.keys())
            .chain(theirs_entries.keys())
            .cloned()
            .collect();
        all_names.sort();
        all_names.dedup();

        let mut merged = BTreeMap::new();

        for name in &all_names {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };

            let b = base_entries.get(name);
            let o = ours_entries.get(name);
            let t = theirs_entries.get(name);

            match (b, o, t) {
                // Unchanged on both sides — keep.
                (Some(base_e), Some(ours_e), Some(theirs_e))
                    if ours_e.id == base_e.id && theirs_e.id == base_e.id =>
                {
                    merged.insert(name.clone(), ours_e.clone());
                }
                // Changed only on ours — take ours.
                (Some(base_e), Some(ours_e), Some(theirs_e))
                    if theirs_e.id == base_e.id =>
                {
                    merged.insert(name.clone(), ours_e.clone());
                }
                // Changed only on theirs — take theirs.
                (Some(base_e), Some(ours_e), Some(theirs_e))
                    if ours_e.id == base_e.id =>
                {
                    merged.insert(name.clone(), theirs_e.clone());
                }
                // Both changed to the same thing — take either.
                (Some(_), Some(ours_e), Some(theirs_e))
                    if ours_e.id == theirs_e.id =>
                {
                    merged.insert(name.clone(), ours_e.clone());
                }
                // Both changed differently — try recursive tree merge or conflict.
                (Some(_base_e), Some(ours_e), Some(theirs_e))
                    if ours_e.kind == EntryKind::Directory
                        && theirs_e.kind == EntryKind::Directory =>
                {
                    let base_sub = _base_e.id;
                    let sub_id = self.merge_trees(
                        &base_sub, &ours_e.id, &theirs_e.id,
                        conflicts, path,
                    )?;
                    merged.insert(name.clone(), TreeEntry {
                        id: sub_id,
                        kind: EntryKind::Directory,
                        executable: false,
                    });
                }
                // Both changed files differently — conflict.
                (Some(_), Some(_), Some(_)) => {
                    conflicts.push(path);
                }
                // Added only in ours.
                (None, Some(ours_e), None) => {
                    merged.insert(name.clone(), ours_e.clone());
                }
                // Added only in theirs.
                (None, None, Some(theirs_e)) => {
                    merged.insert(name.clone(), theirs_e.clone());
                }
                // Added in both with same content — take either.
                (None, Some(ours_e), Some(theirs_e))
                    if ours_e.id == theirs_e.id =>
                {
                    merged.insert(name.clone(), ours_e.clone());
                }
                // Added in both differently — conflict.
                (None, Some(_), Some(_)) => {
                    conflicts.push(path);
                }
                // Deleted in ours, unchanged in theirs — delete.
                (Some(base_e), None, Some(theirs_e))
                    if theirs_e.id == base_e.id =>
                {
                    // Omit from merged (deleted).
                }
                // Deleted in theirs, unchanged in ours — delete.
                (Some(base_e), Some(ours_e), None)
                    if ours_e.id == base_e.id =>
                {
                    // Omit from merged (deleted).
                }
                // Deleted in one but modified in other — conflict.
                (Some(_), None, Some(_)) | (Some(_), Some(_), None) => {
                    conflicts.push(path);
                }
                // Deleted in both — omit.
                (Some(_), None, None) => {}
                // Impossible: not in base, not in either side.
                (None, None, None) => {}
            }
        }

        let tree = Object::Tree(Tree { entries: merged });
        self.put_object(&tree)
    }

    /// Get the entries of a tree object (empty map for ZERO id).
    fn tree_entries(&self, tree_id: &ObjectId) -> Result<BTreeMap<String, TreeEntry>> {
        if *tree_id == ObjectId::ZERO {
            return Ok(BTreeMap::new());
        }
        match self.get_object(tree_id)? {
            Some(Object::Tree(t)) => Ok(t.entries),
            _ => Ok(BTreeMap::new()),
        }
    }

    // ── Remote config ──────────────────────────────────────────────

    /// Add a remote.
    pub fn add_remote(&self, name: &str, url: &str) -> Result<()> {
        let key = format!("remote.{}.url", name);
        if self.backend.get_config(&key)?.is_some() {
            bail!("remote '{}' already exists", name);
        }
        self.backend.set_config(&key, url)
    }

    /// Remove a remote and its associated config (URL, token, etc.).
    pub fn remove_remote(&self, name: &str) -> Result<()> {
        let url_key = format!("remote.{}.url", name);
        if self.backend.get_config(&url_key)?.is_none() {
            bail!("remote '{}' not found", name);
        }
        self.backend.delete_config(&url_key)?;
        // Also clean up associated config (e.g., token).
        let token_key = format!("remote.{}.token", name);
        self.backend.delete_config(&token_key)?;
        Ok(())
    }

    /// Get a remote URL.
    pub fn get_remote_url(&self, name: &str) -> Result<Option<String>> {
        let key = format!("remote.{}.url", name);
        self.backend.get_config(&key)
    }

    /// List all remotes as `(name, url)` pairs.
    pub fn list_remotes(&self) -> Result<Vec<(String, String)>> {
        let entries = self.backend.list_config_prefix("remote.")?;
        let mut remotes = Vec::new();
        for (key, url) in entries {
            // key is "<name>.url" (prefix "remote." already stripped)
            if let Some(name) = key.strip_suffix(".url")
                && !url.is_empty() {
                    remotes.push((name.to_string(), url));
                }
        }
        Ok(remotes)
    }

    // ── Stash ────────────────────────────────────────────────────────

    /// Stash the current working tree changes. Returns the stash index.
    pub fn stash_save(&self, message: &str) -> Result<usize> {
        let status = self.status()?;
        if status.is_clean() {
            bail!("nothing to stash");
        }

        // Snapshot the current working tree.
        let tree_id = self.snapshot_tree(&self.root)?;
        let head_id = self.resolve_head()?;

        let author = self.local_identity()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_micros() as i64;

        let changeset = Changeset {
            parents: head_id.into_iter().collect(),
            tree: tree_id,
            author,
            timestamp,
            message: if message.is_empty() {
                "WIP on stash".to_string()
            } else {
                message.to_string()
            },
            intent: None,
            metadata: BTreeMap::new(),
        };

        let cs_id = self.put_object(&Object::Changeset(changeset))?;

        // Allocate the next stash index atomically via CAS loop.
        // If two concurrent stash_save() calls pick the same index,
        // cas_ref(expected=None) fails for the loser, who retries.
        let next_idx = loop {
            let stash_refs = self.backend.list_refs("refs/stash/")?;
            let idx = stash_refs.iter()
                .filter_map(|(name, _)| name.strip_prefix("refs/stash/")?.parse::<usize>().ok())
                .max()
                .map(|n| n + 1)
                .unwrap_or(0);

            let ref_name = format!("refs/stash/{}", idx);
            if self.backend.cas_ref(&ref_name, None, &Ref::Direct(cs_id))? {
                break idx;
            }
            // CAS failed — another writer claimed this index. Retry.
        };

        // Restore working tree to HEAD.
        if let Some(head) = head_id
            && let Some(Object::Changeset(cs)) = self.get_object(&head)? {
                self.force_checkout_tree(&cs.tree)?;
            }

        Ok(next_idx)
    }

    /// Pop the most recent stash entry and restore it to the working tree.
    pub fn stash_pop(&self) -> Result<ObjectId> {
        let stash_refs = self.backend.list_refs("refs/stash/")?;
        let latest = stash_refs.iter()
            .filter_map(|(name, _)| {
                let idx = name.strip_prefix("refs/stash/")?.parse::<usize>().ok()?;
                Some((idx, name.clone()))
            })
            .max_by_key(|(idx, _)| *idx);

        let (_, ref_name) = latest
            .ok_or_else(|| anyhow::anyhow!("no stash entries"))?;

        let cs_id = self.resolve_ref(&ref_name)?
            .ok_or_else(|| anyhow::anyhow!("stash ref broken"))?;

        if let Some(Object::Changeset(cs)) = self.get_object(&cs_id)? {
            self.force_checkout_tree(&cs.tree)?;
        }

        self.backend.delete_ref(&ref_name)?;
        Ok(cs_id)
    }

    /// List stash entries (index, message).
    pub fn stash_list(&self) -> Result<Vec<(usize, String)>> {
        let stash_refs = self.backend.list_refs("refs/stash/")?;
        let mut entries = Vec::new();
        for (name, _) in &stash_refs {
            if let Some(idx_str) = name.strip_prefix("refs/stash/")
                && let Ok(idx) = idx_str.parse::<usize>() {
                    let cs_id = self.resolve_ref(name)?;
                    let msg = if let Some(id) = cs_id {
                        if let Some(Object::Changeset(cs)) = self.get_object(&id)? {
                            cs.message
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    entries.push((idx, msg));
                }
        }
        entries.sort_by_key(|(idx, _)| *idx);
        Ok(entries)
    }

    // ── Exploration tree ─────────────────────────────────────────────

    /// Create a new exploration goal. Returns the goal's content-addressed ID.
    ///
    /// Stores the goal as a JSON Blob and creates refs for the goal metadata
    /// and target branch. Agents can then create approaches under this goal.
    pub fn create_goal(&self, goal: &Goal) -> Result<ObjectId> {
        let json = serde_json::to_vec(goal)
            .context("failed to serialize goal")?;
        let blob = Object::Blob(Blob { data: json });
        let goal_id = self.put_object(&blob)?;

        // Create the meta ref (CAS: must not already exist).
        let meta_ref = exploration::refs::goal_meta(&goal_id);
        if !self.backend.cas_ref(&meta_ref, None, &Ref::Direct(goal_id))? {
            bail!("goal already exists: {}", &goal_id.to_hex()[..16]);
        }

        // Store the target branch as a symbolic ref.
        let target_ref = exploration::refs::goal_target(&goal_id);
        let target = format!("refs/heads/{}", goal.target_branch);
        self.backend.set_ref(&target_ref, &Ref::Symbolic(target))?;

        self.emit(EventKind::GoalCreated {
            goal_id: goal_id.to_string(),
            description: goal.description.clone(),
        }, Some(goal.created_by));

        Ok(goal_id)
    }

    /// Create a new approach branch for a goal. Returns the approach ref name.
    ///
    /// The approach branch starts from the current tip of the goal's target
    /// branch (e.g., main). Agents commit to this branch independently.
    pub fn create_approach(
        &self,
        goal_id: &ObjectId,
        name: &str,
        agent: IdentityId,
    ) -> Result<String> {
        // Verify goal exists.
        let meta_ref = exploration::refs::goal_meta(goal_id);
        if self.backend.get_ref(&meta_ref)?.is_none() {
            bail!("goal not found: {}", &goal_id.to_hex()[..16]);
        }

        // Read the goal to check max_approaches.
        let goal = self.get_goal(goal_id)?
            .ok_or_else(|| anyhow::anyhow!("goal metadata blob missing"))?;
        if goal.max_approaches > 0 {
            let prefix = exploration::refs::approaches_prefix(goal_id);
            let existing = self.backend.list_refs(&prefix)?;
            if existing.len() >= goal.max_approaches as usize {
                bail!(
                    "goal has reached max approaches ({}) — promote or abandon before adding more",
                    goal.max_approaches
                );
            }
        }

        // Start the approach from the target branch tip.
        let target_ref = exploration::refs::goal_target(goal_id);
        let base = match self.backend.get_ref(&target_ref)? {
            Some(Ref::Symbolic(branch)) => self.resolve_ref(&branch)?,
            Some(Ref::Direct(id)) => Some(id),
            None => None,
        };

        let approach_ref = exploration::refs::approach_tip(goal_id, name);
        if let Some(base_id) = base {
            if !self.backend.cas_ref(&approach_ref, None, &Ref::Direct(base_id))? {
                bail!("approach '{}' already exists for this goal", name);
            }
        } else {
            // No target branch tip yet — create approach ref pointing to nothing.
            // The first commit on this approach will set it.
            bail!("target branch has no commits — commit to {} first", goal.target_branch);
        }

        // Create a claim for this agent.
        self.claim_approach(goal_id, name, agent, "")?;

        self.emit(EventKind::ApproachCreated {
            goal_id: goal_id.to_string(),
            approach: name.to_string(),
            agent: agent.to_string(),
        }, Some(agent));

        Ok(approach_ref)
    }

    /// Claim an approach for an agent (with TTL-based heartbeat).
    pub fn claim_approach(
        &self,
        goal_id: &ObjectId,
        approach: &str,
        agent: IdentityId,
        intent: &str,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_micros() as i64;

        let claim = Claim {
            agent,
            approach: approach.to_string(),
            expires_at: now + (DEFAULT_CLAIM_TTL_SECS as i64 * 1_000_000),
            intent: intent.to_string(),
            heartbeat: 0,
        };

        let json = serde_json::to_vec(&claim)?;
        let blob = Object::Blob(Blob { data: json });
        let claim_id = self.put_object(&blob)?;

        let claim_ref = exploration::refs::agent_claim(goal_id, &agent);
        // Force-set: agent can always update its own claim.
        self.backend.set_ref(&claim_ref, &Ref::Direct(claim_id))?;
        Ok(())
    }

    /// Refresh an agent's claim (heartbeat). Extends the TTL.
    pub fn refresh_claim(
        &self,
        goal_id: &ObjectId,
        agent: IdentityId,
    ) -> Result<()> {
        let claim_ref = exploration::refs::agent_claim(goal_id, &agent);
        let current = self.backend.get_ref(&claim_ref)?
            .ok_or_else(|| anyhow::anyhow!("no active claim for this agent"))?;

        if let Ref::Direct(blob_id) = current
            && let Some(Object::Blob(blob)) = self.get_object(&blob_id)? {
                let mut claim: Claim = serde_json::from_slice(&blob.data)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .context("system clock before UNIX epoch")?
                    .as_micros() as i64;
                claim.expires_at = now + (DEFAULT_CLAIM_TTL_SECS as i64 * 1_000_000);
                claim.heartbeat += 1;

                let json = serde_json::to_vec(&claim)?;
                let new_blob = Object::Blob(Blob { data: json });
                let new_id = self.put_object(&new_blob)?;
                self.backend.set_ref(&claim_ref, &Ref::Direct(new_id))?;
            }
        Ok(())
    }

    /// Release an agent's claim on an approach.
    pub fn release_claim(
        &self,
        goal_id: &ObjectId,
        agent: IdentityId,
    ) -> Result<()> {
        let claim_ref = exploration::refs::agent_claim(goal_id, &agent);
        self.backend.delete_ref(&claim_ref)?;
        Ok(())
    }

    /// Read a goal's metadata from the store.
    pub fn get_goal(&self, goal_id: &ObjectId) -> Result<Option<Goal>> {
        match self.get_object(goal_id)? {
            Some(Object::Blob(blob)) => {
                let goal: Goal = serde_json::from_slice(&blob.data)
                    .context("failed to deserialize goal")?;
                Ok(Some(goal))
            }
            _ => Ok(None),
        }
    }

    /// List all active goals.
    pub fn list_goals(&self) -> Result<Vec<(ObjectId, Goal)>> {
        let refs = self.backend.list_refs(exploration::refs::EXPLORE_PREFIX)?;
        let mut goals = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (name, reference) in &refs {
            // Match refs ending in "//meta".
            if name.ends_with("//meta")
                && let Ref::Direct(blob_id) = reference
                    && seen.insert(*blob_id)
                        && let Some(goal) = self.get_goal(blob_id)? {
                            goals.push((*blob_id, goal));
                        }
        }
        Ok(goals)
    }

    /// Get a complete summary of a goal's exploration state.
    pub fn goal_summary(&self, goal_id: &ObjectId) -> Result<GoalSummary> {
        let goal = self.get_goal(goal_id)?
            .ok_or_else(|| anyhow::anyhow!("goal not found"))?;

        // Read approaches.
        let approach_prefix = exploration::refs::approaches_prefix(goal_id);
        let approach_refs = self.backend.list_refs(&approach_prefix)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_micros() as i64;

        let mut approaches = Vec::new();
        for (name, reference) in &approach_refs {
            let approach_name = name.strip_prefix(&approach_prefix)
                .unwrap_or(name)
                .to_string();

            let (tip, latest_message, created_by, count) = match reference {
                Ref::Direct(id) => {
                    match self.get_object(id)? {
                        Some(Object::Changeset(cs)) => {
                            let count = self.approach_depth(id)?;
                            (Some(*id), Some(cs.message.clone()), Some(cs.author), count)
                        }
                        _ => (Some(*id), None, None, 0),
                    }
                }
                _ => (None, None, None, 0),
            };

            approaches.push(ApproachSummary {
                name: approach_name,
                tip,
                changeset_count: count,
                latest_message,
                created_by,
                verification: tip.map(|id| self.compute_verification_level(&id).unwrap_or(VerificationLevel::Unknown))
                    .unwrap_or(VerificationLevel::Unknown),
            });
        }

        // Read claims (filter out expired).
        let claims_prefix = exploration::refs::claims_prefix(goal_id);
        let claim_refs = self.backend.list_refs(&claims_prefix)?;
        let mut claims = Vec::new();
        for (_name, reference) in &claim_refs {
            if let Ref::Direct(blob_id) = reference
                && let Some(Object::Blob(blob)) = self.get_object(blob_id)?
                    && let Ok(claim) = serde_json::from_slice::<Claim>(&blob.data)
                        && claim.expires_at > now {
                            claims.push(claim);
                        }
        }

        // Check if promoted.
        let promoted_ref = exploration::refs::goal_promoted(goal_id);
        let promoted = self.backend.get_ref(&promoted_ref)?.is_some();
        let promoted_name = if promoted {
            // Find which approach was promoted by checking which tip matches.
            // (Simple heuristic: could also store this explicitly.)
            None // TODO: store approach name in promoted metadata
        } else {
            None
        };

        Ok(GoalSummary {
            goal,
            goal_id: *goal_id,
            approaches,
            claims,
            promoted: promoted_name,
        })
    }

    /// Count how many changesets deep an approach is from its base.
    fn approach_depth(&self, tip: &ObjectId) -> Result<usize> {
        let mut count = 0;
        let mut current = Some(*tip);
        while let Some(id) = current {
            count += 1;
            if count > 1000 {
                break; // Safety limit.
            }
            match self.get_object(&id)? {
                Some(Object::Changeset(cs)) => {
                    current = cs.parents.first().copied();
                }
                _ => break,
            }
        }
        Ok(count)
    }

    /// Promote an approach: merge it into the goal's target branch.
    ///
    /// This is the convergence step — the exploration tree collapses
    /// into a single winning changeset on the target branch.
    pub fn promote_approach(
        &self,
        goal_id: &ObjectId,
        approach_name: &str,
        author: IdentityId,
    ) -> Result<PromoteResult> {
        let goal = self.get_goal(goal_id)?
            .ok_or_else(|| anyhow::anyhow!("goal not found"))?;

        // Get the approach tip.
        let approach_ref = exploration::refs::approach_tip(goal_id, approach_name);
        let approach_tip = self.resolve_ref(&approach_ref)?
            .ok_or_else(|| anyhow::anyhow!("approach '{}' not found", approach_name))?;

        // Get the target branch tip.
        let target_branch = format!("refs/heads/{}", goal.target_branch);
        let target_tip = self.resolve_ref(&target_branch)?;

        let result = match target_tip {
            None => {
                // Target branch empty — just point it to the approach tip.
                self.backend.set_ref(&target_branch, &Ref::Direct(approach_tip))?;
                PromoteResult::FastForward(approach_tip)
            }
            Some(target_id) if target_id == approach_tip => {
                // Already up to date.
                PromoteResult::FastForward(approach_tip)
            }
            Some(target_id) => {
                // Check if approach is a descendant of target (fast-forward).
                if self.is_ancestor(&target_id, &approach_tip)? {
                    self.backend.cas_ref(
                        &target_branch,
                        Some(&Ref::Direct(target_id)),
                        &Ref::Direct(approach_tip),
                    )?;
                    PromoteResult::FastForward(approach_tip)
                } else {
                    // Need a merge.
                    let base_id = self.find_merge_base(&target_id, &approach_tip)?
                        .ok_or_else(|| anyhow::anyhow!(
                            "no common ancestor between target and approach"
                        ))?;

                    let base_tree = self.changeset_tree(&base_id)?;
                    let target_tree = self.changeset_tree(&target_id)?;
                    let approach_tree = self.changeset_tree(&approach_tip)?;

                    let mut conflicts = Vec::new();
                    let merged_tree_id = self.merge_trees(
                        &base_tree, &target_tree, &approach_tree,
                        &mut conflicts, String::new(),
                    )?;

                    if !conflicts.is_empty() {
                        return Ok(PromoteResult::Conflict(conflicts));
                    }

                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .context("system clock before UNIX epoch")?
                        .as_micros() as i64;

                    let changeset = Changeset {
                        parents: vec![target_id, approach_tip],
                        tree: merged_tree_id,
                        author,
                        timestamp,
                        message: format!(
                            "Promote exploration '{}' from goal {}",
                            approach_name,
                            &goal_id.to_hex()[..12],
                        ),
                        intent: Some(Intent {
                            kind: IntentKind::Exploration,
                            affected_paths: vec![],
                            rationale: format!(
                                "Promoted approach '{}': {}",
                                approach_name, goal.description,
                            ),
                            context_ref: Some(*goal_id),
                            verifications: vec![],
                        }),
                        metadata: BTreeMap::new(),
                    };

                    let cs_id = self.put_object(&Object::Changeset(changeset))?;
                    self.backend.cas_ref(
                        &target_branch,
                        Some(&Ref::Direct(target_id)),
                        &Ref::Direct(cs_id),
                    )?;
                    PromoteResult::Merged(cs_id)
                }
            }
        };

        // Mark goal as promoted.
        let promoted_ref = exploration::refs::goal_promoted(goal_id);
        self.backend.set_ref(&promoted_ref, &Ref::Direct(approach_tip))?;

        let result_id = match &result {
            PromoteResult::FastForward(id) | PromoteResult::Merged(id) => id.to_string(),
            PromoteResult::Conflict(_) => String::new(),
        };
        if !result_id.is_empty() {
            self.emit(EventKind::Promoted {
                goal_id: goal_id.to_string(),
                approach: approach_name.to_string(),
                result_id,
            }, Some(author));
        }

        Ok(result)
    }

    /// Abandon a goal — clean up all exploration refs.
    /// Objects remain in the store (content-addressed GC is separate).
    pub fn abandon_goal(&self, goal_id: &ObjectId) -> Result<usize> {
        let prefix = format!(
            "{}{}//",
            exploration::refs::EXPLORE_PREFIX,
            &goal_id.to_hex()[..16],
        );
        let refs = self.backend.list_refs(&prefix)?;
        let count = refs.len();
        for (name, _) in &refs {
            self.backend.delete_ref(name)?;
        }
        self.emit(EventKind::GoalAbandoned {
            goal_id: goal_id.to_string(),
        }, None);
        Ok(count)
    }

    // ── Reset ────────────────────────────────────────────────────────

    /// Reset HEAD to a specific changeset. Modes:
    /// - soft: only move the ref, keep working tree
    /// - hard: move ref and restore working tree
    pub fn reset(&self, target: &ObjectId, hard: bool) -> Result<()> {
        // Verify target is a changeset.
        match self.get_object(target)? {
            Some(Object::Changeset(cs)) => {
                // Reset is intentionally force — the user asked to move HEAD.
                self.update_head_force(target)?;
                if hard {
                    self.force_checkout_tree(&cs.tree)?;
                }
                Ok(())
            }
            _ => bail!("target {} is not a changeset", target),
        }
    }

    // ── Garbage collection ────────────────────────────────────────

    /// Mark-and-sweep garbage collection. Deletes unreachable objects.
    ///
    /// Walks all refs to find reachable objects, then deletes any object
    /// not in the reachable set. Returns (total_objects, deleted_count).
    pub fn gc(&self) -> Result<(usize, usize)> {
        // 1. Mark: walk all refs to find reachable objects.
        let mut reachable = std::collections::HashSet::new();
        let refs = self.backend.list_refs("")?;

        for (_name, reference) in &refs {
            if let Ref::Direct(id) = reference {
                self.mark_reachable(id, &mut reachable)?;
            }
        }

        // 2. Sweep: delete unreachable objects.
        let all_ids = self.backend.list_all_object_ids()?;
        let total = all_ids.len();
        let mut deleted = 0;

        for id in &all_ids {
            if !reachable.contains(id)
                && self.backend.delete_object(id)? {
                    deleted += 1;
                }
        }

        Ok((total, deleted))
    }

    /// Recursively mark an object and its children as reachable.
    fn mark_reachable(
        &self,
        id: &ObjectId,
        reachable: &mut std::collections::HashSet<ObjectId>,
    ) -> Result<()> {
        if !reachable.insert(*id) {
            return Ok(()); // Already visited.
        }
        match self.get_object(id)? {
            Some(Object::Changeset(cs)) => {
                for parent in &cs.parents {
                    self.mark_reachable(parent, reachable)?;
                }
                self.mark_reachable(&cs.tree, reachable)?;
            }
            Some(Object::Tree(tree)) => {
                for entry in tree.entries.values() {
                    self.mark_reachable(&entry.id, reachable)?;
                }
            }
            Some(Object::Envelope(_)) | Some(Object::Blob(_)) => {
                // Leaf objects — no children to mark.
            }
            None => {} // Object referenced but missing — skip.
        }
        Ok(())
    }

    // ── Tree-to-tree diff ───────────────────────────────────────────

    /// Diff two tree objects. Returns lists of added, modified, and deleted paths.
    pub fn diff_trees(
        &self,
        old_tree: Option<&ObjectId>,
        new_tree: &ObjectId,
    ) -> Result<DiffResult> {
        let old_entries = match old_tree {
            Some(id) => self.flatten_tree(id, String::new())?,
            None => BTreeMap::new(),
        };
        let new_entries = self.flatten_tree(new_tree, String::new())?;

        let mut result = DiffResult::default();

        for (path, new_id) in &new_entries {
            match old_entries.get(path) {
                None => result.added.push(path.clone()),
                Some(old_id) if old_id != new_id => result.modified.push(path.clone()),
                _ => {} // Unchanged.
            }
        }
        for path in old_entries.keys() {
            if !new_entries.contains_key(path) {
                result.deleted.push(path.clone());
            }
        }

        Ok(result)
    }

    /// Diff a changeset against its first parent.
    pub fn diff_changeset(&self, cs_id: &ObjectId) -> Result<DiffResult> {
        match self.get_object(cs_id)? {
            Some(Object::Changeset(cs)) => {
                let parent_tree = cs.parents.first()
                    .and_then(|pid| self.changeset_tree(pid).ok());
                self.diff_trees(parent_tree.as_ref(), &cs.tree)
            }
            _ => bail!("not a changeset: {}", cs_id),
        }
    }

    /// Flatten a tree into a map of path → blob ObjectId.
    fn flatten_tree(
        &self,
        tree_id: &ObjectId,
        prefix: String,
    ) -> Result<BTreeMap<String, ObjectId>> {
        let mut result = BTreeMap::new();
        if let Some(Object::Tree(tree)) = self.get_object(tree_id)? {
            for (name, entry) in &tree.entries {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", prefix, name)
                };
                match entry.kind {
                    EntryKind::File | EntryKind::Symlink => {
                        result.insert(path, entry.id);
                    }
                    EntryKind::Directory => {
                        let sub = self.flatten_tree(&entry.id, path)?;
                        result.extend(sub);
                    }
                }
            }
        }
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
            let rel = if dir == self.root {
                name.to_string()
            } else {
                let prefix = dir.strip_prefix(&self.root).unwrap_or(dir.as_ref());
                format!("{}/{}", prefix.display(), name)
            };
            for pattern in &patterns {
                // Trailing / means directory-only — we match against name regardless
                // since we don't know entry type here; the caller skips non-dirs.
                let pat = pattern.strip_suffix('/').unwrap_or(pattern);
                // If pattern contains /, match against the relative path.
                if pat.contains('/') {
                    if glob_match(pat, &rel) {
                        return true;
                    }
                } else {
                    // Match against just the filename component.
                    if glob_match(pat, name) {
                        return true;
                    }
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

/// Check if a granted capability scope covers a required scope.
fn scope_covers(granted: &CapabilityScope, required: &CapabilityScope) -> bool {
    match granted {
        CapabilityScope::Global => true, // Global covers everything.
        CapabilityScope::Repository(granted_repo) => match required {
            CapabilityScope::Global => false,
            CapabilityScope::Repository(req_repo) => granted_repo == req_repo,
            CapabilityScope::Path { repo, .. } => granted_repo == repo,
            CapabilityScope::Branch { repo, .. } => granted_repo == repo,
        },
        CapabilityScope::Path { repo: g_repo, pattern: g_pat } => match required {
            CapabilityScope::Path { repo: r_repo, pattern: r_pat } => {
                g_repo == r_repo && gritgrub_core::policy::glob_match_ref(g_pat, r_pat)
            }
            _ => false,
        },
        CapabilityScope::Branch { repo: g_repo, pattern: g_pat } => match required {
            CapabilityScope::Branch { repo: r_repo, pattern: r_pat } => {
                g_repo == r_repo && gritgrub_core::policy::glob_match_ref(g_pat, r_pat)
            }
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn glob_exact() {
        assert!(glob_match("foo.txt", "foo.txt"));
        assert!(!glob_match("foo.txt", "bar.txt"));
    }

    #[test]
    fn glob_star_extension() {
        assert!(glob_match("*.o", "main.o"));
        assert!(glob_match("*.o", ".o"));
        assert!(!glob_match("*.o", "main.c"));
        assert!(glob_match("*.log", "server.log"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("test_*", "test_foo"));
        assert!(!glob_match("test_*", "main_foo"));
    }

    #[test]
    fn glob_question_mark() {
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
    }

    #[test]
    fn glob_star_does_not_cross_slash() {
        assert!(!glob_match("*.o", "build/main.o"));
        assert!(glob_match("build/*.o", "build/main.o"));
    }
}
