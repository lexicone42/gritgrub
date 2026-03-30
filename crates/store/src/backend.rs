use anyhow::Result;
use gritgrub_core::{ObjectId, Object, Ref, Identity, IdentityId, Capability};

/// Low-level content-addressable object storage.
pub trait ObjectStore {
    fn put_object(&self, object: &Object) -> Result<ObjectId>;
    fn get_object(&self, id: &ObjectId) -> Result<Option<Object>>;
    fn has_object(&self, id: &ObjectId) -> Result<bool>;
    fn find_objects_by_prefix(&self, hex_prefix: &str) -> Result<Vec<(ObjectId, Object)>>;
    /// List all object IDs in the store (for garbage collection).
    fn list_all_object_ids(&self) -> Result<Vec<ObjectId>>;
    /// Delete an object by ID. Returns true if the object existed.
    fn delete_object(&self, id: &ObjectId) -> Result<bool>;
}

/// Named reference storage (branches, HEAD, tags).
pub trait RefStore {
    fn set_ref(&self, name: &str, reference: &Ref) -> Result<()>;
    fn get_ref(&self, name: &str) -> Result<Option<Ref>>;
    fn delete_ref(&self, name: &str) -> Result<bool>;
    fn list_refs(&self, prefix: &str) -> Result<Vec<(String, Ref)>>;
    /// Compare-and-swap: update ref only if its current value matches `expected`.
    /// Returns Ok(true) if the swap succeeded, Ok(false) if the current value didn't match.
    fn cas_ref(&self, name: &str, expected: Option<&Ref>, new: &Ref) -> Result<bool>;
}

/// Key-value config storage.
pub trait ConfigStore {
    fn get_config(&self, key: &str) -> Result<Option<String>>;
    fn set_config(&self, key: &str, value: &str) -> Result<()>;
    fn delete_config(&self, key: &str) -> Result<bool>;
    /// List all config entries whose key starts with `prefix`.
    /// Returns `(key, value)` pairs with the prefix stripped from the key.
    fn list_config_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>>;
}

/// Identity storage — mutable entities, not content-addressed.
pub trait IdentityStore {
    fn put_identity(&self, identity: &Identity) -> Result<()>;
    fn get_identity(&self, id: &IdentityId) -> Result<Option<Identity>>;
    fn list_identities(&self) -> Result<Vec<Identity>>;
    fn set_capabilities(&self, id: &IdentityId, caps: &[Capability]) -> Result<()>;
    fn get_capabilities(&self, id: &IdentityId) -> Result<Vec<Capability>>;
}

/// Append-only event log for audit trails and replay.
pub trait EventStore {
    /// Append an event, returns the sequence number.
    fn append_event(&self, event: &[u8]) -> Result<u64>;
    /// Read events starting from a sequence number (inclusive).
    fn read_events(&self, from_seq: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>>;
    /// Get the latest sequence number (0 if no events).
    fn latest_event_seq(&self) -> Result<u64>;
}

/// Token revocation list.
pub trait RevocationStore {
    /// Mark a token hash as revoked.
    fn revoke_token(&self, token_hash: &[u8; 32]) -> Result<()>;
    /// Check if a token hash is revoked.
    fn is_token_revoked(&self, token_hash: &[u8; 32]) -> Result<bool>;
}

/// Unified backend trait — implementors provide the full storage surface.
/// This is what alternative backends (postgres, S3+index) implement.
pub trait Backend: ObjectStore + RefStore + ConfigStore + IdentityStore + EventStore + RevocationStore + Send + Sync {}

/// Blanket impl: anything that implements all sub-traits is a Backend.
impl<T: ObjectStore + RefStore + ConfigStore + IdentityStore + EventStore + RevocationStore + Send + Sync> Backend for T {}
