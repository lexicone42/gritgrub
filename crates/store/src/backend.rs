use anyhow::Result;
use gritgrub_core::{ObjectId, Object, Ref};

/// Low-level content-addressable object storage.
pub trait ObjectStore {
    fn put_object(&self, object: &Object) -> Result<ObjectId>;
    fn get_object(&self, id: &ObjectId) -> Result<Option<Object>>;
    fn has_object(&self, id: &ObjectId) -> Result<bool>;
}

/// Named reference storage (branches, HEAD, tags).
pub trait RefStore {
    fn set_ref(&self, name: &str, reference: &Ref) -> Result<()>;
    fn get_ref(&self, name: &str) -> Result<Option<Ref>>;
    fn delete_ref(&self, name: &str) -> Result<bool>;
    fn list_refs(&self, prefix: &str) -> Result<Vec<(String, Ref)>>;
}
