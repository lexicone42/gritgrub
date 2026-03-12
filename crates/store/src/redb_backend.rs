use std::path::Path;
use anyhow::Result;
use redb::{Database, TableDefinition, ReadableTable};
use gritgrub_core::{ObjectId, Object, Ref, Identity, IdentityId, Capability};
use crate::backend::{ObjectStore, RefStore, ConfigStore, IdentityStore, EventStore, RevocationStore};

const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const REFS: TableDefinition<&str, &[u8]> = TableDefinition::new("refs");
const CONFIG: TableDefinition<&str, &str> = TableDefinition::new("config");
const IDENTITIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("identities");
const CAPABILITIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("capabilities");
const EVENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("events");
const REVOKED_TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revoked_tokens");

pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    pub fn create(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        {
            tx.open_table(OBJECTS)?;
            tx.open_table(REFS)?;
            tx.open_table(CONFIG)?;
            tx.open_table(IDENTITIES)?;
            tx.open_table(CAPABILITIES)?;
            tx.open_table(EVENTS)?;
            tx.open_table(REVOKED_TOKENS)?;
        }
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::open(path)?;
        // Ensure new tables exist (migration for repos created before these were added).
        let tx = db.begin_write()?;
        {
            tx.open_table(CAPABILITIES)?;
            tx.open_table(EVENTS)?;
            tx.open_table(REVOKED_TOKENS)?;
        }
        tx.commit()?;
        Ok(Self { db })
    }
}

// ── ObjectStore ────────────────────────────────────────────────────

impl ObjectStore for RedbBackend {
    fn put_object(&self, object: &Object) -> Result<ObjectId> {
        let id = object.id();
        let bytes = object.to_tagged_bytes();
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(OBJECTS)?;
            table.insert(id.as_bytes().as_slice(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(id)
    }

    fn get_object(&self, id: &ObjectId) -> Result<Option<Object>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(OBJECTS)?;
        match table.get(id.as_bytes().as_slice())? {
            Some(data) => {
                let obj = Object::from_tagged_bytes(data.value())?;
                Ok(Some(obj))
            }
            None => Ok(None),
        }
    }

    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(OBJECTS)?;
        Ok(table.get(id.as_bytes().as_slice())?.is_some())
    }

    fn find_objects_by_prefix(&self, hex_prefix: &str) -> Result<Vec<(ObjectId, Object)>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(OBJECTS)?;
        let mut results = Vec::new();

        for entry in table.iter()? {
            let (key, value) = entry?;
            let key_bytes: [u8; 32] = key.value().try_into()
                .map_err(|_| anyhow::anyhow!("invalid object key length"))?;
            let id = ObjectId::from_bytes(key_bytes);
            if id.to_hex().starts_with(hex_prefix) {
                let obj = Object::from_tagged_bytes(value.value())?;
                results.push((id, obj));
                if results.len() > 1 {
                    break;
                }
            }
        }

        Ok(results)
    }
}

// ── RefStore ───────────────────────────────────────────────────────

impl RefStore for RedbBackend {
    fn set_ref(&self, name: &str, reference: &Ref) -> Result<()> {
        let bytes = postcard::to_allocvec(reference)?;
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(REFS)?;
            table.insert(name, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    fn get_ref(&self, name: &str) -> Result<Option<Ref>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(REFS)?;
        match table.get(name)? {
            Some(data) => {
                let reference: Ref = postcard::from_bytes(data.value())?;
                Ok(Some(reference))
            }
            None => Ok(None),
        }
    }

    fn delete_ref(&self, name: &str) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = {
            let mut table = tx.open_table(REFS)?;
            table.remove(name)?.is_some()
        };
        tx.commit()?;
        Ok(existed)
    }

    fn list_refs(&self, prefix: &str) -> Result<Vec<(String, Ref)>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(REFS)?;
        let mut refs = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let name = key.value().to_string();
            if name.starts_with(prefix) {
                let reference: Ref = postcard::from_bytes(value.value())?;
                refs.push((name, reference));
            }
        }
        Ok(refs)
    }
}

// ── ConfigStore ────────────────────────────────────────────────────

impl ConfigStore for RedbBackend {
    fn get_config(&self, key: &str) -> Result<Option<String>> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(key)? {
            Some(val) => Ok(Some(val.value().to_string())),
            None => Ok(None),
        }
    }

    fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(CONFIG)?;
            table.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ── IdentityStore ──────────────────────────────────────────────────

impl IdentityStore for RedbBackend {
    fn put_identity(&self, identity: &Identity) -> Result<()> {
        let bytes = postcard::to_allocvec(identity)?;
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(IDENTITIES)?;
            table.insert(identity.id.as_bytes().as_slice(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    fn get_identity(&self, id: &IdentityId) -> Result<Option<Identity>> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(IDENTITIES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(id.as_bytes().as_slice())? {
            Some(data) => {
                let ident: Identity = postcard::from_bytes(data.value())?;
                Ok(Some(ident))
            }
            None => Ok(None),
        }
    }

    fn list_identities(&self) -> Result<Vec<Identity>> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(IDENTITIES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut identities = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let ident: Identity = postcard::from_bytes(value.value())?;
            identities.push(ident);
        }
        Ok(identities)
    }

    fn set_capabilities(&self, id: &IdentityId, caps: &[Capability]) -> Result<()> {
        let bytes = serde_json::to_vec(caps)?;
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(CAPABILITIES)?;
            table.insert(id.as_bytes().as_slice(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    fn get_capabilities(&self, id: &IdentityId) -> Result<Vec<Capability>> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(CAPABILITIES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        match table.get(id.as_bytes().as_slice())? {
            Some(data) => {
                let caps: Vec<Capability> = serde_json::from_slice(data.value())?;
                Ok(caps)
            }
            None => Ok(vec![]),
        }
    }
}

// ── EventStore ─────────────────────────────────────────────────────

impl EventStore for RedbBackend {
    fn append_event(&self, event: &[u8]) -> Result<u64> {
        let tx = self.db.begin_write()?;
        let seq = {
            let mut table = tx.open_table(EVENTS)?;
            // Find the next sequence number.
            let next_seq = match table.last()? {
                Some((key, _)) => key.value() + 1,
                None => 1,
            };
            table.insert(next_seq, event)?;
            next_seq
        };
        tx.commit()?;
        Ok(seq)
    }

    fn read_events(&self, from_seq: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(EVENTS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut events = Vec::new();
        for entry in table.range(from_seq..)? {
            let (key, value) = entry?;
            events.push((key.value(), value.value().to_vec()));
            if events.len() >= limit {
                break;
            }
        }
        Ok(events)
    }

    fn latest_event_seq(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(EVENTS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        match table.last()? {
            Some((key, _)) => Ok(key.value()),
            None => Ok(0),
        }
    }
}

// ── RevocationStore ────────────────────────────────────────────────

impl RevocationStore for RedbBackend {
    fn revoke_token(&self, token_hash: &[u8; 32]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(REVOKED_TOKENS)?;
            // Value is empty — we just need the key to exist.
            table.insert(token_hash.as_slice(), &[] as &[u8])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn is_token_revoked(&self, token_hash: &[u8; 32]) -> Result<bool> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(REVOKED_TOKENS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(token_hash.as_slice())?.is_some())
    }
}
