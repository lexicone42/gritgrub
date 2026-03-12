use std::path::Path;
use anyhow::Result;
use redb::{Database, TableDefinition, ReadableTable};
use gritgrub_core::{ObjectId, Object, Ref};
use crate::backend::{ObjectStore, RefStore};

const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const REFS: TableDefinition<&str, &[u8]> = TableDefinition::new("refs");
const CONFIG: TableDefinition<&str, &str> = TableDefinition::new("config");

pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    pub fn create(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        // Initialize all tables.
        let tx = db.begin_write()?;
        {
            tx.open_table(OBJECTS)?;
            tx.open_table(REFS)?;
            tx.open_table(CONFIG)?;
        }
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::open(path)?;
        Ok(Self { db })
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
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

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(CONFIG)?;
            table.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }
}

impl RedbBackend {
    /// Find objects whose hex ID starts with `hex_prefix`.
    pub fn find_objects_by_prefix(&self, hex_prefix: &str) -> Result<Vec<(ObjectId, Object)>> {
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
                    break; // ambiguous prefix, stop early
                }
            }
        }

        Ok(results)
    }
}

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
}

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
