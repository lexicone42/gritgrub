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

/// Convert a hex prefix to a byte range for B-tree range queries on [u8; 32] keys.
/// Returns (start_key, end_key) where start is the minimum matching key and
/// end is the minimum non-matching key.
///
/// "ab" → ([0xAB, 0, 0, ...], [0xAC, 0, 0, ...])
/// "abc" → ([0xAB, 0xC0, 0, ...], [0xAB, 0xD0, 0, ...])
fn hex_prefix_to_byte_range(hex: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    if hex.is_empty() || hex.len() > 64 {
        return None;
    }
    // Pad to even length for byte conversion.
    let even_hex = if hex.len().is_multiple_of(2) {
        hex.to_string()
    } else {
        format!("{}0", hex)
    };

    // Parse complete bytes.
    let mut start_bytes = Vec::with_capacity(32);
    for i in (0..even_hex.len()).step_by(2) {
        match u8::from_str_radix(&even_hex[i..i + 2], 16) {
            Ok(b) => start_bytes.push(b),
            Err(_) => return None,
        }
    }

    // Pad start to 32 bytes with 0x00.
    while start_bytes.len() < 32 {
        start_bytes.push(0x00);
    }

    // Compute end: increment the last significant byte.
    let mut end_bytes = start_bytes.clone();
    let significant_len = (even_hex.len() / 2).min(32);
    // For odd-length hex prefixes, the last byte was padded with 0 in low nibble.
    // "abc" → 0xAB, 0xC0 — end should be 0xAB, 0xD0 (increment the half-byte).
    if hex.len() % 2 == 1 {
        // Odd prefix: increment the high nibble of the last parsed byte.
        if significant_len > 0 {
            let idx = significant_len - 1;
            let high_nibble = (end_bytes[idx] >> 4) + 1;
            if high_nibble > 0xF {
                // Carry — increment previous byte.
                end_bytes[idx] = 0x00;
                if idx > 0 {
                    end_bytes[idx - 1] = end_bytes[idx - 1].wrapping_add(1);
                }
            } else {
                end_bytes[idx] = high_nibble << 4;
            }
        }
    } else {
        // Even prefix: increment the last full byte.
        if significant_len > 0 {
            let idx = significant_len - 1;
            end_bytes[idx] = end_bytes[idx].wrapping_add(1);
            if end_bytes[idx] == 0 && idx > 0 {
                // Carry.
                end_bytes[idx - 1] = end_bytes[idx - 1].wrapping_add(1);
            }
        }
    }

    Some((start_bytes, end_bytes))
}

/// Compute the lexicographic successor of a string prefix for range queries.
/// "refs/heads/" → "refs/heads0" (/ is 0x2F, 0 is 0x30).
/// This lets us do `table.range(prefix..successor)` for O(log n + k) scans.
fn prefix_successor(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    // Increment the last byte. If it overflows (0xFF), pop and try the previous byte.
    while let Some(last) = bytes.pop() {
        if last < 0xFF {
            bytes.push(last + 1);
            return String::from_utf8_lossy(&bytes).to_string();
        }
        // Last byte was 0xFF, carry to previous byte.
    }
    // All bytes were 0xFF — no successor exists (return something > any string).
    // In practice this never happens for ref names.
    "\u{FFFF}".to_string()
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

        // Convert hex prefix to byte range for B-tree range scan.
        // "ab" → scan from [0xAB, 0x00, ...] to [0xAC, 0x00, ...]
        // "abc" → scan from [0xAB, 0xC0, ...] to [0xAB, 0xD0, ...]
        if let Some((start, end)) = hex_prefix_to_byte_range(hex_prefix) {
            for entry in table.range(start.as_slice()..end.as_slice())? {
                let (key, value) = entry?;
                let key_bytes: [u8; 32] = key.value().try_into()
                    .map_err(|_| anyhow::anyhow!("invalid object key length"))?;
                let id = ObjectId::from_bytes(key_bytes);
                // Double-check full hex prefix (byte range is an over-approximation
                // for odd-length prefixes).
                if id.to_hex().starts_with(hex_prefix) {
                    let obj = Object::from_tagged_bytes(value.value())?;
                    results.push((id, obj));
                    if results.len() > 1 {
                        break;
                    }
                }
            }
        } else {
            // Invalid hex prefix — fall back to full scan.
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
        }

        Ok(results)
    }

    fn list_all_object_ids(&self) -> Result<Vec<ObjectId>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(OBJECTS)?;
        let mut ids = Vec::new();
        for entry in table.iter()? {
            let (key, _) = entry?;
            let key_bytes: [u8; 32] = key.value().try_into()
                .map_err(|_| anyhow::anyhow!("invalid object key length"))?;
            ids.push(ObjectId::from_bytes(key_bytes));
        }
        Ok(ids)
    }

    fn delete_object(&self, id: &ObjectId) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = {
            let mut table = tx.open_table(OBJECTS)?;
            table.remove(id.as_bytes().as_slice())?.is_some()
        };
        tx.commit()?;
        Ok(existed)
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

        if prefix.is_empty() {
            // No prefix = return all refs.
            for entry in table.iter()? {
                let (key, value) = entry?;
                let reference: Ref = postcard::from_bytes(value.value())?;
                refs.push((key.value().to_string(), reference));
            }
        } else {
            // Use B-tree range scan: prefix..prefix_successor.
            // This is O(log n + k) instead of O(n) full scan.
            let end = prefix_successor(prefix);
            for entry in table.range(prefix..end.as_str())? {
                let (key, value) = entry?;
                let reference: Ref = postcard::from_bytes(value.value())?;
                refs.push((key.value().to_string(), reference));
            }
        }

        Ok(refs)
    }

    fn cas_ref(&self, name: &str, expected: Option<&Ref>, new: &Ref) -> Result<bool> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(REFS)?;
            let current = match table.get(name)? {
                Some(data) => Some(postcard::from_bytes::<Ref>(data.value())?),
                None => None,
            };

            // Check expectation.
            match (&current, expected) {
                (None, None) => {} // Expected empty, is empty — proceed.
                (Some(cur), Some(exp)) if cur == exp => {} // Matches — proceed.
                _ => return Ok(false), // Mismatch — CAS failed.
            }

            let bytes = postcard::to_allocvec(new)?;
            table.insert(name, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(true)
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

    fn delete_config(&self, key: &str) -> Result<bool> {
        let tx = self.db.begin_write()?;
        let existed = {
            let mut table = tx.open_table(CONFIG)?;
            table.remove(key)?.is_some()
        };
        tx.commit()?;
        Ok(existed)
    }

    fn list_config_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut results = Vec::new();
        if prefix.is_empty() {
            for entry in table.iter()? {
                let (key, value) = entry?;
                results.push((key.value().to_string(), value.value().to_string()));
            }
        } else {
            let end = prefix_successor(prefix);
            for entry in table.range(prefix..end.as_str())? {
                let (key, value) = entry?;
                let k = key.value();
                let stripped = k.strip_prefix(prefix).unwrap_or(k);
                results.push((stripped.to_string(), value.value().to_string()));
            }
        }
        Ok(results)
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

// ── Atomic compound operations ────────────────────────────────────
//
// These methods perform read-modify-write in a single write transaction,
// preventing lost-update races that occur when read and write use
// separate transactions.

impl RedbBackend {
    /// Atomically read + extend + write capabilities in one write transaction.
    /// Prevents the race where two concurrent grants read the same state and
    /// one overwrites the other's additions.
    pub fn atomic_grant_capabilities(&self, id: &IdentityId, new_caps: &[Capability]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(CAPABILITIES)?;
            let mut caps: Vec<Capability> = match table.get(id.as_bytes().as_slice())? {
                Some(data) => serde_json::from_slice(data.value())?,
                None => vec![],
            };
            caps.extend_from_slice(new_caps);
            let bytes = serde_json::to_vec(&caps)?;
            table.insert(id.as_bytes().as_slice(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_successor_basic() {
        assert_eq!(prefix_successor("refs/heads/"), "refs/heads0");
        assert_eq!(prefix_successor("a"), "b");
        assert_eq!(prefix_successor("abc"), "abd");
    }

    #[test]
    fn prefix_successor_slash() {
        // '/' is 0x2F, successor byte is 0x30 = '0'
        assert_eq!(prefix_successor("refs/"), "refs0");
    }

    #[test]
    fn prefix_successor_empty() {
        // Empty prefix → no bytes to increment, returns fallback.
        let result = prefix_successor("");
        assert_eq!(result, "\u{FFFF}");
    }

    #[test]
    fn hex_prefix_to_byte_range_even() {
        let (start, end) = hex_prefix_to_byte_range("ab").unwrap();
        assert_eq!(start[0], 0xAB);
        assert_eq!(start[1], 0x00);
        assert_eq!(end[0], 0xAC);
        assert_eq!(end[1], 0x00);
    }

    #[test]
    fn hex_prefix_to_byte_range_odd() {
        let (start, end) = hex_prefix_to_byte_range("abc").unwrap();
        assert_eq!(start[0], 0xAB);
        assert_eq!(start[1], 0xC0);
        assert_eq!(end[0], 0xAB);
        assert_eq!(end[1], 0xD0);
    }

    #[test]
    fn hex_prefix_to_byte_range_full() {
        let hex = "ab".repeat(32);
        let (start, end) = hex_prefix_to_byte_range(&hex).unwrap();
        assert!(start.iter().all(|&b| b == 0xAB));
        assert_eq!(end[31], 0xAC);
        assert!(end[..31].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn hex_prefix_to_byte_range_invalid() {
        assert!(hex_prefix_to_byte_range("xyz").is_none());
        assert!(hex_prefix_to_byte_range("").is_none());
    }

    #[test]
    fn hex_prefix_to_byte_range_single_char() {
        let (start, end) = hex_prefix_to_byte_range("a").unwrap();
        assert_eq!(start[0], 0xA0);
        assert_eq!(end[0], 0xB0);
    }
}
