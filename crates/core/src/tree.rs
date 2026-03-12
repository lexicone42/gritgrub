use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};
use crate::id::ObjectId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    pub entries: BTreeMap<String, TreeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub id: ObjectId,
    pub kind: EntryKind,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}
