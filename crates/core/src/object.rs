use serde::{Serialize, Deserialize};
use crate::id::ObjectId;
use crate::tree::Tree;
use crate::changeset::Changeset;
use crate::attestation::Envelope;

// ── Tag format ─────────────────────────────────────────────────────
//
// Each tag is a unique, immutable identifier for a (type, format-version) pair.
// Once assigned, a tag's serialization layout NEVER changes. This is the
// forward-compatibility contract: old tags are always readable by new code.
//
// Encoding: high nibble = format version (0 = v1), low nibble = object type.
//   0x00 = Blob v1
//   0x01 = Tree v1
//   0x02 = Changeset v1
//   0x03 = Envelope v1
//
// When a type needs a v2 layout (e.g., adding fields to Changeset):
//   0x12 = Changeset v2   (high nibble 1 = v2, low nibble 2 = Changeset)
//
// Readers that don't understand a tag return ObjectError::UnknownTag.
// Writers always write the current version (highest known tag for that type).
//
// 4 bits × 4 bits = 16 types × 16 versions = plenty of headroom.

const TAG_BLOB_V1: u8 = 0x00;
const TAG_TREE_V1: u8 = 0x01;
const TAG_CHANGESET_V1: u8 = 0x02;
const TAG_ENVELOPE_V1: u8 = 0x03;
// Next type:    0x04
// Next version: 0x10 (Blob v2), 0x12 (Changeset v2), etc.

#[derive(Debug, Clone)]
pub enum Object {
    Blob(Blob),
    Tree(Tree),
    Changeset(Changeset),
    Envelope(Envelope),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blob {
    pub data: Vec<u8>,
}

impl Object {
    /// Compute the content-addressed BLAKE3 hash for this object.
    /// The hash covers the type tag + serialized body, so different
    /// object types with identical payloads produce different IDs.
    pub fn id(&self) -> ObjectId {
        let bytes = self.to_tagged_bytes();
        let hash = blake3::hash(&bytes);
        ObjectId::from_bytes(*hash.as_bytes())
    }

    /// Extract the object type tag (low nibble) without deserializing.
    pub fn type_tag(bytes: &[u8]) -> Option<u8> {
        bytes.first().map(|b| b & 0x0F)
    }

    /// Extract the format version (high nibble + 1) without deserializing.
    pub fn format_version(bytes: &[u8]) -> Option<u8> {
        bytes.first().map(|b| (b >> 4) + 1)
    }

    /// Serialize to type-tagged bytes (used for both storage and hashing).
    pub fn to_tagged_bytes(&self) -> Vec<u8> {
        let (tag, body) = match self {
            Object::Blob(blob) => {
                (TAG_BLOB_V1, postcard::to_allocvec(blob).expect("blob serialize"))
            }
            Object::Tree(tree) => {
                (TAG_TREE_V1, postcard::to_allocvec(tree).expect("tree serialize"))
            }
            Object::Changeset(cs) => {
                (TAG_CHANGESET_V1, postcard::to_allocvec(cs).expect("changeset serialize"))
            }
            Object::Envelope(env) => {
                (TAG_ENVELOPE_V1, postcard::to_allocvec(env).expect("envelope serialize"))
            }
        };
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(tag);
        out.extend_from_slice(&body);
        out
    }

    /// Deserialize from type-tagged bytes.
    pub fn from_tagged_bytes(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.is_empty() {
            return Err(ObjectError::EmptyData);
        }
        let (tag, body) = (bytes[0], &bytes[1..]);
        match tag {
            TAG_BLOB_V1 => Ok(Object::Blob(postcard::from_bytes(body)?)),
            TAG_TREE_V1 => Ok(Object::Tree(postcard::from_bytes(body)?)),
            TAG_CHANGESET_V1 => Ok(Object::Changeset(postcard::from_bytes(body)?)),
            TAG_ENVELOPE_V1 => Ok(Object::Envelope(postcard::from_bytes(body)?)),
            _ => Err(ObjectError::UnknownTag(tag)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    #[error("empty object data")]
    EmptyData,
    #[error("unknown object type tag: 0x{0:02x}")]
    UnknownTag(u8),
    #[error("deserialization failed: {0}")]
    Deserialize(#[from] postcard::Error),
}
