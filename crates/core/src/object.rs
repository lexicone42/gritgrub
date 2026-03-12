use serde::{Serialize, Deserialize};
use crate::id::ObjectId;
use crate::tree::Tree;
use crate::changeset::Changeset;
use crate::attestation::Envelope;

const TAG_BLOB: u8 = 0x00;
const TAG_TREE: u8 = 0x01;
const TAG_CHANGESET: u8 = 0x02;
const TAG_ENVELOPE: u8 = 0x03;

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

    /// Serialize to type-tagged bytes (used for both storage and hashing).
    pub fn to_tagged_bytes(&self) -> Vec<u8> {
        let (tag, body) = match self {
            Object::Blob(blob) => {
                (TAG_BLOB, postcard::to_allocvec(blob).expect("blob serialize"))
            }
            Object::Tree(tree) => {
                (TAG_TREE, postcard::to_allocvec(tree).expect("tree serialize"))
            }
            Object::Changeset(cs) => {
                (TAG_CHANGESET, postcard::to_allocvec(cs).expect("changeset serialize"))
            }
            Object::Envelope(env) => {
                (TAG_ENVELOPE, postcard::to_allocvec(env).expect("envelope serialize"))
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
            TAG_BLOB => Ok(Object::Blob(postcard::from_bytes(body)?)),
            TAG_TREE => Ok(Object::Tree(postcard::from_bytes(body)?)),
            TAG_CHANGESET => Ok(Object::Changeset(postcard::from_bytes(body)?)),
            TAG_ENVELOPE => Ok(Object::Envelope(postcard::from_bytes(body)?)),
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
