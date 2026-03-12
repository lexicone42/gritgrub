use std::fmt;
use serde::{Serialize, Deserialize, Serializer, Deserializer};

/// A 32-byte BLAKE3 content hash identifying an object.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    pub const ZERO: ObjectId = ObjectId([0u8; 32]);

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full 64-character hex representation.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            use fmt::Write;
            write!(s, "{:02x}", byte).unwrap();
        }
        s
    }

    /// Parse from a 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self, IdError> {
        if s.len() != 64 {
            return Err(IdError::InvalidHexLength(s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0]).ok_or(IdError::InvalidHexChar(chunk[0] as char))?;
            let lo = hex_val(chunk[1]).ok_or(IdError::InvalidHexChar(chunk[1] as char))?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Display shows the first 16 hex chars (8 bytes) — enough to identify without clutter.
impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ObjectId({})", self)
    }
}

/// Serialize as raw bytes in binary formats, hex in human-readable.
impl Serialize for ObjectId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_hex().serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ObjectId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            ObjectId::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; 32]>::deserialize(deserializer)?;
            Ok(ObjectId(bytes))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("invalid hex length: expected 64, got {0}")]
    InvalidHexLength(usize),
    #[error("invalid hex character: '{0}'")]
    InvalidHexChar(char),
}
