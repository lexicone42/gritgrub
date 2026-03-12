use std::fmt;
use serde::{Serialize, Deserialize};

/// Unique identity identifier. Not content-addressed — identities are mutable entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(pub uuid::Uuid);

impl IdentityId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for IdentityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A first-class identity — human or agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: IdentityId,
    pub kind: IdentityKind,
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityKind {
    Human,
    Agent { runtime: String },
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IdentityKind::Human => write!(f, "human"),
            IdentityKind::Agent { runtime } => write!(f, "agent:{}", runtime),
        }
    }
}

/// A scoped permission grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub scope: CapabilityScope,
    pub permissions: Permissions,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityScope {
    /// Full access to everything.
    Global,
    /// Scoped to a single repository.
    Repository(String),
    /// Scoped to file paths matching a glob pattern.
    Path { repo: String, pattern: String },
    /// Scoped to branches matching a glob pattern.
    Branch { repo: String, pattern: String },
}

/// Bitflag permissions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Permissions(pub u32);

impl Permissions {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const CREATE: u32 = 4;
    pub const DELETE: u32 = 8;
    pub const ADMIN: u32 = 16;

    pub fn all() -> Self {
        Self(Self::READ | Self::WRITE | Self::CREATE | Self::DELETE | Self::ADMIN)
    }

    pub fn read_write() -> Self {
        Self(Self::READ | Self::WRITE)
    }

    pub fn read_only() -> Self {
        Self(Self::READ)
    }

    pub fn can_read(&self) -> bool { self.0 & Self::READ != 0 }
    pub fn can_write(&self) -> bool { self.0 & Self::WRITE != 0 }
    pub fn can_create(&self) -> bool { self.0 & Self::CREATE != 0 }
    pub fn can_delete(&self) -> bool { self.0 & Self::DELETE != 0 }
    pub fn is_admin(&self) -> bool { self.0 & Self::ADMIN != 0 }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut perms = Vec::new();
        if self.can_read() { perms.push("r"); }
        if self.can_write() { perms.push("w"); }
        if self.can_create() { perms.push("c"); }
        if self.can_delete() { perms.push("d"); }
        if self.is_admin() { perms.push("A"); }
        write!(f, "{}", perms.join(""))
    }
}
