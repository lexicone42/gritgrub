use serde::{Serialize, Deserialize};
use crate::id::ObjectId;

/// A reference to a changeset — either direct (by ID) or symbolic (by name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ref {
    /// Points directly to a changeset ObjectId.
    Direct(ObjectId),
    /// Points to another ref by name (e.g., HEAD → "refs/heads/main").
    Symbolic(String),
}
