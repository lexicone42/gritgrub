use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};
use crate::id::ObjectId;
use crate::identity::IdentityId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Changeset {
    /// Parent changeset IDs — zero parents means root changeset.
    pub parents: Vec<ObjectId>,
    /// Root tree of the repository state at this changeset.
    pub tree: ObjectId,
    /// Identity of the author (human or agent).
    pub author: IdentityId,
    /// Unix microseconds.
    pub timestamp: i64,
    /// Human-readable summary.
    pub message: String,
    /// Structured semantic intent — the "why" beyond the message.
    pub intent: Option<Intent>,
    /// Extensible key-value metadata.
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub kind: IntentKind,
    /// Semantic scope: not just what files changed, but what's *affected*.
    pub affected_paths: Vec<String>,
    /// Why this change was made.
    pub rationale: String,
    /// Optional reference to an agent scratchpad/trace blob.
    pub context_ref: Option<ObjectId>,
    /// What should be verified about this change.
    pub verifications: Vec<Verification>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentKind {
    Feature,
    Bugfix,
    Refactor,
    AgentTask,
    Exploration,
    Dependency,
    Documentation,
}

impl std::fmt::Display for IntentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IntentKind::Feature => write!(f, "feature"),
            IntentKind::Bugfix => write!(f, "bugfix"),
            IntentKind::Refactor => write!(f, "refactor"),
            IntentKind::AgentTask => write!(f, "agent-task"),
            IntentKind::Exploration => write!(f, "exploration"),
            IntentKind::Dependency => write!(f, "dependency"),
            IntentKind::Documentation => write!(f, "docs"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub kind: VerificationKind,
    pub status: VerificationStatus,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationKind {
    TestPass,
    LintClean,
    TypeCheck,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Pending,
    Passed,
    Failed,
    Skipped,
}
