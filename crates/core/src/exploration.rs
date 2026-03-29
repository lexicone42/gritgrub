//! Exploration tree — structured parallel search over solution spaces.
//!
//! The exploration tree is the coordination layer for multi-agent development.
//! Instead of branches-with-commits (git's model for humans), agents work in
//! goal → approach → attempt trees where the structure itself encodes what
//! was tried, what worked, and what was abandoned.
//!
//! # Data model
//!
//! Explorations are a *protocol* over existing gritgrub primitives:
//! - Goals are Blob objects (serialized JSON) referenced by refs
//! - Approaches are branch-like refs within a goal's namespace
//! - Attempts are ordinary changesets on approach branches
//! - Claims are refs with TTLs for distributed agent coordination
//!
//! No new object types. The exploration layer is a higher-level API over
//! the same content-addressed store, refs, and changesets.
//!
//! # Ref namespace
//!
//! ```text
//! refs/explore/<goal-id>/meta                → Blob (serialized Goal)
//! refs/explore/<goal-id>/target              → Symbolic ref to merge target
//! refs/explore/<goal-id>/approaches/<name>   → changeset tip (like a branch)
//! refs/explore/<goal-id>/promoted            → winning changeset (after promote)
//! refs/explore/<goal-id>/claims/<agent-id>   → Blob (serialized Claim)
//! ```
//!
//! # Agent coordination protocol
//!
//! 1. Agent reads `refs/explore/<goal>/approaches/` to see what's been tried
//! 2. Agent creates a claim: CAS `refs/explore/<goal>/claims/<self>` (expected None)
//! 3. Agent creates/continues an approach branch, committing changesets
//! 4. Agent periodically refreshes claim TTL (heartbeat)
//! 5. When done, agent removes claim
//! 6. Supervisor or human calls `promote` to merge the best approach
//!
//! Stale claims (expired TTL) are ignored by other agents and can be
//! overwritten. This prevents deadlocks from crashed agents.

use serde::{Serialize, Deserialize};
use crate::identity::IdentityId;
use crate::id::ObjectId;

/// A Goal is the top-level unit of exploration — "what are we trying to achieve?"
///
/// Stored as a JSON-serialized Blob in the content-addressed store.
/// The ObjectId of the serialized Goal is used as the goal identifier
/// in the ref namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Goal {
    /// Human/agent-readable description of what needs to be accomplished.
    pub description: String,
    /// Branch to merge the winning approach into (e.g., "main").
    pub target_branch: String,
    /// Constraints that any valid solution must satisfy.
    /// These are evaluable by agents — not just prose.
    pub constraints: Vec<Constraint>,
    /// Who created this goal.
    pub created_by: IdentityId,
    /// Unix microseconds.
    pub created_at: i64,
    /// Maximum number of concurrent approaches (0 = unlimited).
    pub max_approaches: u32,
    /// Maximum time budget in seconds (0 = unlimited).
    pub time_budget_secs: u64,
}

/// A constraint that a solution must satisfy.
/// Constraints are typed so agents can evaluate them programmatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub kind: ConstraintKind,
    pub description: String,
    /// Optional: a command that returns exit 0 if the constraint is met.
    pub check_command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintKind {
    /// All tests must pass.
    TestsPass,
    /// No new clippy warnings.
    LintClean,
    /// Specific files must not be modified.
    PathFrozen,
    /// Performance: operation X must complete in < N ms.
    PerformanceBound,
    /// The change must be backward-compatible.
    BackwardCompatible,
    /// Custom constraint evaluated by check_command.
    Custom,
}

/// An agent's claim on an approach within a goal.
/// Stored as a JSON-serialized Blob.
///
/// Claims have TTLs to prevent deadlocks from crashed agents.
/// A working agent refreshes its claim periodically (heartbeat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    /// The agent holding this claim.
    pub agent: IdentityId,
    /// Which approach the agent is working on.
    pub approach: String,
    /// When this claim expires (Unix microseconds).
    /// Other agents may take over after expiry.
    pub expires_at: i64,
    /// What the agent intends to do (for observability).
    pub intent: String,
    /// Heartbeat counter — incremented on each refresh.
    pub heartbeat: u64,
}

/// Default claim TTL: 5 minutes. Agents must heartbeat faster than this.
pub const DEFAULT_CLAIM_TTL_SECS: u64 = 300;

/// Summary of a goal's exploration state.
/// Computed by reading refs, not stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalSummary {
    /// The goal metadata.
    pub goal: Goal,
    /// Content-addressed ID of the serialized goal.
    pub goal_id: ObjectId,
    /// All approaches and their current state.
    pub approaches: Vec<ApproachSummary>,
    /// Active agent claims.
    pub claims: Vec<Claim>,
    /// Which approach was promoted (if any).
    pub promoted: Option<String>,
}

/// Summary of a single approach's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproachSummary {
    /// Name of the approach (e.g., "token-bucket", "leaky-bucket").
    pub name: String,
    /// Latest changeset on this approach branch.
    pub tip: Option<ObjectId>,
    /// Number of changesets in this approach.
    pub changeset_count: usize,
    /// Latest commit message.
    pub latest_message: Option<String>,
    /// Who created this approach.
    pub created_by: Option<IdentityId>,
    /// Verification state of the tip changeset.
    pub verification: VerificationLevel,
}

/// Monotonic verification levels — each level implies all lower levels.
/// This is a lattice: the verification level of a changeset is the
/// meet (greatest lower bound) of its own attestations and its parents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// No verification data.
    #[default]
    Unknown,
    /// Type-checks / compiles.
    Builds,
    /// All tests pass.
    Tested,
    /// Has attestation envelopes.
    Attested,
    /// Human or senior-agent reviewed.
    Reviewed,
    /// SLSA L1: documented build process.
    SlsaL1,
    /// SLSA L2: hosted build, version controlled.
    SlsaL2,
}


impl std::fmt::Display for VerificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Builds => write!(f, "builds"),
            Self::Tested => write!(f, "tested"),
            Self::Attested => write!(f, "attested"),
            Self::Reviewed => write!(f, "reviewed"),
            Self::SlsaL1 => write!(f, "slsa-l1"),
            Self::SlsaL2 => write!(f, "slsa-l2"),
        }
    }
}

/// Result of promoting an approach.
#[derive(Debug)]
pub enum PromoteResult {
    /// Fast-forward: target branch moved to approach tip.
    FastForward(ObjectId),
    /// Merge: created a merge changeset.
    Merged(ObjectId),
    /// Conflict: cannot auto-merge into target.
    Conflict(Vec<String>),
}

/// Ref namespace helpers.
pub mod refs {
    use crate::id::ObjectId;

    /// Root prefix for all exploration refs.
    pub const EXPLORE_PREFIX: &str = "refs/explore/";

    /// Ref name for a goal's metadata blob.
    pub fn goal_meta(goal_id: &ObjectId) -> String {
        format!("{}{}//meta", EXPLORE_PREFIX, &goal_id.to_hex()[..16])
    }

    /// Ref name for a goal's merge target.
    pub fn goal_target(goal_id: &ObjectId) -> String {
        format!("{}{}//target", EXPLORE_PREFIX, &goal_id.to_hex()[..16])
    }

    /// Ref prefix for a goal's approaches.
    pub fn approaches_prefix(goal_id: &ObjectId) -> String {
        format!("{}{}//a/", EXPLORE_PREFIX, &goal_id.to_hex()[..16])
    }

    /// Ref name for a specific approach branch.
    pub fn approach_tip(goal_id: &ObjectId, approach_name: &str) -> String {
        format!("{}{}//a/{}", EXPLORE_PREFIX, &goal_id.to_hex()[..16], approach_name)
    }

    /// Ref name for the promoted winner.
    pub fn goal_promoted(goal_id: &ObjectId) -> String {
        format!("{}{}//promoted", EXPLORE_PREFIX, &goal_id.to_hex()[..16])
    }

    /// Ref prefix for a goal's agent claims.
    pub fn claims_prefix(goal_id: &ObjectId) -> String {
        format!("{}{}//claims/", EXPLORE_PREFIX, &goal_id.to_hex()[..16])
    }

    /// Ref name for a specific agent's claim.
    pub fn agent_claim(goal_id: &ObjectId, agent_id: &crate::identity::IdentityId) -> String {
        format!("{}{}//claims/{}", EXPLORE_PREFIX, &goal_id.to_hex()[..16], agent_id)
    }
}
