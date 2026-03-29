//! Structured repository events — emitted on every mutation.
//!
//! Events are the nervous system of the multi-agent coordination model.
//! When an agent commits, merges, creates a goal, or runs a pipeline,
//! an event is appended to the event log. Other agents and the dashboard
//! subscribe to the event stream for real-time awareness.

use serde::{Serialize, Deserialize};
use crate::identity::IdentityId;

/// A structured repository event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoEvent {
    /// What happened.
    pub kind: EventKind,
    /// Unix microseconds.
    pub timestamp: i64,
    /// Who caused it (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<IdentityId>,
}

/// The type of event that occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventKind {
    /// A new changeset was created.
    Commit {
        id: String,
        message: String,
        branch: Option<String>,
    },
    /// A ref was updated.
    RefUpdate {
        name: String,
        old_id: Option<String>,
        new_id: String,
    },
    /// A merge completed.
    Merge {
        into: String,
        from: String,
        result_id: String,
    },
    /// An exploration goal was created.
    GoalCreated {
        goal_id: String,
        description: String,
    },
    /// An exploration approach was created.
    ApproachCreated {
        goal_id: String,
        approach: String,
        agent: String,
    },
    /// An approach was promoted.
    Promoted {
        goal_id: String,
        approach: String,
        result_id: String,
    },
    /// A goal was abandoned.
    GoalAbandoned {
        goal_id: String,
    },
    /// An agent claimed an approach.
    AgentClaimed {
        goal_id: String,
        approach: String,
        agent: String,
    },
    /// An agent released its claim.
    AgentReleased {
        goal_id: String,
        agent: String,
    },
    /// A pipeline completed.
    PipelineCompleted {
        pipeline: String,
        changeset_id: String,
        passed: bool,
        duration_ms: u64,
    },
    /// An attestation was created.
    Attested {
        changeset_id: String,
        envelope_id: String,
    },
    /// An agent was provisioned.
    AgentProvisioned {
        identity: String,
        name: String,
    },
}

impl RepoEvent {
    pub fn now(kind: EventKind, actor: Option<IdentityId>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);
        Self { kind, timestamp, actor }
    }
}
