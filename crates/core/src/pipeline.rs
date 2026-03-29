//! Verification pipelines — CI/CD embedded in the version control system.
//!
//! # Why pipelines live in the VCS
//!
//! Traditional CI/CD is a separate system that watches the VCS for changes,
//! runs jobs, and reports back. This creates latency (webhook → queue → runner
//! → report) that's acceptable for humans but crippling for agents that commit
//! every few seconds.
//!
//! gritgrub pipelines eliminate the round-trip: the agent runs verification
//! locally, signs the result as an attestation, and the VCS trusts the signed
//! proof. CI becomes audit (verify attestation integrity), not gate (re-run
//! the tests).
//!
//! # Design
//!
//! A Pipeline is a sequence of Stages. Each stage is either a built-in
//! operation (cargo test, cargo clippy) or a shell command. Stages produce
//! structured StageResults, not terminal output. The pipeline result is
//! stored as an attestation envelope referencing the changeset.
//!
//! Ref policies can require specific pipeline attestations:
//! ```text
//! refs/heads/main:       requires [test, lint]
//! refs/heads/deploy/*:   requires [test, lint, build, security]
//! ```
//!
//! This means: you can't update main unless the changeset has signed
//! attestations proving tests and linting passed. No separate CI server,
//! no YAML, no webhooks.
//!
//! # Agent workflow
//!
//! ```text
//! agent commits → pipeline runs locally → attestation created → ref updated
//!                                            ↑
//!                                   signed by agent's Ed25519 key
//! ```
//!
//! Other agents and humans can verify the attestation's signature. If you
//! don't trust an agent's self-attestation, ref policies can require
//! attestation from a *different* identity (independent verification).

use serde::{Serialize, Deserialize};
use crate::identity::IdentityId;
use crate::id::ObjectId;

/// A verification pipeline — a named sequence of stages.
///
/// Stored as JSON in the repo config under `pipeline.<name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    /// Pipeline name (e.g., "default", "deploy", "security").
    pub name: String,
    /// Ordered stages to execute.
    pub stages: Vec<Stage>,
    /// When this pipeline should trigger.
    pub trigger: Trigger,
}

/// A single verification stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    /// Stage name (e.g., "test", "lint", "build").
    pub name: String,
    /// What to run.
    pub kind: StageKind,
    /// If true, pipeline fails if this stage fails.
    /// If false, failure is recorded but pipeline continues.
    pub required: bool,
    /// Timeout in seconds (0 = no timeout).
    pub timeout_secs: u64,
}

/// What a stage actually does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StageKind {
    /// Run `cargo test` (with optional features/flags).
    CargoTest {
        /// Additional arguments (e.g., ["--release", "-p", "my-crate"]).
        #[serde(default)]
        args: Vec<String>,
    },
    /// Run `cargo clippy`.
    CargoClippy {
        #[serde(default)]
        args: Vec<String>,
    },
    /// Run `cargo build`.
    CargoBuild {
        #[serde(default)]
        release: bool,
    },
    /// Run an arbitrary shell command.
    Command {
        cmd: String,
        #[serde(default)]
        args: Vec<String>,
        /// Working directory (relative to repo root). Empty = repo root.
        #[serde(default)]
        cwd: String,
    },
    /// Check that specific files haven't been modified (for frozen-path constraints).
    PathCheck {
        /// Glob patterns of paths that must not be modified.
        frozen_paths: Vec<String>,
    },
}

/// When a pipeline triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub enum Trigger {
    /// Run on every new changeset (local commit).
    OnCommit,
    /// Run when a specific ref pattern is updated.
    OnRefUpdate { pattern: String },
    /// Only run when explicitly invoked.
    #[default]
    Manual,
}

// ── Results ─────────────────────────────────────────────────────

/// The complete result of running a pipeline on a changeset.
///
/// This is what gets serialized into an attestation envelope.
/// It's structured data, not log output — agents can query it
/// programmatically without parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Which pipeline ran.
    pub pipeline: String,
    /// Which changeset was verified.
    pub changeset: ObjectId,
    /// Results of each stage.
    pub stages: Vec<StageResult>,
    /// Overall pass/fail.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Who ran the pipeline (the attesting agent).
    pub runner: IdentityId,
    /// Unix microseconds when the pipeline completed.
    pub completed_at: i64,
}

/// The result of a single pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    /// Stage name.
    pub name: String,
    /// Pass/fail.
    pub passed: bool,
    /// Exit code (for command-based stages).
    pub exit_code: Option<i32>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Structured output — not raw terminal output.
    /// For cargo test: number passed/failed/ignored.
    /// For clippy: number of warnings.
    /// For commands: first 1000 chars of stderr on failure.
    pub summary: String,
    /// Number of test cases passed (for test stages).
    #[serde(default)]
    pub tests_passed: u32,
    /// Number of test cases failed (for test stages).
    #[serde(default)]
    pub tests_failed: u32,
    /// Number of warnings (for lint stages).
    #[serde(default)]
    pub warnings: u32,
    /// Was this stage required?
    pub required: bool,
}

// ── Pipeline attestation predicate ──────────────────────────────

/// Predicate type URI for pipeline attestations.
/// Follows in-toto statement format.
pub const PIPELINE_PREDICATE: &str = "https://gritgrub.dev/attestation/pipeline/v1";

// ── Default pipelines ───────────────────────────────────────────

impl Pipeline {
    /// The default Rust pipeline: test + clippy + build.
    pub fn default_rust() -> Self {
        Self {
            name: "default".to_string(),
            stages: vec![
                Stage {
                    name: "test".to_string(),
                    kind: StageKind::CargoTest { args: vec![] },
                    required: true,
                    timeout_secs: 300,
                },
                Stage {
                    name: "lint".to_string(),
                    kind: StageKind::CargoClippy { args: vec![] },
                    required: true,
                    timeout_secs: 120,
                },
                Stage {
                    name: "build".to_string(),
                    kind: StageKind::CargoBuild { release: false },
                    required: false,
                    timeout_secs: 300,
                },
            ],
            trigger: Trigger::OnCommit,
        }
    }

    /// A minimal pipeline: just tests.
    pub fn test_only() -> Self {
        Self {
            name: "test".to_string(),
            stages: vec![
                Stage {
                    name: "test".to_string(),
                    kind: StageKind::CargoTest { args: vec![] },
                    required: true,
                    timeout_secs: 300,
                },
            ],
            trigger: Trigger::OnCommit,
        }
    }
}

// ── Ref policy integration ──────────────────────────────────────

/// Required attestations for a ref update.
/// Stored in ref policies alongside existing PolicyDenial checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredAttestations {
    /// Pipeline names that must have passing attestations.
    pub pipelines: Vec<String>,
    /// Minimum verification level (from exploration module).
    pub min_verification_level: Option<crate::exploration::VerificationLevel>,
    /// If true, attestation must be from a different identity than the committer.
    /// This prevents agents from self-attesting on protected branches.
    pub require_independent_attestor: bool,
}
