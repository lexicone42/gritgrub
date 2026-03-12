//! First-class supply-chain attestation types.
//!
//! Built on real standards:
//! - DSSE (Dead Simple Signing Envelope) for the signed wrapper
//! - in-toto Statement v1 for the attestation structure
//! - SLSA Provenance v1 for build/change provenance
//! - CycloneDX for SBOM content
//!
//! Attestations reference changesets by ObjectId (in the subject field),
//! not the other way around — this preserves content-addressing since
//! attestations are created *after* the thing they attest to.

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};
use crate::id::ObjectId;
use crate::identity::IdentityId;

// ── DSSE Envelope ──────────────────────────────────────────────────

/// Dead Simple Signing Envelope — the outermost wrapper.
/// This is what gets stored as an object in the DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// MIME type of the payload (e.g., "application/vnd.in-toto+json").
    pub payload_type: String,
    /// The serialized Statement (JSON bytes).
    pub payload: Vec<u8>,
    /// One or more signatures over the payload.
    pub signatures: Vec<EnvelopeSignature>,
}

/// A signature within a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    /// The identity that produced this signature.
    pub keyid: IdentityId,
    /// Ed25519 signature bytes (64 bytes).
    pub sig: Vec<u8>,
}

// ── in-toto Statement ──────────────────────────────────────────────

/// in-toto Statement v1 — "these subjects have this predicate."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// Fixed: "https://in-toto.io/Statement/v1"
    #[serde(rename = "_type")]
    pub type_: String,
    /// What is being attested to (changeset, tree, blob, etc.).
    pub subject: Vec<Subject>,
    /// URI identifying the predicate schema.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The predicate content — schema depends on predicate_type.
    pub predicate: Predicate,
}

/// An attested subject — a named thing with a content digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// Human-readable name (e.g., "changeset", "tree", file path).
    pub name: String,
    /// Content digests — for gritgrub, always includes "blake3".
    pub digest: BTreeMap<String, String>,
}

impl Subject {
    /// Create a subject from a gritgrub ObjectId.
    pub fn from_object_id(name: &str, id: &ObjectId) -> Self {
        let mut digest = BTreeMap::new();
        digest.insert("blake3".into(), id.to_hex());
        Self { name: name.into(), digest }
    }
}

impl Statement {
    pub const TYPE_URI: &'static str = "https://in-toto.io/Statement/v1";

    pub fn new(subjects: Vec<Subject>, predicate_type: &str, predicate: Predicate) -> Self {
        Self {
            type_: Self::TYPE_URI.into(),
            subject: subjects,
            predicate_type: predicate_type.into(),
            predicate,
        }
    }
}

// ── Predicates ─────────────────────────────────────────────────────

/// The predicate payload — tagged by predicate_type URI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Predicate {
    /// SLSA Provenance v1.0.
    SlsaProvenance(SlsaProvenance),
    /// CycloneDX SBOM reference.
    Sbom(SbomAttestation),
    /// in-toto Link (step evidence in a supply chain layout).
    Link(LinkAttestation),
    /// Code review attestation (human or agent approved).
    Review(ReviewAttestation),
    /// Opaque/unknown predicate (forward compat).
    Other(BTreeMap<String, String>),
}

// ── SLSA Provenance v1.0 ──────────────────────────────────────────

pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// SLSA Provenance v1.0 predicate — who built what, from what, how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaProvenance {
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildDefinition {
    /// URI identifying the build process.
    /// e.g., "https://gritgrub.dev/ForgeCommit/v1" for a forge commit,
    /// "https://gritgrub.dev/AgentTask/v1" for an agent-driven change.
    #[serde(rename = "buildType")]
    pub build_type: String,
    /// Parameters from the caller (e.g., commit message, intent).
    #[serde(rename = "externalParameters")]
    pub external_parameters: BTreeMap<String, String>,
    /// Parameters decided by the build system.
    #[serde(rename = "internalParameters")]
    pub internal_parameters: BTreeMap<String, String>,
    /// Resolved input artifacts.
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDetails {
    /// Who/what performed the build.
    pub builder: BuilderId,
    /// Build metadata (timestamps, invocation ID, etc.).
    pub metadata: BuildMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderId {
    /// URI identifying the builder (e.g., "https://gritgrub.dev/forge-cli/v0.1").
    pub id: String,
    /// Builder version.
    pub version: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildMetadata {
    /// Unique invocation ID.
    #[serde(rename = "invocationId")]
    pub invocation_id: String,
    /// When the build started (RFC 3339).
    #[serde(rename = "startedOn")]
    pub started_on: String,
    /// When the build finished.
    #[serde(rename = "finishedOn")]
    pub finished_on: String,
}

/// A resolved input artifact — source code, dependency, tool, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    /// URI identifying the resource.
    pub uri: String,
    /// Content digests (algorithm → hex value).
    pub digest: BTreeMap<String, String>,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Media type.
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

// ── SBOM Attestation ───────────────────────────────────────────────

pub const CYCLONEDX_PREDICATE: &str = "https://cyclonedx.org/bom";

/// SBOM attestation — references a CycloneDX BOM stored as a blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomAttestation {
    /// Format of the SBOM (always CycloneDX for now).
    pub format: SbomFormat,
    /// Spec version (e.g., "1.6").
    pub spec_version: String,
    /// ObjectId of the blob containing the full CycloneDX JSON.
    pub bom_ref: ObjectId,
    /// Summary: top-level component count.
    pub component_count: u32,
    /// Summary: direct dependency count.
    pub dependency_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

// ── in-toto Link ───────────────────────────────────────────────────

pub const INTOTO_LINK_V0_3: &str = "https://in-toto.io/attestation/link/v0.3";

/// in-toto Link — evidence that a supply chain step was performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAttestation {
    /// Name of the step (e.g., "code", "test", "review", "deploy").
    pub name: String,
    /// Input artifacts before the step ran.
    pub materials: Vec<ResourceDescriptor>,
    /// Output artifacts after the step completed.
    pub products: Vec<ResourceDescriptor>,
    /// Step-specific metadata (command run, environment, etc.).
    pub byproducts: BTreeMap<String, String>,
    /// Environment variables/context.
    pub environment: BTreeMap<String, String>,
}

// ── Code Review ────────────────────────────────────────────────────

pub const REVIEW_PREDICATE_V1: &str = "https://gritgrub.dev/review/v1";

/// A code review attestation — a human or agent approved changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewAttestation {
    /// Disposition: approved, request-changes, comment-only.
    pub result: ReviewResult,
    /// What was reviewed (paths, symbols, specific ranges).
    pub scope: Vec<String>,
    /// Free-form review comments.
    pub body: String,
    /// Time spent reviewing (optional, seconds).
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewResult {
    Approved,
    RequestChanges,
    CommentOnly,
}

// ── Supply Chain Policy ────────────────────────────────────────────

/// An in-toto Layout — the expected supply chain for a branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layout {
    /// Layout schema version.
    pub version: u32,
    /// When this layout expires (unix micros, 0 = never).
    pub expires_at: i64,
    /// Ordered steps that must be completed.
    pub steps: Vec<Step>,
    /// Post-hoc inspections to run at verify time.
    pub inspections: Vec<Inspection>,
    /// Minimum SLSA level required.
    pub slsa_level: SlsaLevel,
    /// Whether SBOM attestation is required.
    pub require_sbom: bool,
}

/// A step in the supply chain layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Step name (must match Link attestation name).
    pub name: String,
    /// Identities allowed to perform this step.
    pub expected_signers: Vec<IdentityId>,
    /// Minimum number of signers required.
    pub threshold: u32,
    /// Constraints on input materials.
    pub expected_materials: Vec<ArtifactRule>,
    /// Constraints on output products.
    pub expected_products: Vec<ArtifactRule>,
}

/// A post-hoc inspection (e.g., "run cargo test on the final tree").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inspection {
    /// Inspection name.
    pub name: String,
    /// Shell command to run.
    pub run: String,
    /// Expected exit code (default 0).
    pub expected_exit_code: i32,
}

/// Artifact matching rule for in-toto layouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactRule {
    /// Artifact must match this glob pattern.
    Match(String),
    /// Artifact must NOT match this glob pattern.
    Disallow(String),
    /// Artifact must exist and be unchanged from previous step.
    Require(String),
    /// Any artifact matching this pattern is allowed.
    Allow(String),
}

/// SLSA build levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlsaLevel {
    /// No provenance required.
    L0,
    /// Provenance exists (any signer).
    L1,
    /// Provenance from a hosted build service (signer != author).
    L2,
    /// Hardened build platform (hermetic, signed by trusted builder).
    L3,
}

// ── Verification output ────────────────────────────────────────────

/// Result of verifying a single signature on an attestation envelope.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Which envelope was verified.
    pub envelope_id: ObjectId,
    /// The predicate type URI.
    pub predicate_type: String,
    /// Who signed it.
    pub signer: IdentityId,
    /// Whether the signature is cryptographically valid.
    pub verified: bool,
    /// Whether we found the signer's public key.
    pub key_found: bool,
}

impl Default for SlsaLevel {
    fn default() -> Self {
        SlsaLevel::L0
    }
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SlsaLevel::L0 => write!(f, "L0"),
            SlsaLevel::L1 => write!(f, "L1"),
            SlsaLevel::L2 => write!(f, "L2"),
            SlsaLevel::L3 => write!(f, "L3"),
        }
    }
}
