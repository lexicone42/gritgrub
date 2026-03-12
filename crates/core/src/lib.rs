mod id;
mod object;
mod tree;
mod changeset;
mod identity;
mod refs;
pub mod attestation;
pub mod signing;

pub use id::{ObjectId, IdError};
pub use object::{Object, Blob, ObjectError};
pub use tree::{Tree, TreeEntry, EntryKind};
pub use changeset::{Changeset, Intent, IntentKind, Verification, VerificationKind, VerificationStatus};
pub use identity::{IdentityId, IdentityKind, Identity, Capability, CapabilityScope, Permissions};
pub use refs::Ref;
pub use signing::{IdentityKeyPair, verify_envelope_signature, SigningError};
pub use attestation::{
    Envelope, EnvelopeSignature, Statement, Subject, Predicate,
    SlsaProvenance, BuildDefinition, RunDetails, BuilderId, BuildMetadata, ResourceDescriptor,
    SbomAttestation, SbomFormat, LinkAttestation, ReviewAttestation, ReviewResult,
    Layout, Step, Inspection, ArtifactRule, SlsaLevel, VerificationResult,
};
