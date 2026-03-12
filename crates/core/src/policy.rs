//! Ref protection policies — rules governing who can update which refs and under what conditions.
//!
//! Policies are stored as JSON in the repository config. They're evaluated
//! at ref-update time, so enforcement is always consistent regardless of
//! whether the update comes from CLI, gRPC, or a future sync protocol.

use serde::{Serialize, Deserialize};
use crate::identity::IdentityId;
use crate::attestation::SlsaLevel;

/// Policy governing updates to refs matching a pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefPolicy {
    /// Glob pattern for ref names (e.g., "refs/heads/main", "refs/heads/release/*").
    pub pattern: String,
    /// If true, the target changeset must have a verified review attestation.
    pub require_review: bool,
    /// Minimum SLSA provenance level required (None = no requirement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_slsa: Option<SlsaLevel>,
    /// Identities allowed to update matching refs (empty = anyone with capability).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_writers: Vec<IdentityId>,
    /// If true, force-pushes (non-fast-forward updates) are forbidden.
    #[serde(default = "default_true")]
    pub forbid_force_push: bool,
}

fn default_true() -> bool { true }

impl RefPolicy {
    /// Check if this policy applies to a ref name.
    pub fn matches(&self, ref_name: &str) -> bool {
        glob_match(&self.pattern, ref_name)
    }

    /// Default policy for main — require review, forbid force push.
    pub fn protected_main() -> Self {
        Self {
            pattern: "refs/heads/main".to_string(),
            require_review: true,
            require_slsa: None,
            allowed_writers: vec![],
            forbid_force_push: true,
        }
    }
}

/// Public entry point for ref scope matching (used by token.rs).
pub fn glob_match_ref(pattern: &str, name: &str) -> bool {
    glob_match(pattern, name)
}

/// Simple glob matching: `*` matches any single path segment, `**` matches everything.
///
/// Includes a step limit to prevent exponential backtracking on adversarial
/// patterns with multiple `**` segments (e.g. `**/**/**/**` vs long paths).
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }

    // Split on '/' and match segment by segment.
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    let name_parts: Vec<&str> = name.split('/').collect();

    let mut steps = 0u32;
    glob_match_parts(&pat_parts, &name_parts, &mut steps)
}

/// Max recursive steps before we bail out (returns false).
/// Generous for real patterns but prevents adversarial explosion.
const GLOB_MAX_STEPS: u32 = 1024;

fn glob_match_parts(pat: &[&str], name: &[&str], steps: &mut u32) -> bool {
    *steps += 1;
    if *steps > GLOB_MAX_STEPS {
        return false;
    }

    match (pat.first(), name.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            // ** matches zero or more segments.
            if glob_match_parts(&pat[1..], name, steps) {
                return true;
            }
            if !name.is_empty() {
                return glob_match_parts(pat, &name[1..], steps);
            }
            false
        }
        (Some(p), Some(n)) => {
            if *p == "*" || p == n {
                glob_match_parts(&pat[1..], &name[1..], steps)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Reason a ref update was denied.
#[derive(Debug, Clone)]
pub enum PolicyDenial {
    /// Identity is not in the allowed_writers list.
    NotAllowedWriter { policy_pattern: String, identity: IdentityId },
    /// Missing required review attestation.
    MissingReview { policy_pattern: String },
    /// Insufficient SLSA level.
    InsufficientSlsa { policy_pattern: String, required: SlsaLevel, actual: SlsaLevel },
    /// Force push forbidden by policy.
    ForcePushForbidden { policy_pattern: String },
    /// Identity lacks the required capability scope.
    MissingCapability { required_scope: String },
}

impl std::fmt::Display for PolicyDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PolicyDenial::NotAllowedWriter { policy_pattern, identity } => {
                write!(f, "policy '{}': identity {} is not an allowed writer", policy_pattern, identity)
            }
            PolicyDenial::MissingReview { policy_pattern } => {
                write!(f, "policy '{}': changeset requires a verified review attestation", policy_pattern)
            }
            PolicyDenial::InsufficientSlsa { policy_pattern, required, actual } => {
                write!(f, "policy '{}': requires SLSA {:?} but changeset has {:?}", policy_pattern, required, actual)
            }
            PolicyDenial::ForcePushForbidden { policy_pattern } => {
                write!(f, "policy '{}': force push (non-fast-forward) is forbidden", policy_pattern)
            }
            PolicyDenial::MissingCapability { required_scope } => {
                write!(f, "missing capability for scope '{}'", required_scope)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(glob_match("refs/heads/main", "refs/heads/main"));
        assert!(!glob_match("refs/heads/main", "refs/heads/develop"));
    }

    #[test]
    fn star_matches_one_segment() {
        assert!(glob_match("refs/heads/*", "refs/heads/main"));
        assert!(glob_match("refs/heads/*", "refs/heads/feature"));
        assert!(!glob_match("refs/heads/*", "refs/heads/feature/foo"));
    }

    #[test]
    fn double_star_matches_deep() {
        assert!(glob_match("refs/heads/**", "refs/heads/main"));
        assert!(glob_match("refs/heads/**", "refs/heads/feature/foo"));
        assert!(glob_match("refs/heads/**", "refs/heads/feature/foo/bar"));
        assert!(!glob_match("refs/tags/**", "refs/heads/main"));
    }
}
