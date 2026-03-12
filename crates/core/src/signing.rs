//! Ed25519 signing for DSSE envelopes.
//!
//! Each Identity gets an Ed25519 keypair. The public key is stored
//! in the object store (via refs/keys/<identity-uuid>). The secret key
//! lives in .forge/keys/<identity-uuid>.secret — never in the store.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use crate::identity::IdentityId;
use crate::attestation::{Envelope, EnvelopeSignature, Statement};

/// A keypair bound to an identity.
pub struct IdentityKeyPair {
    pub identity: IdentityId,
    pub signing_key: SigningKey,
}

impl IdentityKeyPair {
    /// Generate a new random keypair.
    pub fn generate(identity: IdentityId) -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Self { identity, signing_key }
    }

    /// Restore from saved secret key bytes.
    pub fn from_secret_bytes(identity: IdentityId, bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { identity, signing_key }
    }

    /// The 32-byte secret key (for saving to .forge/keys/).
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// The 32-byte public verifying key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a DSSE envelope payload using the PAE (Pre-Authentication Encoding).
    ///
    /// PAE format: "DSSEv1" + SP + len(payload_type) + SP + payload_type + SP + len(payload) + SP + payload
    /// This prevents confusion attacks between payload_type and payload.
    pub fn sign_envelope(&self, statement: &Statement, payload_type: &str) -> Envelope {
        let payload = serde_json::to_vec(statement).expect("statement serialization");
        let pae = dsse_pae(payload_type, &payload);
        let signature = self.signing_key.sign(&pae);

        Envelope {
            payload_type: payload_type.into(),
            payload,
            signatures: vec![EnvelopeSignature {
                keyid: self.identity,
                sig: signature.to_bytes().to_vec(),
            }],
        }
    }

    /// Add a co-signature to an existing envelope.
    pub fn cosign_envelope(&self, envelope: &mut Envelope) {
        let pae = dsse_pae(&envelope.payload_type, &envelope.payload);
        let signature = self.signing_key.sign(&pae);

        envelope.signatures.push(EnvelopeSignature {
            keyid: self.identity,
            sig: signature.to_bytes().to_vec(),
        });
    }
}

/// Verify one signature in an envelope against a known public key.
pub fn verify_envelope_signature(
    envelope: &Envelope,
    sig_index: usize,
    public_key_bytes: &[u8; 32],
) -> Result<bool, SigningError> {
    let sig_entry = envelope.signatures.get(sig_index)
        .ok_or(SigningError::SignatureIndexOutOfBounds)?;

    let sig_bytes: [u8; 64] = sig_entry.sig.as_slice().try_into()
        .map_err(|_| SigningError::InvalidSignatureLength)?;

    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| SigningError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let pae = dsse_pae(&envelope.payload_type, &envelope.payload);
    Ok(verifying_key.verify(&pae, &signature).is_ok())
}

/// DSSE Pre-Authentication Encoding.
/// Prevents type-confusion attacks by binding payload_type and payload together.
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    // "DSSEv1" SP len(type) SP type SP len(body) SP body
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("signature index out of bounds")]
    SignatureIndexOutOfBounds,
    #[error("invalid signature length (expected 64 bytes)")]
    InvalidSignatureLength,
    #[error("invalid public key")]
    InvalidPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        use crate::attestation::{Subject, Predicate};
        use crate::id::ObjectId;

        let identity = IdentityId::new();
        let kp = IdentityKeyPair::generate(identity);

        let subject = Subject::from_object_id("test-changeset", &ObjectId::ZERO);
        let statement = Statement::new(
            vec![subject],
            "https://gritgrub.dev/test/v1",
            Predicate::Other(Default::default()),
        );

        let envelope = kp.sign_envelope(&statement, "application/vnd.in-toto+json");

        assert_eq!(envelope.signatures.len(), 1);
        assert_eq!(envelope.signatures[0].keyid, identity);

        let valid = verify_envelope_signature(&envelope, 0, &kp.public_bytes()).unwrap();
        assert!(valid);
    }

    #[test]
    fn wrong_key_rejects() {
        use crate::attestation::{Subject, Predicate};
        use crate::id::ObjectId;

        let id1 = IdentityId::new();
        let id2 = IdentityId::new();
        let kp1 = IdentityKeyPair::generate(id1);
        let kp2 = IdentityKeyPair::generate(id2);

        let statement = Statement::new(
            vec![Subject::from_object_id("x", &ObjectId::ZERO)],
            "https://gritgrub.dev/test/v1",
            Predicate::Other(Default::default()),
        );

        let envelope = kp1.sign_envelope(&statement, "application/vnd.in-toto+json");

        // Verify with wrong key should fail.
        let valid = verify_envelope_signature(&envelope, 0, &kp2.public_bytes()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn cosign_adds_signature() {
        use crate::attestation::{Subject, Predicate};
        use crate::id::ObjectId;

        let id1 = IdentityId::new();
        let id2 = IdentityId::new();
        let kp1 = IdentityKeyPair::generate(id1);
        let kp2 = IdentityKeyPair::generate(id2);

        let statement = Statement::new(
            vec![Subject::from_object_id("x", &ObjectId::ZERO)],
            "https://gritgrub.dev/test/v1",
            Predicate::Other(Default::default()),
        );

        let mut envelope = kp1.sign_envelope(&statement, "application/vnd.in-toto+json");
        kp2.cosign_envelope(&mut envelope);

        assert_eq!(envelope.signatures.len(), 2);
        assert!(verify_envelope_signature(&envelope, 0, &kp1.public_bytes()).unwrap());
        assert!(verify_envelope_signature(&envelope, 1, &kp2.public_bytes()).unwrap());
    }

    #[test]
    fn keypair_save_restore() {
        let id = IdentityId::new();
        let kp = IdentityKeyPair::generate(id);
        let secret = *kp.secret_bytes();
        let public = kp.public_bytes();

        let restored = IdentityKeyPair::from_secret_bytes(id, &secret);
        assert_eq!(restored.public_bytes(), public);
    }
}
