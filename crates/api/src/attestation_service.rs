use std::sync::Arc;
use tonic::{Request, Response, Status};
use gritgrub_core::*;
use gritgrub_core::attestation::Statement;
use gritgrub_store::Repository;
use crate::pb;
use crate::pb::attestation_service_server::AttestationService;
use crate::auth::require_scope;

pub struct AttestationServer {
    pub(crate) repo: Arc<Repository>,
}

impl AttestationServer {
    pub fn new(repo: Arc<Repository>) -> Self {
        Self { repo }
    }

    pub fn into_service(self) -> pb::attestation_service_server::AttestationServiceServer<Self> {
        pb::attestation_service_server::AttestationServiceServer::new(self)
    }
}

fn to_pb_object_id(id: &ObjectId) -> pb::ObjectId {
    pb::ObjectId { hash: id.as_bytes().to_vec() }
}

fn from_pb_object_id(pb_id: &pb::ObjectId) -> Result<ObjectId, Status> {
    let bytes: [u8; 32] = pb_id.hash.as_slice().try_into()
        .map_err(|_| Status::invalid_argument("ObjectId must be 32 bytes"))?;
    Ok(ObjectId::from_bytes(bytes))
}

fn to_status(e: anyhow::Error) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl AttestationService for AttestationServer {
    async fn create_attestation(
        &self,
        request: Request<pb::CreateAttestationRequest>,
    ) -> Result<Response<pb::CreateAttestationResponse>, Status> {
        require_scope(&request, |s| s.allows_attest(), "attest")?;
        let req = request.into_inner();

        let cs_id = from_pb_object_id(
            req.changeset_id.as_ref()
                .ok_or_else(|| Status::invalid_argument("missing changeset_id"))?
        )?;

        // Parse the provided statement JSON.
        let statement: Statement = serde_json::from_slice(&req.statement_json)
            .map_err(|e| Status::invalid_argument(format!("invalid statement JSON: {}", e)))?;

        let env_id = self.repo.attest(&cs_id, &statement).map_err(to_status)?;

        Ok(Response::new(pb::CreateAttestationResponse {
            envelope_id: Some(to_pb_object_id(&env_id)),
        }))
    }

    async fn list_attestations(
        &self,
        request: Request<pb::ListAttestationsRequest>,
    ) -> Result<Response<pb::ListAttestationsResponse>, Status> {
        let req = request.into_inner();
        let cs_id = from_pb_object_id(
            req.changeset_id.as_ref()
                .ok_or_else(|| Status::invalid_argument("missing changeset_id"))?
        )?;

        let envelopes = self.repo.get_attestations(&cs_id).map_err(to_status)?;

        let attestations: Vec<pb::AttestationEntry> = envelopes.into_iter().map(|(env_id, env)| {
            let predicate_type = serde_json::from_slice::<Statement>(&env.payload)
                .map(|s| s.predicate_type)
                .unwrap_or_default();

            pb::AttestationEntry {
                envelope_id: Some(to_pb_object_id(&env_id)),
                envelope: Some(pb::Envelope {
                    payload_type: env.payload_type,
                    payload: env.payload,
                    signatures: env.signatures.into_iter().map(|sig| {
                        pb::EnvelopeSignature {
                            keyid: Some(pb::IdentityId { uuid: sig.keyid.as_bytes().to_vec() }),
                            sig: sig.sig,
                        }
                    }).collect(),
                }),
                predicate_type,
            }
        }).collect();

        Ok(Response::new(pb::ListAttestationsResponse { attestations }))
    }

    async fn verify_attestations(
        &self,
        request: Request<pb::VerifyAttestationsRequest>,
    ) -> Result<Response<pb::VerifyAttestationsResponse>, Status> {
        let req = request.into_inner();
        let cs_id = from_pb_object_id(
            req.changeset_id.as_ref()
                .ok_or_else(|| Status::invalid_argument("missing changeset_id"))?
        )?;

        let results = self.repo.verify_attestations(&cs_id).map_err(to_status)?;

        let verifications: Vec<pb::SignatureVerification> = results.into_iter().map(|r| {
            pb::SignatureVerification {
                envelope_id: Some(to_pb_object_id(&r.envelope_id)),
                predicate_type: r.predicate_type,
                signer: Some(pb::IdentityId { uuid: r.signer.as_bytes().to_vec() }),
                verified: r.verified,
                key_found: r.key_found,
            }
        }).collect();

        Ok(Response::new(pb::VerifyAttestationsResponse { verifications }))
    }

    async fn check_slsa_level(
        &self,
        request: Request<pb::CheckSlsaLevelRequest>,
    ) -> Result<Response<pb::CheckSlsaLevelResponse>, Status> {
        let req = request.into_inner();
        let cs_id = from_pb_object_id(
            req.changeset_id.as_ref()
                .ok_or_else(|| Status::invalid_argument("missing changeset_id"))?
        )?;

        let required = match pb::SlsaLevel::try_from(req.required_level) {
            Ok(pb::SlsaLevel::L1) => SlsaLevel::L1,
            Ok(pb::SlsaLevel::L2) => SlsaLevel::L2,
            Ok(pb::SlsaLevel::L3) => SlsaLevel::L3,
            _ => SlsaLevel::L0,
        };

        let meets = self.repo.check_slsa_level(&cs_id, required).map_err(to_status)?;

        // Determine actual level by checking each.
        let actual = if self.repo.check_slsa_level(&cs_id, SlsaLevel::L3).map_err(to_status)? {
            pb::SlsaLevel::L3
        } else if self.repo.check_slsa_level(&cs_id, SlsaLevel::L2).map_err(to_status)? {
            pb::SlsaLevel::L2
        } else if self.repo.check_slsa_level(&cs_id, SlsaLevel::L1).map_err(to_status)? {
            pb::SlsaLevel::L1
        } else {
            pb::SlsaLevel::L0
        };

        Ok(Response::new(pb::CheckSlsaLevelResponse {
            meets_level: meets,
            actual_level: actual as i32,
        }))
    }
}
