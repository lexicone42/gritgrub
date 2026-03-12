use std::collections::BTreeMap;
use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_core::attestation::*;
use gritgrub_store::Repository;

/// Create a SLSA provenance attestation for a changeset.
pub fn provenance(changeset_prefix: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let (cs_id, cs) = resolve_changeset(&repo, changeset_prefix)?;

    // Build SLSA provenance.
    let now = chrono::Utc::now().to_rfc3339();
    let identity = repo.local_identity()?;

    let provenance = SlsaProvenance {
        build_definition: BuildDefinition {
            build_type: "https://gritgrub.dev/ForgeCommit/v1".into(),
            external_parameters: BTreeMap::from([
                ("message".into(), cs.message.clone()),
                ("intent".into(), cs.intent.as_ref()
                    .map(|i| i.kind.to_string())
                    .unwrap_or_default()),
            ]),
            internal_parameters: BTreeMap::from([
                ("tree".into(), cs.tree.to_hex()),
            ]),
            resolved_dependencies: cs.parents.iter().map(|p| {
                ResourceDescriptor {
                    uri: format!("forge://changeset/{}", p.to_hex()),
                    digest: {
                        let mut d = BTreeMap::new();
                        d.insert("blake3".into(), p.to_hex());
                        d
                    },
                    name: Some("parent-changeset".into()),
                    media_type: None,
                }
            }).collect(),
        },
        run_details: RunDetails {
            builder: BuilderId {
                id: "https://gritgrub.dev/forge-cli/v0.1".into(),
                version: BTreeMap::from([
                    ("forge".into(), env!("CARGO_PKG_VERSION").into()),
                ]),
            },
            metadata: BuildMetadata {
                invocation_id: format!("{}-{}", identity, cs_id),
                started_on: now.clone(),
                finished_on: now,
            },
        },
    };

    let subject = Subject::from_object_id("changeset", &cs_id);
    let statement = Statement::new(
        vec![subject],
        SLSA_PROVENANCE_V1,
        Predicate::SlsaProvenance(provenance),
    );

    let env_id = repo.attest(&cs_id, &statement)?;
    println!("Created SLSA provenance attestation: {}", env_id);
    println!("  subject: changeset {}", cs_id);
    println!("  signer:  {}", identity);

    Ok(())
}

/// Create a code review attestation.
pub fn review(changeset_prefix: Option<&str>, result: &str, body: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let (cs_id, _cs) = resolve_changeset(&repo, changeset_prefix)?;

    let review_result = match result {
        "approved" | "approve" => ReviewResult::Approved,
        "request-changes" | "changes" => ReviewResult::RequestChanges,
        "comment" => ReviewResult::CommentOnly,
        _ => bail!("invalid review result: {} (use: approved, request-changes, comment)", result),
    };

    let review = ReviewAttestation {
        result: review_result,
        scope: vec![],
        body: body.into(),
        duration_secs: None,
    };

    let subject = Subject::from_object_id("changeset", &cs_id);
    let statement = Statement::new(
        vec![subject],
        REVIEW_PREDICATE_V1,
        Predicate::Review(review),
    );

    let env_id = repo.attest(&cs_id, &statement)?;
    let identity = repo.local_identity()?;
    println!("Created review attestation: {}", env_id);
    println!("  subject:  changeset {}", cs_id);
    println!("  reviewer: {}", identity);
    println!("  result:   {}", result);

    Ok(())
}

/// List attestations for a changeset.
pub fn list(changeset_prefix: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let (cs_id, _cs) = resolve_changeset(&repo, changeset_prefix)?;

    let envelopes = repo.get_attestations(&cs_id)?;

    if envelopes.is_empty() {
        println!("No attestations for changeset {}", cs_id);
        return Ok(());
    }

    println!("Attestations for changeset {}:\n", cs_id);

    for (env_id, envelope) in &envelopes {
        let statement: Statement = serde_json::from_slice(&envelope.payload)
            .unwrap_or_else(|_| Statement::new(vec![], "unknown", Predicate::Other(BTreeMap::new())));

        let pred_name = match statement.predicate_type.as_str() {
            SLSA_PROVENANCE_V1 => "SLSA Provenance v1",
            CYCLONEDX_PREDICATE_V1_6 => "CycloneDX SBOM",
            INTOTO_LINK_V0_3 => "in-toto Link",
            REVIEW_PREDICATE_V1 => "Code Review",
            other => other,
        };

        println!("  {} {}", env_id, pred_name);
        for sig in &envelope.signatures {
            println!("    signed by: {}", sig.keyid);
        }
    }

    Ok(())
}

fn resolve_changeset(repo: &Repository, prefix: Option<&str>) -> Result<(ObjectId, Changeset)> {
    let (id, obj) = match prefix {
        Some(p) => repo.find_by_prefix(p)?,
        None => {
            let head = repo.resolve_head()?
                .ok_or_else(|| anyhow::anyhow!("no changesets yet"))?;
            let obj = repo.get_object(&head)?
                .ok_or_else(|| anyhow::anyhow!("HEAD object missing"))?;
            (head, obj)
        }
    };
    match obj {
        Object::Changeset(cs) => Ok((id, cs)),
        _ => bail!("{} is not a changeset", id),
    }
}
