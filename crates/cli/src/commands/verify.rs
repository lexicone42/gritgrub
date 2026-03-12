use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_core::attestation::*;
use gritgrub_store::Repository;

/// Verify all attestations for a changeset.
pub fn run(changeset_prefix: Option<&str>, slsa_level: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let (cs_id, _cs) = resolve_changeset(&repo, changeset_prefix)?;

    let results = repo.verify_attestations(&cs_id)?;

    if results.is_empty() {
        println!("No attestations found for changeset {}", cs_id);
        return Ok(());
    }

    println!("Verification results for changeset {}:\n", cs_id);

    let mut all_ok = true;
    for r in &results {
        let pred_name = match r.predicate_type.as_str() {
            SLSA_PROVENANCE_V1 => "SLSA Provenance",
            CYCLONEDX_PREDICATE => "CycloneDX SBOM",
            INTOTO_LINK_V0_3 => "in-toto Link",
            REVIEW_PREDICATE_V1 => "Code Review",
            other => other,
        };

        let status = if r.verified {
            "PASS"
        } else if !r.key_found {
            all_ok = false;
            "NOKEY"
        } else {
            all_ok = false;
            "FAIL"
        };

        println!("  [{}] {} — envelope {} signed by {}",
            status, pred_name, r.envelope_id, r.signer);
    }

    // SLSA level check if requested.
    if let Some(level_str) = slsa_level {
        let required = match level_str {
            "0" | "L0" => SlsaLevel::L0,
            "1" | "L1" => SlsaLevel::L1,
            "2" | "L2" => SlsaLevel::L2,
            "3" | "L3" => SlsaLevel::L3,
            _ => bail!("invalid SLSA level: {} (use L0-L3)", level_str),
        };

        let meets = repo.check_slsa_level(&cs_id, required)?;
        println!("\nSLSA {} compliance: {}", required, if meets { "PASS" } else { "FAIL" });
        if !meets {
            all_ok = false;
        }
    }

    if all_ok {
        println!("\nAll verifications passed.");
    } else {
        println!("\nSome verifications failed.");
        std::process::exit(1);
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
