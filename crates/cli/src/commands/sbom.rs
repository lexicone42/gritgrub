use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

/// Generate an SBOM from Cargo.lock and attach as an attestation to HEAD.
pub fn generate(changeset_prefix: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let (cs_id, _cs) = resolve_changeset(&repo, changeset_prefix)?;

    // Parse Cargo.lock for dependency info.
    let lockfile_path = repo.root().join("Cargo.lock");
    if !lockfile_path.exists() {
        bail!("no Cargo.lock found at {} — SBOM generation currently supports Rust projects", repo.root().display());
    }

    let lockfile_content = std::fs::read_to_string(&lockfile_path)?;
    let packages = parse_cargo_lock(&lockfile_content)?;

    if packages.is_empty() {
        bail!("no packages found in Cargo.lock");
    }

    // Build CycloneDX JSON.
    let bom = build_cyclonedx_bom(&packages);
    let bom_json = serde_json::to_vec_pretty(&bom)?;

    // Store the BOM as a blob.
    let bom_blob = Object::Blob(Blob { data: bom_json });
    let bom_id = repo.put_object(&bom_blob)?;

    // Count direct vs transitive (heuristic: workspace members are direct).
    let workspace_count = packages.iter()
        .filter(|p| p.source.is_none())
        .count();
    let dep_count = packages.len() - workspace_count;

    // Create SBOM attestation.
    let sbom_att = SbomAttestation {
        format: SbomFormat::CycloneDx,
        spec_version: "1.6".into(),
        bom_ref: bom_id,
        component_count: packages.len() as u32,
        dependency_count: dep_count as u32,
    };

    let subject = Subject::from_object_id("changeset", &cs_id);
    let tree_subject = Subject::from_object_id("tree", &_cs.tree);
    let statement = Statement::new(
        vec![subject, tree_subject],
        CYCLONEDX_PREDICATE,
        Predicate::Sbom(sbom_att),
    );

    let env_id = repo.attest(&cs_id, &statement)?;

    println!("Generated SBOM attestation: {}", env_id);
    println!("  CycloneDX BOM blob: {}", bom_id);
    println!("  components: {} ({} workspace, {} dependencies)",
        packages.len(), workspace_count, dep_count);
    println!("  subject: changeset {}", cs_id);

    Ok(())
}

/// Show the SBOM for a changeset (if one exists).
pub fn show(changeset_prefix: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let (cs_id, _cs) = resolve_changeset(&repo, changeset_prefix)?;

    let envelopes = repo.get_attestations(&cs_id)?;

    let sbom_env = envelopes.iter().find(|(_, env)| {
        serde_json::from_slice::<Statement>(&env.payload)
            .map(|s| s.predicate_type == CYCLONEDX_PREDICATE)
            .unwrap_or(false)
    });

    let (_env_id, envelope) = match sbom_env {
        Some(e) => e,
        None => {
            println!("No SBOM attestation for changeset {}", cs_id);
            println!("Generate one with: forge sbom generate");
            return Ok(());
        }
    };

    let statement: Statement = serde_json::from_slice(&envelope.payload)?;
    match &statement.predicate {
        Predicate::Sbom(sbom) => {
            println!("SBOM for changeset {}\n", cs_id);
            println!("  format:       CycloneDX {}", sbom.spec_version);
            println!("  components:   {}", sbom.component_count);
            println!("  dependencies: {}", sbom.dependency_count);
            println!("  bom blob:     {}", sbom.bom_ref);

            // Print the actual BOM JSON.
            if let Some(Object::Blob(blob)) = repo.get_object(&sbom.bom_ref)? {
                if let Ok(json) = std::str::from_utf8(&blob.data) {
                    println!("\n{}", json);
                }
            }
        }
        _ => println!("Unexpected predicate type in SBOM attestation"),
    }

    Ok(())
}

// ── Cargo.lock parser ──────────────────────────────────────────────

#[derive(Debug)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn parse_cargo_lock(content: &str) -> Result<Vec<CargoPackage>> {
    let mut packages = Vec::new();
    let mut current: Option<CargoPackage> = None;

    for line in content.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            if let Some(pkg) = current.take() {
                packages.push(pkg);
            }
            current = Some(CargoPackage {
                name: String::new(),
                version: String::new(),
                source: None,
                checksum: None,
            });
            continue;
        }

        if let Some(ref mut pkg) = current {
            if let Some(val) = line.strip_prefix("name = ") {
                pkg.name = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("version = ") {
                pkg.version = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("source = ") {
                pkg.source = Some(val.trim_matches('"').to_string());
            } else if let Some(val) = line.strip_prefix("checksum = ") {
                pkg.checksum = Some(val.trim_matches('"').to_string());
            }
        }
    }

    if let Some(pkg) = current {
        packages.push(pkg);
    }

    Ok(packages)
}

// ── CycloneDX BOM builder ──────────────────────────────────────────

fn build_cyclonedx_bom(packages: &[CargoPackage]) -> serde_json::Value {
    let components: Vec<serde_json::Value> = packages.iter().map(|pkg| {
        let mut component = serde_json::json!({
            "type": if pkg.source.is_none() { "application" } else { "library" },
            "name": pkg.name,
            "version": pkg.version,
            "purl": format!("pkg:cargo/{}@{}", pkg.name, pkg.version),
        });

        if let Some(ref checksum) = pkg.checksum {
            component["hashes"] = serde_json::json!([{
                "alg": "SHA-256",
                "content": checksum,
            }]);
        }

        if let Some(ref source) = pkg.source {
            component["externalReferences"] = serde_json::json!([{
                "type": "distribution",
                "url": source,
            }]);
        }

        component
    }).collect();

    serde_json::json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "gritgrub",
                "name": "forge",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": {
                "type": "application",
                "name": "gritgrub",
            }
        },
        "components": components,
    })
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
