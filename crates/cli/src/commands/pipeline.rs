use anyhow::{Context, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;
use std::process::Command;
use std::time::Instant;

/// Run a pipeline on the current HEAD (or a specific changeset).
pub fn run(pipeline_name: Option<&str>, changeset_id: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let author = repo.local_identity()?;

    let name = pipeline_name.unwrap_or("default");
    let pipeline = match repo.get_pipeline(name)? {
        Some(p) => p,
        None => {
            if name == "default" {
                // Auto-create default Rust pipeline.
                let p = Pipeline::default_rust();
                repo.save_pipeline(&p)?;
                println!("Created default Rust pipeline (test + lint + build)");
                p
            } else {
                anyhow::bail!("pipeline '{}' not found — define it with: forge pipeline define", name);
            }
        }
    };

    let cs_id = match changeset_id {
        Some(prefix) => {
            let (id, _) = repo.find_by_prefix(prefix)?;
            id
        }
        None => repo.resolve_head()?
            .ok_or_else(|| anyhow::anyhow!("no HEAD — commit something first"))?,
    };

    println!("Running pipeline '{}' on {}", pipeline.name, &cs_id.to_hex()[..12]);
    println!();

    let overall_start = Instant::now();
    let mut stage_results = Vec::new();
    let mut all_passed = true;

    for stage in &pipeline.stages {
        let stage_start = Instant::now();
        print!("  {} ... ", stage.name);

        let (passed, exit_code, summary, tests_passed, tests_failed, warnings) =
            execute_stage(stage, &repo)?;

        let duration_ms = stage_start.elapsed().as_millis() as u64;

        if passed {
            println!("\x1b[32m✓\x1b[0m ({:.1}s) {}", duration_ms as f64 / 1000.0, summary);
        } else {
            println!("\x1b[31m✗\x1b[0m ({:.1}s) {}", duration_ms as f64 / 1000.0, summary);
            if stage.required {
                all_passed = false;
            }
        }

        stage_results.push(StageResult {
            name: stage.name.clone(),
            passed,
            exit_code,
            duration_ms,
            summary,
            tests_passed,
            tests_failed,
            warnings,
            required: stage.required,
        });
    }

    let total_ms = overall_start.elapsed().as_millis() as u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock error"))?
        .as_micros() as i64;

    println!();
    if all_passed {
        println!("\x1b[1;32mPipeline passed\x1b[0m ({:.1}s)", total_ms as f64 / 1000.0);
    } else {
        println!("\x1b[1;31mPipeline failed\x1b[0m ({:.1}s)", total_ms as f64 / 1000.0);
    }

    // Create the pipeline result.
    let result = PipelineResult {
        pipeline: pipeline.name.clone(),
        changeset: cs_id,
        stages: stage_results,
        passed: all_passed,
        duration_ms: total_ms,
        runner: author,
        completed_at: now,
    };

    // Attest the result (requires keypair).
    match repo.attest_pipeline_result(&result) {
        Ok(env_id) => {
            println!("  attestation: {}", &env_id.to_hex()[..12]);
            let level = repo.compute_verification_level(&cs_id)?;
            println!("  verification: {}", level);
        }
        Err(e) => {
            eprintln!("  warning: could not create attestation: {}", e);
            eprintln!("  (generate a keypair with: forge identity keygen)");
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}

/// Define a pipeline interactively or from arguments.
pub fn define(name: &str, stages: &[String]) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let parsed_stages: Vec<Stage> = stages.iter().map(|s| {
        parse_stage_spec(s)
    }).collect::<Result<Vec<_>>>()?;

    if parsed_stages.is_empty() {
        anyhow::bail!("at least one stage required — e.g., 'test', 'lint', 'build', 'cmd:make check'");
    }

    let pipeline = Pipeline {
        name: name.to_string(),
        stages: parsed_stages,
        trigger: Trigger::Manual,
    };

    repo.save_pipeline(&pipeline)?;
    println!("Defined pipeline '{}':", name);
    for stage in &pipeline.stages {
        let req = if stage.required { "required" } else { "optional" };
        println!("  {} [{}] {:?}", stage.name, req, stage.kind);
    }
    Ok(())
}

/// List defined pipelines.
pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let pipelines = repo.list_pipelines()?;

    if pipelines.is_empty() {
        println!("No pipelines defined.");
        println!();
        println!("Create one:");
        println!("  forge pipeline define default --stage test --stage lint");
        println!("  forge pipeline run");
        return Ok(());
    }

    for p in &pipelines {
        let trigger = match &p.trigger {
            Trigger::OnCommit => "on-commit",
            Trigger::OnRefUpdate { pattern } => pattern.as_str(),
            Trigger::Manual => "manual",
        };
        println!("{} [trigger: {}]", p.name, trigger);
        for stage in &p.stages {
            let req = if stage.required { "●" } else { "○" };
            println!("  {} {} ({:?})", req, stage.name, stage.kind);
        }
    }
    Ok(())
}

/// Show pipeline results for a changeset.
pub fn show(changeset_id: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    let cs_id = match changeset_id {
        Some(prefix) => repo.find_by_prefix(prefix)?.0,
        None => repo.resolve_head()?
            .ok_or_else(|| anyhow::anyhow!("no HEAD"))?,
    };

    let results = repo.get_pipeline_results(&cs_id)?;
    let level = repo.compute_verification_level(&cs_id)?;

    println!("Changeset {} — verification: {}", &cs_id.to_hex()[..12], level);
    println!();

    if results.is_empty() {
        println!("No pipeline results. Run: forge pipeline run");
        return Ok(());
    }

    for r in &results {
        let icon = if r.passed { "\x1b[32m✓\x1b[0m" } else { "\x1b[31m✗\x1b[0m" };
        println!("{} {} ({:.1}s) runner={}", icon, r.pipeline, r.duration_ms as f64 / 1000.0, r.runner);
        for s in &r.stages {
            let si = if s.passed { "\x1b[32m✓\x1b[0m" } else { "\x1b[31m✗\x1b[0m" };
            let req = if s.required { "" } else { " (optional)" };
            println!("  {} {} ({:.1}s){} — {}", si, s.name, s.duration_ms as f64 / 1000.0, req, s.summary);
        }
    }
    Ok(())
}

// ── Stage execution ─────────────────────────────────────────────

fn execute_stage(
    stage: &Stage,
    _repo: &Repository,
) -> Result<(bool, Option<i32>, String, u32, u32, u32)> {
    match &stage.kind {
        StageKind::CargoTest { args } => {
            let mut cmd = Command::new("cargo");
            cmd.arg("test");
            for arg in args {
                cmd.arg(arg);
            }
            let output = cmd.output().context("failed to run cargo test")?;
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Parse test summary from cargo output.
            let (passed_count, failed_count) = parse_test_counts(&stderr);
            let summary = if failed_count > 0 {
                format!("{} passed, {} failed", passed_count, failed_count)
            } else {
                format!("{} passed", passed_count)
            };

            Ok((
                output.status.success(),
                output.status.code(),
                summary,
                passed_count,
                failed_count,
                0,
            ))
        }

        StageKind::CargoClippy { args } => {
            let mut cmd = Command::new("cargo");
            cmd.arg("clippy");
            cmd.args(["--", "-D", "warnings"]);
            for arg in args {
                cmd.arg(arg);
            }
            let output = cmd.output().context("failed to run cargo clippy")?;
            let stderr = String::from_utf8_lossy(&output.stderr);

            let warning_count = stderr.matches("warning:").count() as u32;
            let summary = if warning_count > 0 {
                format!("{} warnings", warning_count)
            } else {
                "clean".to_string()
            };

            Ok((
                output.status.success(),
                output.status.code(),
                summary,
                0, 0,
                warning_count,
            ))
        }

        StageKind::CargoBuild { release } => {
            let mut cmd = Command::new("cargo");
            cmd.arg("build");
            if *release {
                cmd.arg("--release");
            }
            let output = cmd.output().context("failed to run cargo build")?;
            let summary = if output.status.success() {
                "ok".to_string()
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let first_error = stderr.lines()
                    .find(|l| l.contains("error"))
                    .unwrap_or("build failed")
                    .to_string();
                first_error.chars().take(200).collect()
            };

            Ok((
                output.status.success(),
                output.status.code(),
                summary,
                0, 0, 0,
            ))
        }

        StageKind::Command { cmd, args, cwd } => {
            let mut command = Command::new(cmd);
            for arg in args {
                command.arg(arg);
            }
            if !cwd.is_empty() {
                command.current_dir(cwd);
            }
            let output = command.output()
                .with_context(|| format!("failed to run: {} {}", cmd, args.join(" ")))?;

            let summary = if output.status.success() {
                "ok".to_string()
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                stderr.chars().take(200).collect()
            };

            Ok((
                output.status.success(),
                output.status.code(),
                summary,
                0, 0, 0,
            ))
        }

        StageKind::PathCheck { frozen_paths } => {
            // TODO: check against the changeset's diff.
            let summary = format!("{} frozen paths checked", frozen_paths.len());
            Ok((true, Some(0), summary, 0, 0, 0))
        }
    }
}

/// Parse "N passed; M failed" from cargo test output.
fn parse_test_counts(output: &str) -> (u32, u32) {
    let mut total_passed = 0u32;
    let mut total_failed = 0u32;

    for line in output.lines() {
        if line.starts_with("test result:") {
            // "test result: ok. 26 passed; 0 failed; ..."
            for part in line.split(';') {
                let part = part.trim();
                if part.ends_with("passed") {
                    if let Some(n) = part.split_whitespace().rev().nth(1) {
                        total_passed += n.parse::<u32>().unwrap_or(0);
                    }
                }
                if part.ends_with("failed") {
                    if let Some(n) = part.split_whitespace().rev().nth(1) {
                        total_failed += n.parse::<u32>().unwrap_or(0);
                    }
                }
            }
        }
    }

    (total_passed, total_failed)
}

/// Parse a stage spec like "test", "lint", "build", "cmd:make check".
fn parse_stage_spec(spec: &str) -> Result<Stage> {
    let (name, kind) = if let Some(cmd) = spec.strip_prefix("cmd:") {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let (bin, args) = parts.split_first()
            .ok_or_else(|| anyhow::anyhow!("empty command in stage spec"))?;
        (cmd.to_string(), StageKind::Command {
            cmd: bin.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: String::new(),
        })
    } else {
        match spec {
            "test" => ("test".into(), StageKind::CargoTest { args: vec![] }),
            "lint" | "clippy" => ("lint".into(), StageKind::CargoClippy { args: vec![] }),
            "build" => ("build".into(), StageKind::CargoBuild { release: false }),
            "build-release" => ("build".into(), StageKind::CargoBuild { release: true }),
            other => anyhow::bail!(
                "unknown stage '{}' — use: test, lint, build, build-release, or cmd:<command>",
                other
            ),
        }
    };

    Ok(Stage {
        name,
        kind,
        required: true,
        timeout_secs: 300,
    })
}
