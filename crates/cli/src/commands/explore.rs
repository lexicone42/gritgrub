use anyhow::{Context, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

/// Create a new exploration goal.
pub fn create(
    description: &str,
    target: &str,
    max_approaches: u32,
    time_budget: u64,
    constraints: &[String],
) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let author = repo.local_identity()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock error"))?
        .as_micros() as i64;

    let parsed_constraints: Vec<Constraint> = constraints.iter().map(|c| {
        // Parse "kind:description" or just "description".
        if let Some((kind_str, desc)) = c.split_once(':') {
            let kind = match kind_str {
                "tests" => ConstraintKind::TestsPass,
                "lint" => ConstraintKind::LintClean,
                "frozen" => ConstraintKind::PathFrozen,
                "perf" => ConstraintKind::PerformanceBound,
                "compat" => ConstraintKind::BackwardCompatible,
                _ => ConstraintKind::Custom,
            };
            Constraint {
                kind,
                description: desc.to_string(),
                check_command: None,
            }
        } else {
            Constraint {
                kind: ConstraintKind::Custom,
                description: c.to_string(),
                check_command: None,
            }
        }
    }).collect();

    let goal = Goal {
        description: description.to_string(),
        target_branch: target.to_string(),
        constraints: parsed_constraints,
        created_by: author,
        created_at: now,
        max_approaches,
        time_budget_secs: time_budget,
    };

    let goal_id = repo.create_goal(&goal)?;
    println!("Created exploration goal {}", &goal_id.to_hex()[..12]);
    println!("  {}", description);
    println!("  target: {}", target);
    if max_approaches > 0 {
        println!("  max approaches: {}", max_approaches);
    }
    if time_budget > 0 {
        println!("  time budget: {}s", time_budget);
    }
    println!();
    println!("Start an approach:");
    println!("  forge explore approach {} --name <approach-name>", &goal_id.to_hex()[..12]);

    Ok(())
}

/// Create a new approach branch for a goal.
pub fn approach(goal_prefix: &str, name: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let agent = repo.local_identity()?;

    let goal_id = find_goal_by_prefix(&repo, goal_prefix)?;
    let approach_ref = repo.create_approach(&goal_id, name, agent)?;

    println!("Created approach '{}' for goal {}", name, &goal_id.to_hex()[..12]);
    println!("  branch: {}", approach_ref);
    println!();
    println!("Switch to this approach and start working:");
    println!("  forge checkout {}", name);
    println!();
    println!("When done, promote it:");
    println!("  forge explore promote {} --approach {}", &goal_id.to_hex()[..12], name);

    Ok(())
}

/// List all active exploration goals.
pub fn list() -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let goals = repo.list_goals()?;

    if goals.is_empty() {
        println!("No active explorations.");
        println!();
        println!("Start one:");
        println!("  forge explore create \"description of what to achieve\"");
        return Ok(());
    }

    for (goal_id, goal) in &goals {
        let summary = repo.goal_summary(goal_id)?;
        let short_id = &goal_id.to_hex()[..12];

        // Header.
        let status = if summary.promoted.is_some() {
            "promoted"
        } else if summary.approaches.is_empty() {
            "no approaches"
        } else {
            "exploring"
        };
        println!("\x1b[1;33m{}\x1b[0m [{}] {}", short_id, status, goal.description);
        println!("  target: {}  approaches: {}  agents: {}",
            goal.target_branch,
            summary.approaches.len(),
            summary.claims.len(),
        );

        // Approaches.
        for a in &summary.approaches {
            let tip_short = a.tip
                .map(|id| id.to_hex()[..8].to_string())
                .unwrap_or_else(|| "—".to_string());
            let msg = a.latest_message.as_deref().unwrap_or("(no commits)");
            let claimed = summary.claims.iter()
                .any(|c| c.approach == a.name);
            let marker = if claimed { " \x1b[32m●\x1b[0m" } else { "" };

            println!("    \x1b[36m{}\x1b[0m {} ({} commits) {}{}",
                a.name, tip_short, a.changeset_count, msg, marker);
        }

        // Constraints.
        if !goal.constraints.is_empty() {
            println!("  constraints:");
            for c in &goal.constraints {
                println!("    - [{}] {}", match c.kind {
                    ConstraintKind::TestsPass => "tests",
                    ConstraintKind::LintClean => "lint",
                    ConstraintKind::PathFrozen => "frozen",
                    ConstraintKind::PerformanceBound => "perf",
                    ConstraintKind::BackwardCompatible => "compat",
                    ConstraintKind::Custom => "custom",
                }, c.description);
            }
        }
        println!();
    }

    Ok(())
}

/// Show detailed status of a specific goal.
pub fn show(goal_prefix: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let goal_id = find_goal_by_prefix(&repo, goal_prefix)?;
    let summary = repo.goal_summary(&goal_id)?;

    println!("\x1b[1mGoal:\x1b[0m {}", summary.goal.description);
    println!("  id:     {}", summary.goal_id.to_hex());
    println!("  target: {}", summary.goal.target_branch);
    println!("  author: {}", summary.goal.created_by);

    if summary.promoted.is_some() {
        println!("  status: \x1b[32mpromoted\x1b[0m");
    } else {
        println!("  status: \x1b[33mexploring\x1b[0m");
    }

    println!();
    println!("\x1b[1mApproaches:\x1b[0m");
    for a in &summary.approaches {
        let tip_hex = a.tip
            .map(|id| id.to_hex()[..12].to_string())
            .unwrap_or_else(|| "none".to_string());
        println!("  \x1b[36m{}\x1b[0m", a.name);
        println!("    tip:      {}", tip_hex);
        println!("    commits:  {}", a.changeset_count);
        if let Some(msg) = &a.latest_message {
            println!("    message:  {}", msg);
        }
        if let Some(author) = &a.created_by {
            println!("    author:   {}", author);
        }
        println!("    verified: {}", a.verification);
    }

    if !summary.claims.is_empty() {
        println!();
        println!("\x1b[1mActive agents:\x1b[0m");
        for c in &summary.claims {
            println!("  {} → approach '{}' (heartbeat #{})",
                c.agent, c.approach, c.heartbeat);
            if !c.intent.is_empty() {
                println!("    intent: {}", c.intent);
            }
        }
    }

    Ok(())
}

/// Promote an approach: merge it into the goal's target branch.
pub fn promote(goal_prefix: &str, approach_name: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let author = repo.local_identity()?;
    let goal_id = find_goal_by_prefix(&repo, goal_prefix)?;

    let result = repo.promote_approach(&goal_id, approach_name, author)?;

    match result {
        PromoteResult::FastForward(id) => {
            println!("Fast-forward promoted '{}' → {}", approach_name, &id.to_hex()[..12]);
        }
        PromoteResult::Merged(id) => {
            println!("Merge-promoted '{}' → {}", approach_name, &id.to_hex()[..12]);
        }
        PromoteResult::Conflict(paths) => {
            println!("Cannot promote '{}': merge conflicts in:", approach_name);
            for p in &paths {
                println!("  {}", p);
            }
            println!();
            println!("Resolve conflicts manually, then retry.");
            return Ok(());
        }
    }

    let goal = repo.get_goal(&goal_id)?
        .context("goal not found")?;
    println!("  merged into: {}", goal.target_branch);
    Ok(())
}

/// Abandon a goal — clean up all exploration refs.
pub fn abandon(goal_prefix: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let goal_id = find_goal_by_prefix(&repo, goal_prefix)?;

    let goal = repo.get_goal(&goal_id)?
        .context("goal not found")?;
    let count = repo.abandon_goal(&goal_id)?;

    println!("Abandoned goal: {}", goal.description);
    println!("  cleaned up {} refs", count);
    println!("  objects remain in store (garbage collect separately)");

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────

fn find_goal_by_prefix(repo: &Repository, prefix: &str) -> Result<ObjectId> {
    let goals = repo.list_goals()?;
    let matches: Vec<_> = goals.iter()
        .filter(|(id, _)| id.to_hex().starts_with(prefix))
        .collect();

    match matches.len() {
        0 => anyhow::bail!("no goal matching prefix '{}'", prefix),
        1 => Ok(matches[0].0),
        _ => {
            anyhow::bail!(
                "ambiguous prefix '{}': matches {} goals",
                prefix,
                matches.len(),
            );
        }
    }
}
