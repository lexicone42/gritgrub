use anyhow::Result;
use gritgrub_core::{Intent, IntentKind};
use gritgrub_store::Repository;

pub fn run(message: &str, intent_kind: Option<&str>, rationale: Option<&str>) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let author = repo.local_identity()?;

    let intent = intent_kind.map(|kind| Intent {
        kind: parse_intent_kind(kind),
        affected_paths: vec![],
        rationale: rationale.unwrap_or("").to_string(),
        context_ref: None,
        verifications: vec![],
    });

    let id = repo.commit(message, author, intent)?;
    let branch = repo.head_branch()?.unwrap_or_else(|| "detached".into());

    println!("[{} {}] {}", branch, id, message);

    Ok(())
}

fn parse_intent_kind(s: &str) -> IntentKind {
    match s.to_lowercase().as_str() {
        "feature" | "feat" => IntentKind::Feature,
        "bugfix" | "fix" | "bug" => IntentKind::Bugfix,
        "refactor" | "refact" => IntentKind::Refactor,
        "agent-task" | "agent" => IntentKind::AgentTask,
        "exploration" | "explore" => IntentKind::Exploration,
        "dependency" | "dep" | "deps" => IntentKind::Dependency,
        "documentation" | "docs" | "doc" => IntentKind::Documentation,
        _ => {
            eprintln!("warning: unknown intent '{}', defaulting to feature", s);
            IntentKind::Feature
        }
    }
}
