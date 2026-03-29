use std::collections::{HashMap, HashSet, VecDeque};
use anyhow::Result;
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run(count: usize, graph: bool, oneline: bool) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    if graph || oneline {
        return run_graph(&repo, count, graph, oneline);
    }

    let entries = repo.log(count)?;
    if entries.is_empty() {
        let branch = repo.head_branch()?.unwrap_or_else(|| "main".into());
        println!("On branch {} — no changesets yet", branch);
        return Ok(());
    }

    let author_name = repo.get_config("identity.name")?.unwrap_or_default();
    let branch = repo.head_branch()?;

    for (i, (id, cs)) in entries.iter().enumerate() {
        if i == 0 {
            if let Some(ref b) = branch {
                print!("changeset  {}  ({})", id, b);
            } else {
                print!("changeset  {}", id);
            }
        } else {
            print!("changeset  {}", id);
        }
        println!();

        println!("author     {} ({})", cs.author, author_name);

        if let Some(dt) = chrono::DateTime::from_timestamp_micros(cs.timestamp) {
            println!("date       {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
        }

        if let Some(ref intent) = cs.intent {
            println!("intent     {}", intent.kind);
            if !intent.rationale.is_empty() {
                println!("rationale  {}", intent.rationale);
            }
        }

        println!();
        for line in cs.message.lines() {
            println!("    {}", line);
        }
        println!();
    }

    Ok(())
}

/// Render log with ASCII graph like `git log --graph --oneline`.
fn run_graph(repo: &Repository, count: usize, show_graph: bool, oneline: bool) -> Result<()> {
    // Collect all branch heads so we can label them.
    let branch_refs = repo.list_refs("refs/heads/")?;
    let tag_refs = repo.list_refs("refs/tags/")?;
    let current_branch = repo.head_branch()?;

    // Map: changeset_id → list of labels
    let mut labels: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, reference) in &branch_refs {
        let branch = name.strip_prefix("refs/heads/").unwrap_or(name);
        if let Some(id) = resolve_ref_to_id(repo, reference) {
            let marker = if current_branch.as_deref() == Some(branch) {
                format!("HEAD -> {}", branch)
            } else {
                branch.to_string()
            };
            labels.entry(id).or_default().push(marker);
        }
    }
    for (name, reference) in &tag_refs {
        let tag = name.strip_prefix("refs/tags/").unwrap_or(name);
        if let Some(id) = resolve_ref_to_id(repo, reference) {
            labels.entry(id).or_default().push(format!("tag: {}", tag));
        }
    }

    // Walk full graph from all branch heads (not just HEAD).
    let entries = walk_all_branches(repo, &branch_refs, count)?;
    if entries.is_empty() {
        let branch = current_branch.unwrap_or_else(|| "main".into());
        println!("On branch {} — no changesets yet", branch);
        return Ok(());
    }

    if !show_graph {
        // --oneline without --graph: simple compact output
        for (id, cs) in &entries {
            let short = &id.to_string()[..16];
            let label = labels.get(id).map(|l| format!(" ({})", l.join(", "))).unwrap_or_default();
            let first_line = cs.message.lines().next().unwrap_or("");
            println!("{}{} {}", short, label, first_line);
        }
        return Ok(());
    }

    // Build graph columns for visualization.
    // Each "column" tracks an active branch of the commit graph.
    let mut columns: Vec<ObjectId> = Vec::new();

    for (id, cs) in &entries {
        // Find which column this commit is in, or add a new one.
        let col = columns.iter().position(|c| c == id);
        let col = match col {
            Some(c) => c,
            None => {
                columns.push(*id);
                columns.len() - 1
            }
        };

        // Build the graph line.
        let mut graph_chars: Vec<&str> = Vec::new();
        for (i, _) in columns.iter().enumerate() {
            if i == col {
                graph_chars.push("*");
            } else {
                graph_chars.push("|");
            }
        }
        let graph_str = graph_chars.join(" ");

        // Print commit line.
        let short = &id.to_string()[..16];
        let label = labels.get(id).map(|l| format!(" ({})", l.join(", "))).unwrap_or_default();
        let first_line = cs.message.lines().next().unwrap_or("");

        if oneline {
            println!("{} {}{} {}", graph_str, short, label, first_line);
        } else {
            println!("{} changeset {}{}", graph_str, short, label);
            println!("{} {}", continuation_line(&columns, col), first_line);
            println!("{}", continuation_line(&columns, usize::MAX));
        }

        // Update columns: replace this commit with its first parent,
        // add additional parents as new columns.
        if cs.parents.is_empty() {
            // Root commit — close this column.
            columns.remove(col);
        } else {
            columns[col] = cs.parents[0];
            // Merge commits: additional parents get new columns.
            for parent in cs.parents.iter().skip(1) {
                if !columns.contains(parent) {
                    // Insert merge line.
                    let merge_graph: String = columns.iter().enumerate()
                        .map(|(i, _)| if i == col { "|\\" } else { "| " })
                        .collect::<Vec<_>>().join("");
                    if oneline {
                        println!("{}", merge_graph);
                    } else {
                        println!("{}", merge_graph);
                    }
                    columns.insert(col + 1, *parent);
                }
            }
        }
    }

    Ok(())
}

/// Generate a continuation line (pipes for active columns).
fn continuation_line(columns: &[ObjectId], skip: usize) -> String {
    columns.iter().enumerate()
        .map(|(i, _)| if i == skip { " " } else { "|" })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Walk commits from all branch heads in topological order.
fn walk_all_branches(
    repo: &Repository,
    branch_refs: &[(String, Ref)],
    max_count: usize,
) -> Result<Vec<(ObjectId, Changeset)>> {
    // Collect all starting points.
    let mut starts: Vec<ObjectId> = Vec::new();
    for (_, reference) in branch_refs {
        if let Some(id) = resolve_ref_to_id(repo, reference) {
            starts.push(id);
        }
    }
    // Also include HEAD in case it's detached.
    if let Some(head) = repo.resolve_head()? {
        if !starts.contains(&head) {
            starts.push(head);
        }
    }

    // BFS with timestamp-based priority (most recent first).
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut queue: VecDeque<ObjectId> = starts.into_iter().collect();

    // First pass: collect all reachable commits.
    let mut all_commits: Vec<(ObjectId, Changeset)> = Vec::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        match repo.get_object(&id)? {
            Some(Object::Changeset(cs)) => {
                for parent in &cs.parents {
                    queue.push_back(*parent);
                }
                all_commits.push((id, cs));
            }
            _ => {}
        }
    }

    // Sort by timestamp descending (most recent first).
    all_commits.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp));

    // Take up to max_count.
    result.extend(all_commits.into_iter().take(max_count));
    Ok(result)
}

fn resolve_ref_to_id(repo: &Repository, reference: &Ref) -> Option<ObjectId> {
    match reference {
        Ref::Direct(id) => Some(*id),
        Ref::Symbolic(target) => repo.resolve_ref(target).ok().flatten(),
    }
}
