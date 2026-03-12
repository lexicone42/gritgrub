use anyhow::Result;
use gritgrub_store::Repository;

pub fn run(count: usize) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let entries = repo.log(count)?;

    if entries.is_empty() {
        let branch = repo.head_branch()?.unwrap_or_else(|| "main".into());
        println!("On branch {} — no changesets yet", branch);
        return Ok(());
    }

    let author_name = repo.get_config("identity.name")?.unwrap_or_default();
    let branch = repo.head_branch()?;

    for (i, (id, cs)) in entries.iter().enumerate() {
        // Show branch label on the first (most recent) entry.
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
        // Indent the message body.
        for line in cs.message.lines() {
            println!("    {}", line);
        }
        println!();
    }

    Ok(())
}
