use anyhow::Result;
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run(id_prefix: &str) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;
    let (id, obj) = repo.find_by_prefix(id_prefix)?;

    match obj {
        Object::Blob(blob) => print_blob(&blob),
        Object::Tree(tree) => print_tree(&tree),
        Object::Changeset(cs) => print_changeset(&id, &cs),
    }

    Ok(())
}

fn print_blob(blob: &Blob) {
    println!("type  blob");
    println!("size  {} bytes", blob.data.len());
    println!();

    match std::str::from_utf8(&blob.data) {
        Ok(text) => print!("{}", text),
        Err(_) => {
            for (i, chunk) in blob.data.chunks(16).enumerate() {
                print!("{:08x}  ", i * 16);
                for byte in chunk {
                    print!("{:02x} ", byte);
                }
                println!();
            }
        }
    }
}

fn print_tree(tree: &Tree) {
    println!("type     tree");
    println!("entries  {}", tree.entries.len());
    println!();

    for (name, entry) in &tree.entries {
        let kind = match entry.kind {
            EntryKind::File => if entry.executable { "file*" } else { "file " },
            EntryKind::Directory => "dir  ",
            EntryKind::Symlink => "link ",
        };
        println!("  {} {} {}", kind, entry.id, name);
    }
}

fn print_changeset(id: &ObjectId, cs: &Changeset) {
    println!("type       changeset");
    println!("id         {}", id.to_hex());
    println!("tree       {}", cs.tree);

    for (i, parent) in cs.parents.iter().enumerate() {
        println!("parent[{}]  {}", i, parent);
    }

    println!("author     {}", cs.author);

    if let Some(dt) = chrono::DateTime::from_timestamp_micros(cs.timestamp) {
        println!("date       {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    if let Some(ref intent) = cs.intent {
        println!("intent     {}", intent.kind);
        if !intent.rationale.is_empty() {
            println!("rationale  {}", intent.rationale);
        }
    }

    for (k, v) in &cs.metadata {
        println!("meta.{}  {}", k, v);
    }

    println!();
    for line in cs.message.lines() {
        println!("    {}", line);
    }
}
