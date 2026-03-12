use anyhow::{bail, Result};
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run(id_prefix: &str) -> Result<()> {
    if id_prefix.len() < 8 {
        bail!("object ID prefix must be at least 8 hex characters");
    }

    // For now, require a full 64-char hex ID. Prefix lookup comes later.
    let id = ObjectId::from_hex(id_prefix)
        .map_err(|e| anyhow::anyhow!("invalid object ID: {}", e))?;

    let repo = Repository::discover(&std::env::current_dir()?)?;

    match repo.get_object(&id)? {
        Some(Object::Blob(blob)) => print_blob(&blob),
        Some(Object::Tree(tree)) => print_tree(&tree),
        Some(Object::Changeset(cs)) => print_changeset(&id, &cs),
        None => bail!("object not found: {}", id),
    }

    Ok(())
}

fn print_blob(blob: &Blob) {
    println!("type  blob");
    println!("size  {} bytes", blob.data.len());
    println!();

    // Try to display as UTF-8, fall back to hex dump.
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
    println!("type  tree");
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
    println!("tree       {}", cs.tree.to_hex());
    println!("author     {}", cs.author);
    println!("timestamp  {}", cs.timestamp);

    for (i, parent) in cs.parents.iter().enumerate() {
        println!("parent[{}]  {}", i, parent.to_hex());
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
    println!("    {}", cs.message);
}
