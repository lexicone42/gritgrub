use anyhow::Result;
use gritgrub_core::*;
use gritgrub_store::Repository;

pub fn run(name: Option<&str>, delete: bool) -> Result<()> {
    let repo = Repository::discover(&std::env::current_dir()?)?;

    if delete {
        let tag_name = name.ok_or_else(|| anyhow::anyhow!("tag name required for -d"))?;
        let ref_name = format!("refs/tags/{}", tag_name);
        if !repo.delete_ref(&ref_name)? {
            anyhow::bail!("tag '{}' not found", tag_name);
        }
        println!("Deleted tag '{}'", tag_name);
        return Ok(());
    }

    match name {
        None => {
            let refs = repo.list_refs("refs/tags/")?;
            if refs.is_empty() {
                println!("No tags.");
            }
            for (ref_name, reference) in &refs {
                let tag = ref_name.strip_prefix("refs/tags/").unwrap_or(ref_name);
                let id = match reference {
                    Ref::Direct(id) => format!("{}", id),
                    Ref::Symbolic(target) => format!("-> {}", target),
                };
                println!("{:24} {}", tag, id);
            }
        }
        Some(tag_name) => {
            let head = repo.resolve_head()?
                .ok_or_else(|| anyhow::anyhow!("no changesets yet"))?;
            let ref_name = format!("refs/tags/{}", tag_name);
            repo.set_ref(&ref_name, &Ref::Direct(head))?;
            println!("Tagged '{}' at {}", tag_name, head);
        }
    }

    Ok(())
}
