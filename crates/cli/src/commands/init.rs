use std::path::Path;
use anyhow::Result;
use gritgrub_store::Repository;

pub fn run(name: Option<&str>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repository::init(&cwd)?;

    if let Some(name) = name {
        repo.set_config("identity.name", name)?;
    }

    let identity = repo.local_identity()?;
    let author_name = repo.get_config("identity.name")?.unwrap_or_default();

    // Write CLAUDE.md if it doesn't exist.
    let claude_md = cwd.join("CLAUDE.md");
    if !claude_md.exists() {
        write_claude_md(&claude_md)?;
    }

    // Write .forgeignore if it doesn't exist.
    let forgeignore = cwd.join(".forgeignore");
    if !forgeignore.exists() {
        write_forgeignore(&forgeignore)?;
    }

    println!(
        "Initialized forge repository in {}",
        cwd.join(".forge").display()
    );
    println!("  identity: {} ({})", identity, author_name);

    Ok(())
}

fn write_claude_md(path: &Path) -> Result<()> {
    std::fs::write(path, CLAUDE_MD_TEMPLATE)?;
    Ok(())
}

fn write_forgeignore(path: &Path) -> Result<()> {
    std::fs::write(path, FORGEIGNORE_TEMPLATE)?;
    Ok(())
}

const FORGEIGNORE_TEMPLATE: &str = "\
# forge ignore — files excluded from changesets
# Syntax: globs (*.ext), exact names, comments (#)

# Build artifacts
target/
build/
dist/
*.o
*.so
*.dylib

# Dependencies
node_modules/

# IDE / editor
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Secrets — NEVER commit these
.env
.env.*
*.pem
*.key
";

const CLAUDE_MD_TEMPLATE: &str = r#"# Project — forge-managed repository

This project uses **forge** (gritgrub) for version control instead of git.
Do NOT use git commands. Use `forge` commands documented below.

## Quick reference

| Task | Command |
|------|---------|
| Check status | `forge status` |
| Create changeset | `forge commit -m "message"` |
| With intent | `forge commit -m "msg" --intent feature --rationale "why"` |
| View history | `forge log` |
| Show changeset | `forge show` |
| Show diff | `forge diff` |
| Create branch | `forge branch <name>` |
| Switch branch | `forge checkout <branch>` |
| Create + switch | `forge checkout -b <name>` |
| Merge branch | `forge merge <branch>` |
| Create tag | `forge tag <name>` |
| Stash changes | `forge stash save` |
| Pop stash | `forge stash pop` |
| Push to remote | `forge push` |
| Pull from remote | `forge pull` |
| Graph history | `forge log --graph --oneline` |
| Compact log | `forge log --oneline` |

## Commit workflow

```bash
# Check what changed
forge status
forge diff

# Commit with structured intent (preferred)
forge commit -m "Add user auth endpoint" --intent feature --rationale "Required for API v2"

# Intent kinds: feature, bugfix, refactor, agent-task, exploration, dep, docs
```

## Identity

Each contributor (human or agent) has a unique identity with capabilities.

```bash
forge identity list          # Show all identities
forge identity create --name "my-agent" --kind agent --runtime claude-code
forge identity use <id>      # Switch active identity
```

## Agent scratchpad

Persistent key-value store scoped to your identity — use it for working context,
plans, notes, or intermediate state that should survive across sessions.

```bash
forge agent write plan "Step 1: refactor auth\nStep 2: add tests"
forge agent read plan
forge agent list
```

## Attestations

Create supply-chain attestations for changesets:

```bash
forge identity keygen                              # Generate signing key (once)
forge attest provenance                             # SLSA provenance
forge attest review --result approved --body "LGTM" # Code review
forge sbom generate                                 # CycloneDX SBOM
forge verify --slsa L1                              # Verify attestations
```

## Multi-agent collaboration

Spawn agents on dedicated branches with scoped tokens:

```bash
forge collab spawn --task "add user authentication"
forge collab list                       # See all active agents
forge collab review agent/add-user-auth # Review agent's work
forge merge agent/add-user-auth         # Merge into current branch
forge collab complete agent/add-user-auth
```

## Server workflow

```bash
# On server machine
forge serve                    # Starts gRPC + HTTP server (auto-TLS via mkcert)
forge serve --http-addr localhost:8080  # Enable HTTP/JSON gateway

# On client machine
forge clone https://host:50051 myproject
cd myproject
# ... work ...
forge push
forge pull

# HTTP/JSON API (when enabled)
# GET  /api/v1/log          — changeset history
# GET  /api/v1/branches     — list branches
# GET  /api/v1/status        — repo status
# GET  /api/v1/refs          — list refs
# GET  /api/v1/objects/{id}  — fetch object
# GET  /health               — health check
```
"#;
