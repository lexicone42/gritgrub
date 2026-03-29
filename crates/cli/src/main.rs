use clap::{Parser, Subcommand};
use anyhow::Result;

mod commands;

#[derive(Parser)]
#[command(name = "forge", about = "gritgrub — version control for humans and agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new forge repository
    Init {
        /// Set the author name (defaults to $USER)
        #[arg(long)]
        name: Option<String>,
    },

    /// Create a changeset from the current working directory
    Commit {
        /// Changeset message
        #[arg(short, long)]
        message: String,

        /// Intent kind: feature, bugfix, refactor, agent-task, exploration, dep, docs
        #[arg(long)]
        intent: Option<String>,

        /// Why this change was made (requires --intent)
        #[arg(long)]
        rationale: Option<String>,
    },

    /// Show changeset history
    Log {
        /// Maximum entries to show
        #[arg(short = 'n', long, default_value = "10")]
        count: usize,
        /// Show ASCII branch graph
        #[arg(long)]
        graph: bool,
        /// One-line compact format
        #[arg(long)]
        oneline: bool,
    },

    /// Show working directory status
    Status,

    /// Import git history into forge
    ImportGit,

    /// Inspect a stored object
    Cat {
        /// Object ID (hex prefix)
        id: String,
    },

    /// Show differences between changesets or against the working tree
    Diff {
        /// First changeset (or omit for HEAD vs working tree)
        from: Option<String>,
        /// Second changeset (or omit to diff against parent)
        to: Option<String>,
    },

    /// Show a changeset with its diff (like git show)
    Show {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
    },

    /// List, create, or delete branches
    Branch {
        /// Branch name to create or delete (omit to list)
        name: Option<String>,
        /// Delete the named branch
        #[arg(short = 'd', long)]
        delete: bool,
    },

    /// Switch branches or detach HEAD at a changeset
    Checkout {
        /// Branch name or changeset ID prefix
        target: String,
        /// Create a new branch and switch to it
        #[arg(short = 'b')]
        create: bool,
    },

    /// Manage identities (humans and agents)
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// Agent scratchpad — persistent working context
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Export forge-native changesets to git
    ExportGit,

    /// Supply-chain attestations (SLSA, in-toto, code review)
    Attest {
        #[command(subcommand)]
        action: AttestAction,
    },

    /// Software Bill of Materials (CycloneDX)
    Sbom {
        #[command(subcommand)]
        action: SbomAction,
    },

    /// Verify attestations and supply-chain policies
    Verify {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
        /// Required SLSA level (L0-L3)
        #[arg(long)]
        slsa: Option<String>,
    },

    /// Stash working tree changes
    Stash {
        #[command(subcommand)]
        action: StashAction,
    },

    /// Reset HEAD to a previous changeset
    Reset {
        /// Changeset ID or prefix
        target: String,
        /// Also update working tree (destructive)
        #[arg(long)]
        hard: bool,
    },

    /// Merge a branch into the current branch
    Merge {
        /// Branch name to merge
        branch: String,
    },

    /// Manage remote repositories
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },

    /// List, create, or delete tags
    Tag {
        /// Tag name (omit to list)
        name: Option<String>,
        /// Delete the named tag
        #[arg(short = 'd', long)]
        delete: bool,
    },

    /// Get or set repository config values
    Config {
        /// Config key (e.g., remote.origin.token)
        key: String,
        /// Value to set (omit to read)
        value: Option<String>,
    },

    /// Push changesets to a remote server
    Push {
        /// Remote name (default: origin)
        remote: Option<String>,
    },

    /// Pull changesets from a remote server
    Pull {
        /// Remote name (default: origin)
        remote: Option<String>,
    },

    /// Clone a remote repository
    Clone {
        /// Remote server URL (e.g., http://[::1]:50051)
        url: String,
        /// Local directory (default: derived from URL)
        path: Option<String>,
    },

    /// Multi-agent collaboration
    Collab {
        #[command(subcommand)]
        action: CollabAction,
    },

    /// Exploration tree — structured parallel search over solution spaces
    Explore {
        #[command(subcommand)]
        action: ExploreAction,
    },

    /// Start the gRPC + HTTP server
    Serve {
        /// Override gRPC listen address
        #[arg(long)]
        addr: Option<String>,
        /// Enable HTTP/JSON gateway on this address (e.g., localhost:8080)
        #[arg(long)]
        http_addr: Option<String>,
        /// Path to server config TOML (default: .forge/server.toml)
        #[arg(long)]
        config: Option<String>,
        /// Write a default config file and exit
        #[arg(long)]
        init_config: bool,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// List all identities
    List,
    /// Create a new identity
    Create {
        /// Display name
        #[arg(long)]
        name: String,
        /// Kind: human or agent
        #[arg(long, default_value = "human")]
        kind: String,
        /// Agent runtime (e.g., claude-code, custom-bot)
        #[arg(long)]
        runtime: Option<String>,
    },
    /// Show identity details
    Show {
        /// Identity UUID
        id: String,
    },
    /// Set as the active identity for commits
    Use {
        /// Identity UUID
        id: String,
    },
    /// Generate a signing keypair for an identity
    Keygen {
        /// Identity UUID (defaults to active identity)
        id: Option<String>,
    },
    /// Generate a bearer token for gRPC auth
    Token {
        /// Identity UUID (defaults to active identity)
        id: Option<String>,
        /// Token expiry in hours (0 = no expiry)
        #[arg(long, default_value = "24")]
        expiry_hours: u64,
        /// Comma-separated scopes (default: * = admin). Options: read, write, attest, identity, ref:<pattern>
        #[arg(long, default_value = "*")]
        scope: String,
    },
    /// Grant capabilities to an identity
    Grant {
        /// Identity UUID
        id: String,
        /// Permission scope: global, read, write, admin
        #[arg(long, default_value = "global")]
        scope: String,
        /// Permission level: r, rw, rwcd, admin
        #[arg(long, default_value = "rw")]
        permissions: String,
    },
    /// Show capabilities for an identity
    Capabilities {
        /// Identity UUID (defaults to active identity)
        id: Option<String>,
    },
    /// Revoke a bearer token
    Revoke {
        /// Token to revoke (or pipe via stdin)
        token: String,
    },
}

#[derive(Subcommand)]
enum AttestAction {
    /// Create a SLSA provenance attestation
    Provenance {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
    },
    /// Create a code review attestation
    Review {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
        /// Review result: approved, request-changes, comment
        #[arg(long, default_value = "approved")]
        result: String,
        /// Review comment
        #[arg(short, long, default_value = "")]
        body: String,
    },
    /// List attestations for a changeset
    List {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum SbomAction {
    /// Generate a CycloneDX SBOM from Cargo.lock
    Generate {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
    },
    /// Show the SBOM for a changeset
    Show {
        /// Changeset ID (defaults to HEAD)
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum RemoteAction {
    /// Add a remote
    Add {
        /// Remote name
        name: String,
        /// Remote URL (gRPC address)
        url: String,
    },
    /// Remove a remote
    Remove {
        /// Remote name
        name: String,
    },
    /// List configured remotes
    List,
}

#[derive(Subcommand)]
enum StashAction {
    /// Save working directory changes
    Save {
        /// Optional message
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Apply and remove the latest stash
    Pop,
    /// List stash entries
    List,
}

#[derive(Subcommand)]
enum CollabAction {
    /// Spawn an agent on a new branch with a task
    Spawn {
        /// Task description
        #[arg(long)]
        task: String,
        /// Branch name (auto-generated if omitted)
        #[arg(long)]
        branch: Option<String>,
        /// Agent runtime (default: claude-code)
        #[arg(long)]
        runtime: Option<String>,
    },
    /// List active agent collaborations
    List,
    /// Review an agent's work
    Review {
        /// Branch name to review
        branch: String,
    },
    /// Mark a collaboration as completed
    Complete {
        /// Branch name
        branch: String,
    },
}

#[derive(Subcommand)]
enum ExploreAction {
    /// Create a new exploration goal
    Create {
        /// What are we trying to achieve?
        description: String,
        /// Target branch to merge the winner into (default: main)
        #[arg(long, default_value = "main")]
        target: String,
        /// Maximum concurrent approaches (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_approaches: u32,
        /// Time budget in seconds (0 = unlimited)
        #[arg(long, default_value = "0")]
        time_budget: u64,
        /// Constraints (repeatable): "tests:all tests must pass", "lint:no warnings"
        #[arg(long, short)]
        constraint: Vec<String>,
    },
    /// Create a new approach for a goal
    Approach {
        /// Goal ID prefix
        goal: String,
        /// Approach name
        #[arg(long)]
        name: String,
    },
    /// List all active exploration goals
    List,
    /// Show detailed status of a goal
    Show {
        /// Goal ID prefix
        goal: String,
    },
    /// Promote the winning approach into the target branch
    Promote {
        /// Goal ID prefix
        goal: String,
        /// Approach name to promote
        #[arg(long)]
        approach: String,
    },
    /// Abandon a goal and clean up refs
    Abandon {
        /// Goal ID prefix
        goal: String,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Write a scratchpad entry
    Write {
        /// Key name
        key: String,
        /// Value (or use --file, or pipe via stdin)
        value: Option<String>,
        /// Read value from file
        #[arg(long)]
        file: Option<String>,
    },
    /// Read a scratchpad entry
    Read {
        /// Key name
        key: String,
    },
    /// List all scratchpad entries
    List,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name } => commands::init::run(name.as_deref()),
        Commands::Commit { message, intent, rationale } => {
            commands::commit::run(&message, intent.as_deref(), rationale.as_deref())
        }
        Commands::Log { count, graph, oneline } => commands::log::run(count, graph, oneline),
        Commands::Status => commands::status::run(),
        Commands::ImportGit => commands::import_git::run(),
        Commands::Cat { id } => commands::cat::run(&id),
        Commands::Diff { from, to } => {
            commands::diff::run(from.as_deref(), to.as_deref())
        }
        Commands::Show { id } => commands::show::run(id.as_deref()),
        Commands::Branch { name, delete } => commands::branch::run(name.as_deref(), delete),
        Commands::Checkout { target, create } => {
            commands::checkout::run(&target, create)
        }
        Commands::Identity { action } => match action {
            IdentityAction::List => commands::identity::list(),
            IdentityAction::Create { name, kind, runtime } => {
                commands::identity::create(&name, &kind, runtime.as_deref())
            }
            IdentityAction::Show { id } => commands::identity::show(&id),
            IdentityAction::Use { id } => commands::identity::activate(&id),
            IdentityAction::Keygen { id } => commands::identity::keygen(id.as_deref()),
            IdentityAction::Token { id, expiry_hours, scope } => {
                commands::identity::gen_token(id.as_deref(), expiry_hours, &scope)
            }
            IdentityAction::Grant { id, scope, permissions } => {
                commands::identity::grant(&id, &scope, &permissions)
            }
            IdentityAction::Capabilities { id } => {
                commands::identity::capabilities(id.as_deref())
            }
            IdentityAction::Revoke { token } => {
                commands::identity::revoke_token(&token)
            }
        },
        Commands::Agent { action } => match action {
            AgentAction::Write { key, value, file } => {
                commands::agent::write(&key, value.as_deref(), file.as_deref())
            }
            AgentAction::Read { key } => commands::agent::read(&key),
            AgentAction::List => commands::agent::list(),
        },
        Commands::ExportGit => commands::export_git::run(),
        Commands::Attest { action } => match action {
            AttestAction::Provenance { id } => {
                commands::attest::provenance(id.as_deref())
            }
            AttestAction::Review { id, result, body } => {
                commands::attest::review(id.as_deref(), &result, &body)
            }
            AttestAction::List { id } => {
                commands::attest::list(id.as_deref())
            }
        },
        Commands::Sbom { action } => match action {
            SbomAction::Generate { id } => commands::sbom::generate(id.as_deref()),
            SbomAction::Show { id } => commands::sbom::show(id.as_deref()),
        },
        Commands::Verify { id, slsa } => {
            commands::verify::run(id.as_deref(), slsa.as_deref())
        }
        Commands::Config { key, value } => match value {
            Some(val) => commands::config::set(&key, &val),
            None => commands::config::get(&key),
        },
        Commands::Tag { name, delete } => commands::tag::run(name.as_deref(), delete),
        Commands::Push { remote } => commands::push::run(remote.as_deref()),
        Commands::Pull { remote } => commands::pull::run(remote.as_deref()),
        Commands::Clone { url, path } => commands::clone::run(&url, path.as_deref()),
        Commands::Merge { branch } => commands::merge::run(&branch),
        Commands::Remote { action } => match action {
            RemoteAction::Add { name, url } => commands::remote::add(&name, &url),
            RemoteAction::Remove { name } => commands::remote::remove(&name),
            RemoteAction::List => commands::remote::list(),
        },
        Commands::Collab { action } => match action {
            CollabAction::Spawn { task, branch, runtime } => {
                commands::collab::spawn(&task, branch.as_deref(), runtime.as_deref())
            }
            CollabAction::List => commands::collab::list(),
            CollabAction::Review { branch } => commands::collab::review(&branch),
            CollabAction::Complete { branch } => commands::collab::complete(&branch),
        },
        Commands::Stash { action } => match action {
            StashAction::Save { message } => commands::stash::save(message.as_deref()),
            StashAction::Pop => commands::stash::pop(),
            StashAction::List => commands::stash::list(),
        },
        Commands::Reset { target, hard } => commands::reset::run(&target, hard),
        Commands::Explore { action } => match action {
            ExploreAction::Create { description, target, max_approaches, time_budget, constraint } => {
                commands::explore::create(&description, &target, max_approaches, time_budget, &constraint)
            }
            ExploreAction::Approach { goal, name } => {
                commands::explore::approach(&goal, &name)
            }
            ExploreAction::List => commands::explore::list(),
            ExploreAction::Show { goal } => commands::explore::show(&goal),
            ExploreAction::Promote { goal, approach } => {
                commands::explore::promote(&goal, &approach)
            }
            ExploreAction::Abandon { goal } => commands::explore::abandon(&goal),
        },
        Commands::Serve { addr, http_addr, config, init_config } => {
            commands::serve::run(addr.as_deref(), http_addr.as_deref(), config.as_deref(), init_config)
        }
    }
}
