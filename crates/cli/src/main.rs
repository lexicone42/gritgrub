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

    /// List or create branches
    Branch {
        /// Branch name to create (omit to list)
        name: Option<String>,
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

    /// Start the gRPC server
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "[::1]:50051")]
        addr: String,
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
        Commands::Log { count } => commands::log::run(count),
        Commands::Status => commands::status::run(),
        Commands::ImportGit => commands::import_git::run(),
        Commands::Cat { id } => commands::cat::run(&id),
        Commands::Diff { from, to } => {
            commands::diff::run(from.as_deref(), to.as_deref())
        }
        Commands::Show { id } => commands::show::run(id.as_deref()),
        Commands::Branch { name } => commands::branch::run(name.as_deref()),
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
        },
        Commands::Agent { action } => match action {
            AgentAction::Write { key, value, file } => {
                commands::agent::write(&key, value.as_deref(), file.as_deref())
            }
            AgentAction::Read { key } => commands::agent::read(&key),
            AgentAction::List => commands::agent::list(),
        },
        Commands::ExportGit => commands::export_git::run(),
        Commands::Serve { addr } => commands::serve::run(&addr),
    }
}
