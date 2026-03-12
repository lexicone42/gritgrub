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
        /// Object ID (hex prefix, at least 8 chars)
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
    }
}
