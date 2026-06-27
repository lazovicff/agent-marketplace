mod commands;
mod utils;

use clap::Parser;

/// Agent Marketplace CLI — manage agents, tasks, schemas, and proofs.
#[derive(Parser)]
#[command(name = "amp", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser)]
enum Commands {
    /// Deploy an agent to EigenCloud.
    Deploy(commands::deploy::DeployArgs),
    /// Register the agent in the on-chain Agent Registry.
    Register(commands::register::RegisterArgs),
    /// Submit a zkTLS proof for a task.
    SubmitProof(commands::submit_proof::SubmitProofArgs),
    /// Create a new zkTLS schema.
    CreateSchema(commands::create_schema::CreateSchemaArgs),
    /// Check agent registration status.
    Status(commands::status::StatusArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Deploy(args) => commands::deploy::run(args).await,
        Commands::Register(args) => commands::register::run(args).await,
        Commands::SubmitProof(args) => commands::submit_proof::run(args).await,
        Commands::CreateSchema(args) => commands::create_schema::run(args).await,
        Commands::Status(args) => commands::status::run(args).await,
    }
}
