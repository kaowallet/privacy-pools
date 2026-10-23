//! Repo automation tasks for the `privacy-pools` workspace.
//!
//! Run via the cargo alias defined in `.cargo/config.toml`:
//!
//! ```text
//! cargo xtask pull-circuits
//! cargo xtask pull-circuits-v2 [--circuits deposit,ragequit,transact_2x2]
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};

mod pull_circuits;
mod pull_circuits_v2;

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Automation tasks for the privacy-pools workspace",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pull the circom circuits + trusted-setup keys from privacy-pools-core,
    /// compile the circuits into circom-witnesscalc graph files, and stage all
    /// artifacts under `crates/privacy-pools/artifacts/`.
    PullCircuits(pull_circuits::Args),
    /// Same for Privacy Pools v2: compile the v2 circuits into graphs and stage
    /// the ceremony keys under `crates/privacy-pools/artifacts/v2/`.
    PullCircuitsV2(pull_circuits_v2::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::PullCircuits(args) => pull_circuits::run(args),
        Command::PullCircuitsV2(args) => pull_circuits_v2::run(args),
    }
}
