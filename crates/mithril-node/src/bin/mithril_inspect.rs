use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mithril_node::{NativeIdentityInspector, Result};

#[derive(Parser)]
#[command(about = "Inspect live Mithril node identity without taking ownership")]
struct Cli {
    #[arg(long)]
    pin_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Task {
        #[arg(long)]
        host_pid: u32,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let inspector = NativeIdentityInspector::new(cli.pin_root);
    match cli.command {
        Command::Task { host_pid } => println!("{}", inspector.snapshot_json(host_pid)?),
    }
    Ok(())
}
