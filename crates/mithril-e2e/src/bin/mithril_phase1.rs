use std::path::PathBuf;

use clap::Parser;
use mithril_e2e::{Phase1Runner, Result};

#[derive(Parser)]
#[command(about = "Run the privileged Mithril Phase 1 host lifecycle check")]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    #[arg(long)]
    output_directory: PathBuf,
    #[arg(long)]
    pin_root: PathBuf,
    #[arg(long)]
    lease_path: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let runner = Phase1Runner::new(cli.repo_root);
    let bundle = runner.host_lifecycle(&cli.output_directory, &cli.pin_root, &cli.lease_path)?;
    runner.write_json(
        &cli.output_directory.join("phase1-host-lifecycle.json"),
        &bundle,
    )?;
    println!("Mithril Phase 1 host lifecycle completed successfully");
    Ok(())
}
