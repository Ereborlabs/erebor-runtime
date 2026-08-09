use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mithril_e2e::{IdentityTestRunner, Result};

#[derive(Parser)]
#[command(about = "Verify the production Mithril native-identity program")]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    #[arg(long)]
    output_directory: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify,
    PhysicalProbe {
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        cgroup_path: PathBuf,
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
    let runner = IdentityTestRunner::new(cli.repo_root);
    match cli.command {
        Command::Verify => {
            let bundle = runner.verify(&cli.output_directory)?;
            runner.write_json(
                &cli.output_directory.join("identity-verification.json"),
                &bundle,
            )?;
            println!("Mithril native-identity object verification passed");
        }
        Command::PhysicalProbe {
            pin_root,
            lease_path,
            cgroup_path,
        } => {
            let bundle = runner.physical_probe(
                &cli.output_directory,
                &pin_root,
                &lease_path,
                &cgroup_path,
            )?;
            runner.write_json(
                &cli.output_directory.join("identity-physical-probe.json"),
                &bundle,
            )?;
            println!("Mithril native-identity physical probe passed");
        }
    }
    Ok(())
}
