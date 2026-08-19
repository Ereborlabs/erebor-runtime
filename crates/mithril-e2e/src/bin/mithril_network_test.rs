use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mithril_e2e::{run_effect_child, NetworkTestRunner, Result};

#[derive(Parser)]
#[command(name = "mithril-network-test")]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    PhysicalProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        cgroup_path: PathBuf,
    },
    #[command(hide = true)]
    Child {
        #[arg(long)]
        fixture_root: PathBuf,
        #[arg(long)]
        mailbox_path: PathBuf,
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
    match cli.command {
        Command::PhysicalProbe {
            output_directory,
            pin_root,
            lease_path,
            cgroup_path,
        } => {
            let runner = NetworkTestRunner::new(cli.repo_root);
            let bundle =
                runner.physical_probe(&output_directory, &pin_root, &lease_path, &cgroup_path)?;
            runner.write_json(
                &output_directory.join("network-physical-probe.json"),
                &bundle,
            )?;
            println!("Mithril network physical probe passed");
            Ok(())
        }
        Command::Child {
            fixture_root,
            mailbox_path,
        } => run_effect_child(&fixture_root, &mailbox_path),
    }
}
