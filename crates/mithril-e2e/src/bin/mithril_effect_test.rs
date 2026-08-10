use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mithril_e2e::{run_effect_child, EffectTestRunner, Result};

#[derive(Parser)]
#[command(name = "mithril-effect-test")]
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
        #[arg(long, default_value_t = 10_000)]
        measured_opens: u32,
        #[arg(long, default_value_t = 50_000)]
        saturation_opens: u32,
        /// Promote the signed fixture from observation to physical denial.
        #[arg(long)]
        protect: bool,
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
            measured_opens,
            saturation_opens,
            protect,
        } => {
            let runner = EffectTestRunner::new(cli.repo_root);
            let bundle = runner.physical_probe(
                &output_directory,
                &pin_root,
                &lease_path,
                &cgroup_path,
                measured_opens,
                saturation_opens,
                protect,
            )?;
            runner.write_json(
                &output_directory.join("effect-physical-probe.json"),
                &bundle,
            )?;
            println!("Mithril effect physical probe passed");
            Ok(())
        }
        Command::Child {
            fixture_root,
            mailbox_path,
        } => run_effect_child(&fixture_root, &mailbox_path),
    }
}
