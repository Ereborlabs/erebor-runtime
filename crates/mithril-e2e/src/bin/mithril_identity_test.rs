use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mithril_e2e::{Error, IdentityTestRunner, Result};

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
    InjectTaskLabelLoss {
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        host_pid: u32,
    },
    PhysicalProbe {
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        cgroup_path: PathBuf,
        #[arg(long)]
        with_kubernetes: bool,
        #[arg(long, required_if_eq("with_kubernetes", "true"))]
        previous_bundle: Option<PathBuf>,
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
        Command::InjectTaskLabelLoss { pin_root, host_pid } => {
            runner.remove_task_label_for_fixture(&pin_root, host_pid)?;
            println!("Mithril task-label loss injection passed");
        }
        Command::PhysicalProbe {
            pin_root,
            lease_path,
            cgroup_path,
            with_kubernetes,
            previous_bundle,
        } => {
            let bundle = if with_kubernetes {
                let previous_bundle = previous_bundle.ok_or_else(|| Error::InvalidInput {
                    path: PathBuf::from("--previous-bundle"),
                    reason: "Kubernetes qualification requires the native identity bundle"
                        .to_owned(),
                    location: snafu::Location::default(),
                })?;
                runner.physical_kubernetes_probe(
                    &cli.output_directory,
                    &previous_bundle,
                    &pin_root,
                    &lease_path,
                )?
            } else {
                runner.physical_probe(
                    &cli.output_directory,
                    &pin_root,
                    &lease_path,
                    &cgroup_path,
                )?
            };
            runner.write_json(
                &cli.output_directory.join("identity-physical-probe.json"),
                &bundle,
            )?;
            println!("Mithril native-identity physical probe passed");
        }
    }
    Ok(())
}
