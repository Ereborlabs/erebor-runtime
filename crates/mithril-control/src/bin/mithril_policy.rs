use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mithril_control::{HardSafetyConditionV1, PolicyArtifactOwner};

#[derive(Parser)]
#[command(about = "Compile, verify, and simulate Mithril observe policy candidates")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Compile {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        seal_request: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Simulate {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        decision_key: PathBuf,
        #[arg(long)]
        hard_safety_condition: Option<HardSafetyConditionArg>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum HardSafetyConditionArg {
    PriorLsmDenial,
    MissingTaskIdentity,
    CorruptGeneration,
    EmergencyRestriction,
    AmbiguousTopology,
    UnsupportedPhysicalBoundary,
}

impl From<HardSafetyConditionArg> for HardSafetyConditionV1 {
    fn from(value: HardSafetyConditionArg) -> Self {
        match value {
            HardSafetyConditionArg::PriorLsmDenial => Self::PriorLsmDenial,
            HardSafetyConditionArg::MissingTaskIdentity => Self::MissingTaskIdentity,
            HardSafetyConditionArg::CorruptGeneration => Self::CorruptGeneration,
            HardSafetyConditionArg::EmergencyRestriction => Self::EmergencyRestriction,
            HardSafetyConditionArg::AmbiguousTopology => Self::AmbiguousTopology,
            HardSafetyConditionArg::UnsupportedPhysicalBoundary => {
                Self::UnsupportedPhysicalBoundary
            }
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> mithril_control::Result<()> {
    let owner = PolicyArtifactOwner::default();
    match Cli::parse().command {
        Command::Compile {
            source,
            seal_request,
            signing_key,
            output,
        } => {
            let artifact = owner.compile_and_sign(&source, &seal_request, &signing_key, &output)?;
            println!(
                "compiled {} version {} into {} exact cells",
                artifact.header.profile_id,
                artifact.header.profile_version,
                artifact.compiled_profile.compiled_cells.len()
            );
        }
        Command::Verify {
            artifact,
            public_key,
        } => {
            let artifact = owner.load_verified(&artifact, &public_key)?;
            println!(
                "verified {} version {} ({})",
                artifact.header.profile_id,
                artifact.header.profile_version,
                artifact.header.policy_document_digest
            );
        }
        Command::Simulate {
            artifact,
            public_key,
            decision_key,
            hard_safety_condition,
        } => {
            println!(
                "{}",
                owner.simulate_json(
                    &artifact,
                    &public_key,
                    &decision_key,
                    hard_safety_condition.map(Into::into),
                )?
            );
        }
    }
    Ok(())
}
