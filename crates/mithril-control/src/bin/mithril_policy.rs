use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mithril_control::{
    policy_custom_resource, HardSafetyConditionV1, PolicyArtifactOwner, PolicyDocumentV1,
    PolicySignerTrustV1, TrustGenerationV1,
};

#[derive(Parser)]
#[command(about = "Compile, verify, and simulate Mithril observe policy candidates")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    PrintCrd {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    PrintPolicyManifest {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    PrintTrustGeneration {
        #[arg(long)]
        signing_key_id: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        issuer_epoch: u64,
        #[arg(long, default_value_t = 1)]
        generation: u64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PolicyArtifactOwner::default();
    match Cli::parse().command {
        Command::PrintCrd { output } => {
            // The checked-in Helm CRD is generated from this Rust schema to keep one schema owner.
            let crd = mithril_control::policy_custom_resource_definition()?;
            write_json(output, &crd)?;
        }
        Command::PrintPolicyManifest {
            source,
            name,
            namespace,
            output,
        } => {
            let bytes = std::fs::read(&source)?;
            let document = PolicyDocumentV1::parse(&source, &bytes)?;
            write_json(
                output,
                &policy_custom_resource(&name, &namespace, document)?,
            )?;
        }
        Command::PrintTrustGeneration {
            signing_key_id,
            public_key,
            issuer_epoch,
            generation,
            output,
        } => {
            let public_key = std::fs::read_to_string(public_key)?.trim().to_owned();
            if signing_key_id.is_empty()
                || generation == 0
                || issuer_epoch == 0
                || public_key.len() != 64
                || !public_key
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("the trust generation inputs are invalid".into());
            }
            let trust = TrustGenerationV1 {
                generation,
                bundle_digest: String::new(),
                policy_issuer_sequence_epoch: issuer_epoch,
                policy_signers: vec![PolicySignerTrustV1 {
                    signing_key_id,
                    ed25519_public_key_hex: public_key,
                    revoked: false,
                }],
            }
            .with_computed_bundle_digest();
            write_json(output, &trust)?;
        }
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

fn write_json(
    output: Option<PathBuf>,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let document = format!("{}\n", serde_json::to_string_pretty(value)?);
    if let Some(output) = output {
        std::fs::write(output, document)?;
    } else {
        print!("{document}");
    }
    Ok(())
}
