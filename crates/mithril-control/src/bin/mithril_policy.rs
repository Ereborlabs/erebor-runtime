use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use mithril_control::{
    policy_custom_resource, HardSafetyConditionV1, NodeDecommissionAuthorizationV1,
    PolicyArtifactOwner, PolicySignerTrustV1, SignedNodeDecommissionV1, TrustGenerationV1,
    WorkloadProtectionPolicySpec,
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
        kind: CrdKindArg,
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
    SealNodeDecommission {
        #[arg(long)]
        cluster_uid: String,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        node_boot_id: String,
        #[arg(long)]
        expires_at_utc_ns: i64,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        signing_key_id: String,
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

#[derive(Clone, Copy, ValueEnum)]
enum CrdKindArg {
    Policy,
    Exception,
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
        Command::PrintCrd { kind, output } => {
            // The checked-in Helm CRD is generated from this Rust schema to keep one schema owner.
            let crd = match kind {
                CrdKindArg::Policy => mithril_control::policy_custom_resource_definition()?,
                CrdKindArg::Exception => mithril_control::exception_custom_resource_definition()?,
            };
            write_json(output, &crd)?;
        }
        Command::PrintPolicyManifest {
            source,
            name,
            namespace,
            output,
        } => {
            let bytes = std::fs::read(&source)?;
            let spec = WorkloadProtectionPolicySpec::parse(&source, &bytes)?;
            write_json(output, &policy_custom_resource(&name, &namespace, spec)?)?;
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
        Command::SealNodeDecommission {
            cluster_uid,
            node_id,
            node_boot_id,
            expires_at_utc_ns,
            nonce,
            signing_key_id,
            signing_key,
            output,
        } => {
            let authorization = NodeDecommissionAuthorizationV1::new(
                &cluster_uid,
                node_id,
                &node_boot_id,
                expires_at_utc_ns,
                &nonce,
            )?;
            let key = SigningKey::from_bytes(&read_signing_key(&signing_key)?);
            let artifact = SignedNodeDecommissionV1::sign(&authorization, signing_key_id, &key)?;
            std::fs::write(output, artifact.to_bytes()?)?;
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

fn read_signing_key(path: &std::path::Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() == 32 {
        return Ok(bytes
            .try_into()
            .map_err(|_| "signing key is not 32 bytes")?);
    }
    let text = std::str::from_utf8(&bytes)?.trim();
    let decoded = hex::decode(text)?;
    decoded
        .try_into()
        .map_err(|_| "signing key must be 32 raw bytes or 64 lowercase hex characters".into())
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
