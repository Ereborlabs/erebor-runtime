use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use erebor_runtime_ipc::transport::MAX_GRPC_MESSAGE_BYTES;
use snafu::ResultExt;

use crate::error::{
    CliError, DaemonClientSnafu, DaemonRuntimeSnafu, InvalidPolicyCommandSnafu,
    WriteSessionOutputSnafu,
};

use super::parse_non_empty_path;

const MAX_POLICY_TEST_REQUEST_BYTES: u64 = (MAX_GRPC_MESSAGE_BYTES - 1024) as u64;

#[derive(Debug, Args)]
pub(super) struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

impl PolicyArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            PolicyCommand::Test(args) => format!(
                "policy test policy={} event={}",
                args.policy.display(),
                args.event.display()
            ),
            PolicyCommand::Package(args) => args.display(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate bounded policy and event fixtures through the local daemon.
    Test(PolicyTestArgs),
    /// Store an immutable daemon-owned policy package revision.
    Package(PolicyPackageArgs),
}

#[derive(Debug, Args)]
struct PolicyTestArgs {
    /// JSON policy fixture uploaded to the daemon for evaluation.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: PathBuf,
    /// Runtime event JSON fixture uploaded to the daemon for evaluation.
    #[arg(long, value_parser = parse_non_empty_path)]
    event: PathBuf,
}

pub(super) struct PolicyCommandOwner<'a> {
    args: &'a PolicyArgs,
    client: &'a DaemonClient,
}

impl<'a> PolicyCommandOwner<'a> {
    pub(super) const fn new(args: &'a PolicyArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            PolicyCommand::Test(args) => PolicyTestCommand::new(args, self.client).execute(),
            PolicyCommand::Package(args) => {
                PolicyPackageCommandOwner::new(args, self.client).execute()
            }
        }
    }
}

#[derive(Debug, Args)]
struct PolicyPackageArgs {
    #[command(subcommand)]
    command: PolicyPackageCommand,
}

impl PolicyPackageArgs {
    fn display(&self) -> String {
        match &self.command {
            PolicyPackageCommand::Apply(args) => {
                format!(
                    "policy package apply {} --name {}",
                    args.path.display(),
                    args.name
                )
            }
            PolicyPackageCommand::Ls => String::from("policy package ls"),
            PolicyPackageCommand::Inspect(args) => format!("policy package inspect {}", args.name),
            PolicyPackageCommand::Verify(args) => format!("policy package verify {}", args.name),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicyPackageCommand {
    /// Validate a package directory through the daemon's descriptor broker.
    Apply(PolicyPackageApplyArgs),
    /// List policy packages visible to the caller's daemon namespace.
    Ls,
    /// Show one immutable PolicyPackage selected by name.
    Inspect(PolicyPackageNameArgs),
    /// Re-read and validate one immutable PolicyPackage selected by name.
    Verify(PolicyPackageNameArgs),
}

#[derive(Debug, Args)]
struct PolicyPackageApplyArgs {
    #[arg(value_parser = parse_non_empty_path)]
    path: PathBuf,
    /// Immutable owner-scoped name for the PolicyPackage resource.
    #[arg(long, value_parser = super::parse_non_empty_string)]
    name: String,
    #[arg(long, value_parser = super::parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct PolicyPackageNameArgs {
    #[arg(value_parser = super::parse_non_empty_string)]
    name: String,
}

struct PolicyPackageCommandOwner<'a> {
    args: &'a PolicyPackageArgs,
    client: &'a DaemonClient,
}

impl<'a> PolicyPackageCommandOwner<'a> {
    const fn new(args: &'a PolicyPackageArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        match &self.args.command {
            PolicyPackageCommand::Apply(args) => {
                let record = runtime
                    .block_on(self.client.policy_package_apply(
                        args.path.display().to_string(),
                        &args.name,
                        &args.idempotency_key,
                    ))
                    .context(DaemonClientSnafu)?;
                println!("policyPackage={}", record.name);
                Ok(())
            }
            PolicyPackageCommand::Ls => {
                let page = runtime
                    .block_on(self.client.policy_package_list())
                    .context(DaemonClientSnafu)?;
                for record in page.packages {
                    println!("policyPackage={}", record.name);
                }
                Ok(())
            }
            PolicyPackageCommand::Inspect(args) => {
                let record = runtime
                    .block_on(self.client.policy_package_inspect(&args.name))
                    .context(DaemonClientSnafu)?;
                println!("policyPackage={}", record.name);
                Ok(())
            }
            PolicyPackageCommand::Verify(args) => {
                let record = runtime
                    .block_on(self.client.policy_package_verify(&args.name))
                    .context(DaemonClientSnafu)?;
                println!("verified policyPackage={}", record.name);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct PolicySetArgs {
    #[command(subcommand)]
    command: PolicySetSubcommand,
}

impl PolicySetArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            PolicySetSubcommand::Create(_) => String::from("policyset create"),
            PolicySetSubcommand::Ls => String::from("policyset ls"),
            PolicySetSubcommand::Inspect(args) => format!("policyset inspect {}", args.name),
            PolicySetSubcommand::Verify(args) => format!("policyset verify {}", args.name),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicySetSubcommand {
    /// Create one named, immutable ordered composition of PolicyPackages.
    Create(PolicySetCreateArgs),
    /// List named immutable PolicySets visible to the caller.
    Ls,
    /// Show one immutable PolicySet selected by name.
    Inspect(PolicySetNameArgs),
    /// Re-read and validate one immutable PolicySet selected by name.
    Verify(PolicySetNameArgs),
}

#[derive(Debug, Args)]
struct PolicySetCreateArgs {
    /// Immutable owner-scoped name for the new PolicySet.
    #[arg(long, value_parser = super::parse_non_empty_string)]
    name: String,
    /// Ordered PolicyPackage name. Supply once for each package in the composition.
    #[arg(
        long = "package",
        required = true,
        value_parser = super::parse_non_empty_string
    )]
    package_names: Vec<String>,
    /// Stable key reused only after an uncertain create result.
    #[arg(long, value_parser = super::parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct PolicySetNameArgs {
    #[arg(value_parser = super::parse_non_empty_string)]
    name: String,
}

pub(super) struct PolicySetCommandOwner<'a> {
    args: &'a PolicySetArgs,
    client: &'a DaemonClient,
}

impl<'a> PolicySetCommandOwner<'a> {
    pub(super) const fn new(args: &'a PolicySetArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        match &self.args.command {
            PolicySetSubcommand::Create(args) => {
                let record = runtime
                    .block_on(self.client.policy_set_create(
                        &args.name,
                        args.package_names.clone(),
                        &args.idempotency_key,
                    ))
                    .context(DaemonClientSnafu)?;
                println!("policySet={}", record.name);
                Ok(())
            }
            PolicySetSubcommand::Ls => {
                let page = runtime
                    .block_on(self.client.policy_set_list())
                    .context(DaemonClientSnafu)?;
                for record in page.policy_sets {
                    println!("policySet={}", record.name);
                }
                Ok(())
            }
            PolicySetSubcommand::Inspect(args) => {
                let record = runtime
                    .block_on(self.client.policy_set_inspect(&args.name))
                    .context(DaemonClientSnafu)?;
                println!("policySet={}", record.name);
                Ok(())
            }
            PolicySetSubcommand::Verify(args) => {
                let record = runtime
                    .block_on(self.client.policy_set_verify(&args.name))
                    .context(DaemonClientSnafu)?;
                println!("verified policySet={}", record.name);
                Ok(())
            }
        }
    }
}

struct PolicyTestCommand<'a> {
    args: &'a PolicyTestArgs,
    client: &'a DaemonClient,
}

impl<'a> PolicyTestCommand<'a> {
    const fn new(args: &'a PolicyTestArgs, client: &'a DaemonClient) -> Self {
        Self { args, client }
    }

    fn execute(&self) -> Result<(), CliError> {
        let policy_json =
            Self::read_bounded(&self.args.policy, true, MAX_POLICY_TEST_REQUEST_BYTES)?;
        let remaining = MAX_POLICY_TEST_REQUEST_BYTES.saturating_sub(policy_json.len() as u64);
        let event_json = Self::read_bounded(&self.args.event, false, remaining)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let response = runtime
            .block_on(self.client.policy_test(policy_json, event_json))
            .context(DaemonClientSnafu)?;
        let mut output = std::io::stdout().lock();
        output
            .write_all(&response.decision_json)
            .context(WriteSessionOutputSnafu)?;
        writeln!(output).context(WriteSessionOutputSnafu)
    }

    fn read_bounded(path: &PathBuf, policy: bool, maximum_bytes: u64) -> Result<Vec<u8>, CliError> {
        let metadata =
            std::fs::metadata(path).map_err(|source| input_read_error(path, policy, source))?;
        if metadata.len() > maximum_bytes {
            return InvalidPolicyCommandSnafu {
                reason: format!(
                    "{} `{}` exceeds the remaining {}-byte policy-test request bound",
                    if policy { "policy" } else { "event" },
                    path.display(),
                    maximum_bytes,
                ),
            }
            .fail();
        }
        let mut file = File::open(path).map_err(|source| input_read_error(path, policy, source))?;
        let mut source = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut source)
            .map_err(|source| input_read_error(path, policy, source))?;
        if source.len() as u64 > maximum_bytes {
            return InvalidPolicyCommandSnafu {
                reason: format!(
                    "{} `{}` changed while it was read and exceeds the remaining {}-byte policy-test request bound",
                    if policy { "policy" } else { "event" },
                    path.display(),
                    maximum_bytes,
                ),
            }
            .fail();
        }
        Ok(source)
    }
}

fn input_read_error(path: &Path, policy: bool, source: std::io::Error) -> CliError {
    if policy {
        CliError::ReadPolicy {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }
    } else {
        CliError::ReadEvent {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }
    }
}
