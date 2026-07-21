use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use snafu::ResultExt;

use crate::error::{
    CliError, DaemonClientSnafu, DaemonRuntimeSnafu, InvalidPolicyCommandSnafu,
    WriteSessionOutputSnafu,
};

use super::parse_non_empty_path;

const MAX_POLICY_TEST_INPUT_BYTES: u64 = 1024 * 1024;

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
            PolicyCommand::Set(args) => args.display(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate bounded policy and event fixtures through the local daemon.
    Test(PolicyTestArgs),
    /// Store an immutable daemon-owned policy package revision.
    Package(PolicyPackageArgs),
    /// Store an immutable composition of existing policy-package revisions.
    Set(PolicySetArgs),
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
}

impl<'a> PolicyCommandOwner<'a> {
    pub(super) const fn new(args: &'a PolicyArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            PolicyCommand::Test(args) => PolicyTestCommand::new(args).execute(),
            PolicyCommand::Package(args) => PolicyPackageCommandOwner::new(args).execute(),
            PolicyCommand::Set(args) => PolicySetCommandOwner::new(args).execute(),
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
                format!("policy package apply {}", args.path.display())
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicyPackageCommand {
    /// Validate a package directory through the daemon's descriptor broker.
    Apply(PolicyPackageApplyArgs),
}

#[derive(Debug, Args)]
struct PolicyPackageApplyArgs {
    #[arg(value_parser = parse_non_empty_path)]
    path: PathBuf,
    #[arg(long, value_parser = super::parse_non_empty_string)]
    idempotency_key: String,
}

struct PolicyPackageCommandOwner<'a> {
    args: &'a PolicyPackageArgs,
}

impl<'a> PolicyPackageCommandOwner<'a> {
    const fn new(args: &'a PolicyPackageArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        let PolicyPackageCommand::Apply(args) = &self.args.command;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let record = runtime
            .block_on(
                DaemonClient::local()
                    .policy_package_apply(args.path.display().to_string(), &args.idempotency_key),
            )
            .context(DaemonClientSnafu)?;
        println!("digest={} name={}", record.digest, record.name);
        Ok(())
    }
}

#[derive(Debug, Args)]
struct PolicySetArgs {
    #[command(subcommand)]
    command: PolicySetSubcommand,
}

impl PolicySetArgs {
    fn display(&self) -> String {
        String::from("policy set create")
    }
}

#[derive(Debug, Subcommand)]
enum PolicySetSubcommand {
    /// Compose root, package, and optional local policy revisions by exact digest.
    Create(PolicySetCreateArgs),
}

#[derive(Debug, Args)]
struct PolicySetCreateArgs {
    #[arg(long, value_parser = super::parse_non_empty_string)]
    root_minimum_digest: String,
    #[arg(long = "package", value_parser = super::parse_non_empty_string)]
    package_minimum_digests: Vec<String>,
    #[arg(long, value_parser = super::parse_non_empty_string)]
    local_override_digest: Option<String>,
    #[arg(long, value_parser = super::parse_non_empty_string)]
    idempotency_key: String,
}

struct PolicySetCommandOwner<'a> {
    args: &'a PolicySetArgs,
}

impl<'a> PolicySetCommandOwner<'a> {
    const fn new(args: &'a PolicySetArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        let PolicySetSubcommand::Create(args) = &self.args.command;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let record = runtime
            .block_on(DaemonClient::local().policy_set_create(
                &args.root_minimum_digest,
                args.package_minimum_digests.clone(),
                args.local_override_digest.clone(),
                &args.idempotency_key,
            ))
            .context(DaemonClientSnafu)?;
        println!("digest={}", record.digest);
        Ok(())
    }
}

struct PolicyTestCommand<'a> {
    args: &'a PolicyTestArgs,
}

impl<'a> PolicyTestCommand<'a> {
    const fn new(args: &'a PolicyTestArgs) -> Self {
        Self { args }
    }

    fn execute(&self) -> Result<(), CliError> {
        let policy_json = Self::read_bounded(&self.args.policy, true)?;
        let event_json = Self::read_bounded(&self.args.event, false)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        let response = runtime
            .block_on(DaemonClient::local().policy_test(policy_json, event_json))
            .context(DaemonClientSnafu)?;
        let mut output = std::io::stdout().lock();
        output
            .write_all(&response.decision_json)
            .context(WriteSessionOutputSnafu)?;
        writeln!(output).context(WriteSessionOutputSnafu)
    }

    fn read_bounded(path: &PathBuf, policy: bool) -> Result<Vec<u8>, CliError> {
        let metadata =
            std::fs::metadata(path).map_err(|source| input_read_error(path, policy, source))?;
        if metadata.len() > MAX_POLICY_TEST_INPUT_BYTES {
            return InvalidPolicyCommandSnafu {
                reason: format!(
                    "{} `{}` exceeds the {}-byte upload bound",
                    if policy { "policy" } else { "event" },
                    path.display(),
                    MAX_POLICY_TEST_INPUT_BYTES,
                ),
            }
            .fail();
        }
        let mut file = File::open(path).map_err(|source| input_read_error(path, policy, source))?;
        let mut source = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(MAX_POLICY_TEST_INPUT_BYTES + 1)
            .read_to_end(&mut source)
            .map_err(|source| input_read_error(path, policy, source))?;
        if source.len() as u64 > MAX_POLICY_TEST_INPUT_BYTES {
            return InvalidPolicyCommandSnafu {
                reason: format!(
                    "{} `{}` changed while it was read and exceeds the {}-byte upload bound",
                    if policy { "policy" } else { "event" },
                    path.display(),
                    MAX_POLICY_TEST_INPUT_BYTES,
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
