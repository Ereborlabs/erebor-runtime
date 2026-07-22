use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand};
use erebor_runtime_client::DaemonClient;
use erebor_runtime_ipc::MAX_PAYLOAD_LEN;
use snafu::ResultExt;

use crate::error::{
    CliError, DaemonClientSnafu, DaemonRuntimeSnafu, InvalidPolicyCommandSnafu,
    WriteSessionOutputSnafu,
};

use super::parse_non_empty_path;

const MAX_POLICY_TEST_REQUEST_BYTES: u64 = (MAX_PAYLOAD_LEN - 1024) as u64;

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
            PolicyPackageCommand::Ls => String::from("policy package ls"),
            PolicyPackageCommand::Inspect(args) => {
                format!("policy package inspect {}", args.digest)
            }
            PolicyPackageCommand::Verify(args) => format!("policy package verify {}", args.digest),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicyPackageCommand {
    /// Validate a package directory through the daemon's descriptor broker.
    Apply(PolicyPackageApplyArgs),
    /// List policy packages visible to the caller's daemon namespace.
    Ls,
    /// Show one immutable policy package selected by digest.
    Inspect(PolicyPackageDigestArgs),
    /// Re-read and validate one immutable policy package selected by digest.
    Verify(PolicyPackageDigestArgs),
}

#[derive(Debug, Args)]
struct PolicyPackageApplyArgs {
    #[arg(value_parser = parse_non_empty_path)]
    path: PathBuf,
    #[arg(long, value_parser = super::parse_non_empty_string)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct PolicyPackageDigestArgs {
    #[arg(value_parser = super::parse_non_empty_string)]
    digest: String,
}

struct PolicyPackageCommandOwner<'a> {
    args: &'a PolicyPackageArgs,
}

impl<'a> PolicyPackageCommandOwner<'a> {
    const fn new(args: &'a PolicyPackageArgs) -> Self {
        Self { args }
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
                    .block_on(DaemonClient::local().policy_package_apply(
                        args.path.display().to_string(),
                        &args.idempotency_key,
                    ))
                    .context(DaemonClientSnafu)?;
                println!("digest={} name={}", record.digest, record.name);
                Ok(())
            }
            PolicyPackageCommand::Ls => {
                let page = runtime
                    .block_on(DaemonClient::local().policy_package_list())
                    .context(DaemonClientSnafu)?;
                for record in page.packages {
                    println!("digest={} name={}", record.digest, record.name);
                }
                Ok(())
            }
            PolicyPackageCommand::Inspect(args) => {
                let record = runtime
                    .block_on(DaemonClient::local().policy_package_inspect(&args.digest))
                    .context(DaemonClientSnafu)?;
                println!("digest={} name={}", record.digest, record.name);
                Ok(())
            }
            PolicyPackageCommand::Verify(args) => {
                let record = runtime
                    .block_on(DaemonClient::local().policy_package_verify(&args.digest))
                    .context(DaemonClientSnafu)?;
                println!("verified digest={} name={}", record.digest, record.name);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Args)]
struct PolicySetArgs {
    #[command(subcommand)]
    command: PolicySetSubcommand,
}

impl PolicySetArgs {
    fn display(&self) -> String {
        match &self.command {
            PolicySetSubcommand::Create(_) => String::from("policy set create"),
            PolicySetSubcommand::Alias(args) => {
                format!("policy set alias {} {}", args.alias, args.policy_set_digest)
            }
            PolicySetSubcommand::Ls => String::from("policy set ls"),
            PolicySetSubcommand::Inspect(args) => format!("policy set inspect {}", args.digest),
            PolicySetSubcommand::Verify(args) => format!("policy set verify {}", args.digest),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicySetSubcommand {
    /// Compose root, package, and optional local policy revisions by exact digest.
    Create(PolicySetCreateArgs),
    /// Bind a caller-local policy-set alias to one immutable revision.
    Alias(PolicySetAliasArgs),
    /// List immutable policy-set revisions visible to the caller.
    Ls,
    /// Show one immutable policy-set revision selected by digest.
    Inspect(PolicySetDigestArgs),
    /// Re-read and validate one immutable policy-set revision selected by digest.
    Verify(PolicySetDigestArgs),
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

#[derive(Debug, Args)]
struct PolicySetDigestArgs {
    #[arg(value_parser = super::parse_non_empty_string)]
    digest: String,
}

#[derive(Debug, Args)]
struct PolicySetAliasArgs {
    #[arg(value_parser = super::parse_non_empty_string)]
    alias: String,
    #[arg(value_parser = super::parse_non_empty_string)]
    policy_set_digest: String,
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(DaemonRuntimeSnafu)?;
        match &self.args.command {
            PolicySetSubcommand::Create(args) => {
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
            PolicySetSubcommand::Alias(args) => {
                let record = runtime
                    .block_on(DaemonClient::local().policy_set_alias_set(
                        &args.alias,
                        &args.policy_set_digest,
                        &args.idempotency_key,
                    ))
                    .context(DaemonClientSnafu)?;
                println!(
                    "alias={} policy_set_digest={}",
                    record.alias, record.policy_set_digest
                );
                Ok(())
            }
            PolicySetSubcommand::Ls => {
                let page = runtime
                    .block_on(DaemonClient::local().policy_set_list())
                    .context(DaemonClientSnafu)?;
                for record in page.policy_sets {
                    println!("digest={}", record.digest);
                }
                Ok(())
            }
            PolicySetSubcommand::Inspect(args) => {
                let record = runtime
                    .block_on(DaemonClient::local().policy_set_inspect(&args.digest))
                    .context(DaemonClientSnafu)?;
                println!("digest={}", record.digest);
                Ok(())
            }
            PolicySetSubcommand::Verify(args) => {
                let record = runtime
                    .block_on(DaemonClient::local().policy_set_verify(&args.digest))
                    .context(DaemonClientSnafu)?;
                println!("verified digest={}", record.digest);
                Ok(())
            }
        }
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
            .block_on(DaemonClient::local().policy_test(policy_json, event_json))
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
