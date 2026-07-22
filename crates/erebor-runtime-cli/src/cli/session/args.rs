use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use erebor_runtime_core::SessionRunnerKind;

use super::super::{parse_non_empty_path, parse_non_empty_string};

#[derive(Debug, Args)]
pub(crate) struct SessionArgs {
    #[command(subcommand)]
    pub(crate) command: SessionCommand,
}

/// The public Phase 4 Codex run request. The daemon resolves its local alias
/// to the certified package entrypoint; this command deliberately has no raw
/// executable or argv position.
#[derive(Debug, Args)]
pub(crate) struct CodexRunArgs {
    /// Caller-local `codex` or `codex-app-server` installation alias.
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) alias: String,
    /// Caller-local policy-set alias or immutable policy-set digest.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) policy: String,
    /// Workspace admitted by the daemon under the caller UID. Defaults to the current directory.
    #[arg(long, value_parser = parse_non_empty_path)]
    pub(crate) workspace: Option<PathBuf>,
    #[arg(long, default_value = "terminate", value_parser = parse_failure_mode)]
    pub(crate) failure_mode: String,
    #[arg(long, default_value_t = 2)]
    pub(crate) loss_grace_seconds: u64,
    /// Create and start the session without attaching the client output stream.
    #[arg(short = 'd', long)]
    pub(crate) detached: bool,
}

impl SessionArgs {
    pub(crate) fn display(&self) -> String {
        match &self.command {
            SessionCommand::Create(_) => String::from("session create"),
            SessionCommand::Run(_) => String::from("session run"),
            SessionCommand::Start(args) => format!("session start {}", args.session_id),
            SessionCommand::Ps => String::from("session ps"),
            SessionCommand::Inspect(args) => format!("session inspect {}", args.session_id),
            SessionCommand::Logs(args) => format!("session logs {}", args.session_id),
            SessionCommand::Attach(args) => format!("session attach {}", args.session_id),
            SessionCommand::Events(args) => format!("session events {}", args.session_id),
            SessionCommand::Stop(args) => format!("session stop {}", args.session_id),
            SessionCommand::Kill(args) => format!("session kill {}", args.session_id),
            SessionCommand::Wait(args) => format!("session wait {}", args.session_id),
            SessionCommand::Remove(args) => format!("session rm {}", args.session_id),
            SessionCommand::Prune(_) => String::from("session prune"),
            SessionCommand::Alias(_) => String::from("session alias"),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommand {
    /// Create a daemon-owned generic session without starting its workload.
    Create(GenericSessionCreateArgs),
    /// Create and start a daemon-owned generic session.
    Run(SessionRunArgs),
    /// Start a previously created session.
    Start(SessionMutationArgs),
    /// List your daemon-owned sessions.
    #[command(alias = "ls")]
    Ps,
    /// Inspect one daemon-owned session.
    Inspect(SessionArgsById),
    /// Read bounded durable session output.
    Logs(SessionLogsArgs),
    /// Acquire a read-only or input lease attachment.
    Attach(SessionAttachArgs),
    /// Read bounded durable session lifecycle events.
    Events(SessionEventsArgs),
    /// Request a graceful stop.
    Stop(SessionStopArgs),
    /// Deliver an admitted terminal signal.
    Kill(SessionKillArgs),
    /// Wait for a generation change.
    Wait(SessionWaitArgs),
    /// Remove a terminal session.
    #[command(alias = "rm")]
    Remove(SessionRemoveArgs),
    /// Remove eligible terminal sessions.
    Prune(SessionPruneArgs),
    /// Manage daemon-owned local aliases for your sessions.
    Alias(SessionAliasArgs),
}

#[derive(Debug, Args)]
pub(crate) struct GenericSessionCreateArgs {
    #[command(flatten)]
    pub(crate) request: GenericSessionRequestArgs,
    /// Stable key reused only after an uncertain create result.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionRunArgs {
    #[command(flatten)]
    pub(crate) request: GenericSessionRequestArgs,
    /// Stable key reused only after an uncertain create/start result.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct GenericSessionRequestArgs {
    /// The Phase 3 generic runner. Docker is unavailable until Phase 6.
    #[arg(long, alias = "runtime", value_enum)]
    pub(crate) runner: SessionRunnerArg,
    /// Existing workspace admitted by the daemon under the caller UID.
    #[arg(long, value_parser = parse_non_empty_path)]
    pub(crate) workspace: PathBuf,
    /// Exact installed agent-package canonical digest. Omit all identity flags to use the
    /// daemon-installed generic package and host-minimum policy.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) package_digest: Option<String>,
    /// Exact caller-owned installation canonical digest. Supply with every other identity flag.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) installation_digest: Option<String>,
    /// Exact generic adapter canonical digest selected by the package. Supply with every other
    /// identity flag.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) adapter_digest: Option<String>,
    /// Exact caller-owned immutable policy-set digest. Supply with every other identity flag.
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) policy_set_digest: Option<String>,
    /// Failure contract for daemon loss.
    #[arg(long, default_value = "terminate", value_parser = parse_failure_mode)]
    pub(crate) failure_mode: String,
    /// Requested grace period, bounded by root daemon configuration.
    #[arg(long, default_value_t = 2)]
    pub(crate) loss_grace_seconds: u64,
    /// Pass one explicitly declared environment value (NAME=VALUE).
    #[arg(long = "env", value_parser = parse_environment)]
    pub(crate) environment: Vec<(String, String)>,
    /// Pass one approved secret provider reference.
    #[arg(long = "secret", value_parser = parse_non_empty_string)]
    pub(crate) secret_references: Vec<String>,
    /// Request an admitted TTY.
    #[arg(short = 't', long)]
    pub(crate) tty: bool,
    /// Return after start without waiting for a state change.
    #[arg(short = 'd', long)]
    pub(crate) detached: bool,
    /// Initial argv; the daemon never starts a shell for this request.
    #[arg(required = true, trailing_var_arg = true, num_args = 1..)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SessionMutationArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionArgsById {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionLogsArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, default_value = "stdout", value_parser = parse_stream)]
    pub(crate) stream: String,
    #[arg(long, default_value_t = 0)]
    pub(crate) after_sequence: u64,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub(crate) maximum_records: u32,
}

#[derive(Debug, Args)]
pub(crate) struct SessionAttachArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, default_value_t = 0)]
    pub(crate) after_output_sequence: u64,
    /// Request the exclusive input lease for an admitted TTY.
    #[arg(long)]
    pub(crate) input: bool,
    #[arg(long, default_value = "erebor-cli", value_parser = parse_non_empty_string)]
    pub(crate) client_instance_id: String,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionEventsArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, default_value_t = 0)]
    pub(crate) after_sequence: u64,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub(crate) maximum_records: u32,
}

#[derive(Debug, Args)]
pub(crate) struct SessionStopArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, default_value_t = 2)]
    pub(crate) grace_seconds: u64,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionKillArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, default_value = "kill", value_parser = parse_non_empty_string)]
    pub(crate) signal: String,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionWaitArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, default_value_t = 0)]
    pub(crate) after_generation: u64,
}

#[derive(Debug, Args)]
pub(crate) struct SessionRemoveArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) force: bool,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionPruneArgs {
    /// Prune only terminal sessions older than this Unix timestamp in milliseconds.
    #[arg(long)]
    pub(crate) terminal_before_unix_ms: u64,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub(crate) maximum_sessions: u32,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionAliasArgs {
    #[command(subcommand)]
    pub(crate) command: SessionAliasCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionAliasCommand {
    /// Bind an alias to an exact session id or one unique session-id prefix.
    Set(SessionAliasSetArgs),
    /// Remove one local alias.
    Remove(SessionAliasRemoveArgs),
    /// List local aliases in your daemon namespace.
    #[command(alias = "ls")]
    List,
}

#[derive(Debug, Args)]
pub(crate) struct SessionAliasSetArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) alias: String,
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct SessionAliasRemoveArgs {
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) alias: String,
    #[arg(long, value_parser = parse_non_empty_string)]
    pub(crate) idempotency_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SessionRunnerArg {
    Docker,
    LinuxHost,
}

impl SessionRunnerArg {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::LinuxHost => "linux-host",
        }
    }
}

impl From<SessionRunnerArg> for SessionRunnerKind {
    fn from(value: SessionRunnerArg) -> Self {
        match value {
            SessionRunnerArg::Docker => Self::Docker,
            SessionRunnerArg::LinuxHost => Self::LinuxHost,
        }
    }
}

fn parse_failure_mode(value: &str) -> Result<String, String> {
    match value {
        "terminate" | "continue" | "continue_if_enforced" => Ok(value.to_owned()),
        _ => Err(String::from(
            "must be one of `terminate`, `continue`, or `continue_if_enforced`",
        )),
    }
}

fn parse_environment(value: &str) -> Result<(String, String), String> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| String::from("must use NAME=VALUE"))?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        || name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
    {
        return Err(String::from("environment name must be a shell identifier"));
    }
    Ok((name.to_owned(), value.to_owned()))
}

fn parse_stream(value: &str) -> Result<String, String> {
    match value {
        "stdout" | "stderr" => Ok(value.to_owned()),
        _ => Err(String::from("must be `stdout` or `stderr`")),
    }
}
