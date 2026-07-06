use std::path::PathBuf;

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use erebor_runtime_core::{SessionAdoptTarget, SessionRunnerKind};

use super::super::{
    parse_non_empty_path, parse_non_empty_string, parse_positive_pid, OutputFormat,
};

#[derive(Debug, Args)]
pub(crate) struct SessionArgs {
    #[command(subcommand)]
    pub(crate) command: SessionCommand,
}

impl SessionArgs {
    pub(crate) fn display(&self) -> String {
        match &self.command {
            SessionCommand::Run(args) => format!(
                "session run runner={} config={} command={}",
                args.runner.as_str(),
                args.config.display(),
                args.command.join(" ")
            ),
            SessionCommand::Diagnose(args) => format!(
                "session diagnose runner={} config={} name={}",
                args.runner.as_str(),
                args.config.display(),
                args.name
            ),
            SessionCommand::Adopt(args) => format!(
                "session adopt runner={} config={} target={}",
                args.runner.as_str(),
                args.config.display(),
                args.target_display()
            ),
            SessionCommand::Ls(args) => format!("session ls format={}", args.format.as_str()),
            SessionCommand::Show(args) => format!(
                "session show session_id={} format={}",
                args.session_id,
                args.format.as_str()
            ),
            SessionCommand::Describe(args) => format!(
                "session describe session_id={} format={}",
                args.session_id,
                args.format.as_str()
            ),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommand {
    /// Start an agent inside a governed session runner.
    Run(SessionRunArgs),
    /// Run a named bounded diagnostic from the session config.
    Diagnose(SessionDiagnoseArgs),
    /// Adopt an already-running agent process into a governed session.
    Adopt(SessionAdoptArgs),
    /// List sessions present in an audit log.
    Ls(SessionLsArgs),
    /// Show a buyer-readable summary for one governed session.
    Show(SessionShowArgs),
    /// Describe governed session decisions with proof details.
    Describe(SessionDescribeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SessionRunArgs {
    /// Session config describing policies, audit, surfaces, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    pub(crate) config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    pub(crate) runner: SessionRunnerArg,
    /// Agent entrypoint to launch inside the governed session runner.
    #[arg(required = true, trailing_var_arg = true, num_args = 1..)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SessionDiagnoseArgs {
    /// Session config describing policies, audit, diagnostics, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    pub(crate) config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    pub(crate) runner: SessionRunnerArg,
    /// Named diagnostic from the session config.
    pub(crate) name: String,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("adopt_target")
        .required(true)
        .args(["pid", "match_pattern"])
))]
pub(crate) struct SessionAdoptArgs {
    /// Session config describing policies, audit, surfaces, and runner settings.
    #[arg(long, value_parser = parse_non_empty_path)]
    pub(crate) config: PathBuf,
    /// Concrete session runner to use.
    #[arg(long, alias = "runtime", value_enum)]
    pub(crate) runner: SessionRunnerArg,
    /// Already-running process id to attach to.
    #[arg(long, value_parser = parse_positive_pid)]
    pub(crate) pid: Option<i32>,
    /// Find one already-running process whose executable or command line contains this text.
    #[arg(long = "match", value_name = "TEXT", value_parser = parse_non_empty_string)]
    pub(crate) match_pattern: Option<String>,
}

impl SessionAdoptArgs {
    pub(crate) fn target_display(&self) -> String {
        self.target().display_target()
    }

    pub(crate) fn target(&self) -> SessionAdoptTarget {
        match (self.pid, self.match_pattern.as_deref()) {
            (Some(pid), None) => SessionAdoptTarget::pid(pid),
            (None, Some(pattern)) => SessionAdoptTarget::process_match(pattern),
            _ => unreachable!("clap enforces exactly one session adoption target"),
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct SessionLsArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SessionShowArgs {
    /// Session id to show.
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct SessionDescribeArgs {
    /// Session id to describe.
    #[arg(value_parser = parse_non_empty_string)]
    pub(crate) session_id: String,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,
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
