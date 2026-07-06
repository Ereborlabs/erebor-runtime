use std::{fs, path::PathBuf};

use clap::{Args, Subcommand};
use erebor_runtime_events::RuntimeEvent;
use erebor_runtime_policy::{LocalPolicy, PolicyEvaluator, PolicySet};
use snafu::ResultExt;

use crate::error::{
    CliError, EncodeJsonSnafu, InvalidEventSnafu, InvalidPolicySnafu, PolicyEvaluationSnafu,
    ReadEventSnafu, ReadPolicySnafu,
};

use super::parse_non_empty_path;

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
        }
    }
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate a single event fixture against a policy.
    Test(PolicyTestArgs),
}

#[derive(Debug, Args)]
struct PolicyTestArgs {
    /// Policy file or package entrypoint to test.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: PathBuf,
    /// Runtime event JSON fixture.
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
        tracing::debug!(
            policy = %self.args.policy.display(),
            event = %self.args.event.display(),
            "testing policy"
        );
        let policy_set =
            PolicyInputReader::read_policy_set(std::slice::from_ref(&self.args.policy))?;
        let event = PolicyInputReader::read_event(&self.args.event)?;
        let decision = policy_set.evaluate(&event).context(PolicyEvaluationSnafu)?;
        println!(
            "{}",
            serde_json::to_string(&decision).context(EncodeJsonSnafu)?
        );
        Ok(())
    }
}

struct PolicyInputReader;

impl PolicyInputReader {
    fn read_policy(path: &PathBuf) -> Result<LocalPolicy, CliError> {
        tracing::debug!(path = %path.display(), "reading policy");
        let source = fs::read_to_string(path).context(ReadPolicySnafu { path: path.clone() })?;

        LocalPolicy::from_json_str(&source).context(InvalidPolicySnafu)
    }

    fn read_policy_set(paths: &[PathBuf]) -> Result<PolicySet, CliError> {
        let policies = paths
            .iter()
            .map(Self::read_policy)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PolicySet::from_policies(policies))
    }

    fn read_event(path: &PathBuf) -> Result<RuntimeEvent, CliError> {
        tracing::debug!(path = %path.display(), "reading runtime event fixture");
        let source = fs::read_to_string(path).context(ReadEventSnafu { path: path.clone() })?;

        serde_json::from_str(&source).context(InvalidEventSnafu)
    }
}
