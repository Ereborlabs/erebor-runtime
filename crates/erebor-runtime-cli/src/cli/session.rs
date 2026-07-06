use std::{io, io::Write, path::PathBuf};

use erebor_runtime_audit::SessionReviewSource;
use erebor_runtime_core::{RuntimeConfig, SessionRunPlan};
use erebor_runtime_events::SessionId;
use erebor_runtime_session::{
    SessionAdoptionService, SessionDiagnosticOutcome, SessionExecutionService,
};
use snafu::ResultExt;

use crate::error::{
    CliError, InvalidConfigSnafu, SessionExecutionSnafu, SessionReviewSnafu,
    WriteSessionOutputSnafu,
};

use super::config_paths::RuntimeConfigLoader;

mod args;

use args::{
    SessionCommand, SessionDescribeArgs, SessionDiagnoseArgs, SessionLsArgs, SessionRunArgs,
    SessionShowArgs,
};

pub(super) use args::SessionArgs;

pub(super) struct SessionCommandOwner<'a> {
    args: &'a SessionArgs,
}

impl<'a> SessionCommandOwner<'a> {
    pub(super) const fn new(args: &'a SessionArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            SessionCommand::Run(args) => self.run(args),
            SessionCommand::Diagnose(args) => self.diagnose(args),
            SessionCommand::Adopt(args) => self.adopt(args),
            SessionCommand::Ls(args) => self.list(args),
            SessionCommand::Show(args) => self.show(args),
            SessionCommand::Describe(args) => self.describe(args),
        }
    }

    fn run(&self, args: &SessionRunArgs) -> Result<(), CliError> {
        let config = RuntimeConfigLoader::read(&args.config)?;
        let plan = SessionPlanBuilder::new(&config, &args.config).run(args)?;
        SessionExecutionService::run_plan(&config, &plan).context(SessionExecutionSnafu)?;
        Ok(())
    }

    fn diagnose(&self, args: &SessionDiagnoseArgs) -> Result<(), CliError> {
        let config = RuntimeConfigLoader::read(&args.config)?;
        let plan = SessionPlanBuilder::new(&config, &args.config).diagnostic(args)?;
        let outcome = SessionExecutionService::run_diagnostic(&config, &plan)
            .context(SessionExecutionSnafu)?;
        SessionDiagnosticOutput::new(&outcome).write()
    }

    fn adopt(&self, args: &args::SessionAdoptArgs) -> Result<(), CliError> {
        let config = RuntimeConfigLoader::read(&args.config)?;
        let session_id = SessionIdFactory::for_process();
        SessionAdoptionService::adopt_target(
            &config,
            args.runner.into(),
            session_id,
            args.target(),
        )
        .context(SessionExecutionSnafu)?;
        Ok(())
    }

    fn list(&self, args: &SessionLsArgs) -> Result<(), CliError> {
        let output = SessionReviewSource::default()
            .render_list(args.format.into())
            .context(SessionReviewSnafu)?;
        print!("{output}");
        Ok(())
    }

    fn show(&self, args: &SessionShowArgs) -> Result<(), CliError> {
        let output = SessionReviewSource::default()
            .render_show(&args.session_id, args.format.into())
            .context(SessionReviewSnafu)?;
        print!("{output}");
        Ok(())
    }

    fn describe(&self, args: &SessionDescribeArgs) -> Result<(), CliError> {
        let output = SessionReviewSource::default()
            .render_describe(&args.session_id, args.format.into())
            .context(SessionReviewSnafu)?;
        print!("{output}");
        Ok(())
    }
}

struct SessionPlanBuilder<'a> {
    config: &'a RuntimeConfig,
    config_path: &'a PathBuf,
}

impl<'a> SessionPlanBuilder<'a> {
    const fn new(config: &'a RuntimeConfig, config_path: &'a PathBuf) -> Self {
        Self {
            config,
            config_path,
        }
    }

    fn run(&self, args: &SessionRunArgs) -> Result<SessionRunPlan, CliError> {
        let mut plan = SessionRunPlan::from_config(
            self.config,
            args.runner.into(),
            SessionIdFactory::for_process(),
            args.command.clone(),
        )
        .context(InvalidConfigSnafu)?;
        plan.set_config_path(self.config_path.clone());
        Ok(plan)
    }

    fn diagnostic(&self, args: &SessionDiagnoseArgs) -> Result<SessionRunPlan, CliError> {
        let mut plan = SessionRunPlan::from_diagnostic(
            self.config,
            args.runner.into(),
            SessionIdFactory::for_process(),
            &args.name,
        )
        .context(InvalidConfigSnafu)?;
        plan.set_config_path(self.config_path.clone());
        Ok(plan)
    }
}

struct SessionIdFactory;

impl SessionIdFactory {
    fn for_process() -> SessionId {
        SessionId::new(format!("session-{}", std::process::id()))
    }
}

struct SessionDiagnosticOutput<'a> {
    outcome: &'a SessionDiagnosticOutcome,
}

impl<'a> SessionDiagnosticOutput<'a> {
    const fn new(outcome: &'a SessionDiagnosticOutcome) -> Self {
        Self { outcome }
    }

    fn write(&self) -> Result<(), CliError> {
        if !self.outcome.stdout().is_empty() {
            io::stdout()
                .write_all(self.outcome.stdout().as_bytes())
                .context(WriteSessionOutputSnafu)?;
        }
        if !self.outcome.stderr().is_empty() {
            io::stderr()
                .write_all(self.outcome.stderr().as_bytes())
                .context(WriteSessionOutputSnafu)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
