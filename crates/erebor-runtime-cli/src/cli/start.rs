use std::{net::SocketAddr, path::PathBuf};

use clap::Args;
use erebor_runtime_core::{SessionSurfaceLaunchPlan, SessionSurfaceStartPlan};
use erebor_runtime_session::SurfaceServiceRunner;
use snafu::ResultExt;

use crate::error::{CliError, InvalidConfigSnafu, RuntimeSnafu, SessionExecutionSnafu};

use super::{config_paths::RuntimeConfigLoader, parse_non_empty_path};

#[derive(Debug, Args)]
pub(super) struct StartArgs {
    /// Runtime config describing enabled session surfaces and policies.
    #[arg(long, value_parser = parse_non_empty_path)]
    config: PathBuf,
    /// Local address for runtime control/status APIs.
    #[arg(long, default_value = "127.0.0.1:3737")]
    listen: SocketAddr,
}

impl StartArgs {
    pub(super) fn display(&self) -> String {
        format!(
            "start config={} listen={}",
            self.config.display(),
            self.listen
        )
    }
}

pub(super) struct StartCommand<'a> {
    args: &'a StartArgs,
}

impl<'a> StartCommand<'a> {
    pub(super) const fn new(args: &'a StartArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        SurfaceLaunchRunner::start(self.launch_plan()?)
    }

    pub(super) fn launch_plan(&self) -> Result<SessionSurfaceLaunchPlan, CliError> {
        let plan = self.start_plan()?;
        tracing::debug!(
            control_listen = %self.args.listen,
            surfaces = ?plan.surfaces(),
            policy_count = plan.policies().len(),
            "building session surface launch plan"
        );
        SessionSurfaceLaunchPlan::from_start_plan(self.args.listen, &plan).context(RuntimeSnafu)
    }

    fn start_plan(&self) -> Result<SessionSurfaceStartPlan, CliError> {
        RuntimeConfigLoader::read(&self.args.config)?
            .surface_start_plan()
            .context(InvalidConfigSnafu)
    }
}

pub(super) struct SurfaceLaunchRunner;

impl SurfaceLaunchRunner {
    pub(super) fn start(launch_plan: SessionSurfaceLaunchPlan) -> Result<(), CliError> {
        SurfaceServiceRunner::start(launch_plan).context(SessionExecutionSnafu)
    }
}

#[cfg(test)]
mod tests;
