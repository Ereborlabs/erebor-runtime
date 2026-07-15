use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand};
use erebor_runtime_core::{
    BrowserCdpSurfaceLayerConfig, RuntimeAuditConfig, RuntimeConfig, SessionSurfaceLaunchPlan,
    SessionSurfaceLayers,
};
use snafu::ResultExt;

use crate::error::{CliError, InvalidConfigSnafu, RuntimeSnafu};

use super::{parse_non_empty_path, parse_ws_url, start::SurfaceLaunchRunner, WebSocketUrl};

#[derive(Debug, Args)]
pub(super) struct DevArgs {
    #[command(subcommand)]
    command: DevCommand,
}

impl DevArgs {
    pub(super) fn display(&self) -> String {
        match &self.command {
            DevCommand::ProxyCdp(args) => args.display(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Proxy an existing Chromium CDP endpoint with an explicit policy.
    ProxyCdp(ProxyCdpArgs),
}

#[derive(Debug, Args)]
struct ProxyCdpArgs {
    /// Existing local Chromium browser websocket URL.
    #[arg(long, value_parser = parse_ws_url)]
    browser_url: WebSocketUrl,
    /// Policy file or package entrypoint to apply.
    #[arg(long, value_parser = parse_non_empty_path)]
    policy: PathBuf,
    /// Local address for the governed CDP endpoint.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}

impl ProxyCdpArgs {
    fn display(&self) -> String {
        format!(
            "dev proxy-cdp policy={} listen={} upstream=configured",
            self.policy.display(),
            self.listen
        )
    }
}

pub(super) struct DevCommandOwner<'a> {
    args: &'a DevArgs,
}

impl<'a> DevCommandOwner<'a> {
    pub(super) const fn new(args: &'a DevArgs) -> Self {
        Self { args }
    }

    pub(super) fn execute(&self) -> Result<(), CliError> {
        match &self.args.command {
            DevCommand::ProxyCdp(args) => {
                SurfaceLaunchRunner::start(ProxyCdpCommand::new(args).launch_plan()?)
            }
        }
    }
}

struct ProxyCdpCommand<'a> {
    args: &'a ProxyCdpArgs,
}

impl<'a> ProxyCdpCommand<'a> {
    const fn new(args: &'a ProxyCdpArgs) -> Self {
        Self { args }
    }

    fn launch_plan(&self) -> Result<SessionSurfaceLaunchPlan, CliError> {
        let config = RuntimeConfig {
            policies: vec![self.args.policy.clone()],
            audit: RuntimeAuditConfig::default(),
            session: Default::default(),
            codex: Default::default(),
            surfaces: SessionSurfaceLayers {
                browser_cdp: BrowserCdpSurfaceLayerConfig {
                    enabled: true,
                    policies: Vec::new(),
                    browser_url: Some(self.args.browser_url.as_str().to_owned()),
                    listen: self.args.listen,
                    browser: Default::default(),
                },
                ..SessionSurfaceLayers::default()
            },
        };
        let plan = config.surface_start_plan().context(InvalidConfigSnafu)?;

        SessionSurfaceLaunchPlan::from_start_plan(self.args.listen, &plan).context(RuntimeSnafu)
    }
}

#[cfg(test)]
mod tests;
