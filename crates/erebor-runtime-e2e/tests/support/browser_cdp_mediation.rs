use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use erebor_runtime_e2e::E2eError;

#[path = "browser_cdp_mediation/audit.rs"]
mod audit;
#[path = "browser_cdp_mediation/config.rs"]
mod config;
#[path = "browser_cdp_mediation/host.rs"]
mod host;
#[path = "browser_cdp_mediation/ports.rs"]
mod ports;
#[path = "browser_cdp_mediation/probe.rs"]
mod probe;

pub use host::BrowserCdpMediationHost;

use audit::SessionAudit;
use config::{write_empty_policy, MediationLifecycleConfig};
use ports::PortPair;
use probe::OriginalBrowserCommandProbe;

pub struct BrowserCdpMediationLifecycle {
    config_path: PathBuf,
    ports: PortPair,
    browser_bin: PathBuf,
    original_command: OriginalBrowserCommandProbe,
}

impl BrowserCdpMediationLifecycle {
    pub fn prepare(workspace: &Path, host: &BrowserCdpMediationHost) -> Result<Self, E2eError> {
        let ports = PortPair::allocate()?;
        let policy_path = write_empty_policy(workspace)?;
        let original_command = OriginalBrowserCommandProbe::install(workspace)?;
        let config_path =
            MediationLifecycleConfig::new(workspace, &policy_path, ports).write(workspace)?;

        Ok(Self {
            config_path,
            ports,
            browser_bin: host.browser_bin().to_path_buf(),
            original_command,
        })
    }

    pub fn command_environment(&self) -> Result<Vec<(String, OsString)>, E2eError> {
        Ok(vec![
            (
                String::from("EREBOR_BROWSER_BIN"),
                self.browser_bin.as_os_str().to_os_string(),
            ),
            (String::from("PATH"), self.original_command.path_value()?),
        ])
    }

    pub fn assert_original_command_not_executed(&self) -> Result<(), E2eError> {
        self.original_command.assert_not_executed()
    }

    pub fn audit(&self, workspace: &Path) -> Result<SessionAudit, E2eError> {
        SessionAudit::from_workspace(workspace)
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn devtools_listening_line(&self) -> String {
        format!(
            "DevTools listening on ws://127.0.0.1:{}/devtools/browser/erebor-managed-browser",
            self.ports.governed()
        )
    }

    pub fn governed_endpoint_prefix(&self) -> String {
        format!("ws://127.0.0.1:{}/", self.ports.governed())
    }
}
