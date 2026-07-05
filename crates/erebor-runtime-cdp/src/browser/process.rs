use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use erebor_runtime_core::{BrowserCdpSurfaceConfig, BrowserLaunchConfig};
use erebor_runtime_telemetry::debug;
use snafu::ResultExt;

use super::{
    devtools::DevToolsEndpointProbe, diagnostics::BrowserLaunchDiagnostics,
    launch::OwnedBrowserLaunch, page_target::PageTargetCreator,
};
use crate::{error::IoSnafu, CdpError};

pub(super) struct BrowserUpstream {
    endpoint: String,
    owned_browser: Option<OwnedBrowserProcess>,
}

impl BrowserUpstream {
    pub(super) fn prepare(config: &BrowserCdpSurfaceConfig) -> Result<Self, CdpError> {
        if let Some(browser_url) = config.browser_url() {
            return Ok(Self {
                endpoint: browser_url.to_owned(),
                owned_browser: None,
            });
        }

        let owned_browser = OwnedBrowserProcess::launch(config.browser())?;
        debug!(
            browser_endpoint = %owned_browser.browser_ws_url,
            page_endpoint = %owned_browser.page_ws_url,
            "prepared owned browser CDP upstream"
        );
        let endpoint = owned_browser.browser_ws_url.clone();

        Ok(Self {
            endpoint,
            owned_browser: Some(owned_browser),
        })
    }

    pub(super) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(super) fn browser_profile(&self) -> Option<PathBuf> {
        self.owned_browser
            .as_ref()
            .map(|browser| browser.user_data_dir.clone())
    }

    pub(super) fn owns_browser(&self) -> bool {
        self.owned_browser.is_some()
    }

    pub(super) fn into_owned_browser(self) -> Option<OwnedBrowserProcess> {
        self.owned_browser
    }
}

pub(super) struct OwnedBrowserProcess {
    child: Child,
    user_data_dir: PathBuf,
    cleanup_user_data_dir: bool,
    browser_ws_url: String,
    page_ws_url: String,
}

impl OwnedBrowserProcess {
    fn launch(config: &BrowserLaunchConfig) -> Result<Self, CdpError> {
        let launch = OwnedBrowserLaunch::from_config(config)?;
        let stderr_log = fs::File::create(&launch.stderr_log_path).context(IoSnafu)?;

        let mut command = Command::new(&launch.executable.path);
        command
            .args(&launch.args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log));

        debug!(
            browser = %launch.executable.label(),
            binary = %launch.executable.path.display(),
            profile = %launch.user_data_dir.display(),
            stderr = %launch.stderr_log_path.display(),
            headless = launch.options.headless,
            args = ?launch.args,
            "launching owned browser"
        );
        let mut child = command.spawn().context(IoSnafu)?;
        let devtools = DevToolsEndpointProbe::wait(
            &mut child,
            &launch.user_data_dir.join("DevToolsActivePort"),
            launch.options.remote_debugging_port,
            &launch.stderr_log_path,
        )
        .map_err(|error| BrowserLaunchDiagnostics::enrich(error, &launch.stderr_log_path))?;
        let page_ws_url = PageTargetCreator::create(&devtools.browser_ws_url, devtools.port)
            .or_else(|ws_error| {
                PageTargetCreator::wait_for_http(&mut child, devtools.port).map_err(|http_error| {
                    BrowserLaunchDiagnostics::page_target_error(ws_error, http_error)
                })
            })?;

        Ok(Self {
            child,
            user_data_dir: launch.user_data_dir,
            cleanup_user_data_dir: launch.cleanup_user_data_dir,
            browser_ws_url: devtools.browser_ws_url,
            page_ws_url,
        })
    }
}

impl Drop for OwnedBrowserProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _kill_result = self.child.kill();
            let _wait_result = self.child.wait();
        }

        if self.cleanup_user_data_dir {
            let _cleanup_result = fs::remove_dir_all(&self.user_data_dir);
        }
    }
}
