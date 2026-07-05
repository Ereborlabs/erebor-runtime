use std::{
    fs,
    path::Path,
    process::Child,
    time::{Duration, Instant},
};

use snafu::ResultExt;

use super::{diagnostics::BrowserLaunchDiagnostics, page_target::PageTargetCreator};
use crate::{
    error::{BrowserLaunchSnafu, IoSnafu},
    CdpError,
};

const DEVTOOLS_WAIT: Duration = Duration::from_secs(10);
const DEVTOOLS_POLL: Duration = Duration::from_millis(50);

pub(super) struct DevToolsEndpoint {
    pub(super) port: u16,
    pub(super) browser_ws_url: String,
}

pub(super) struct DevToolsEndpointProbe;

impl DevToolsEndpointProbe {
    pub(super) fn wait(
        child: &mut Child,
        active_port_file: &Path,
        configured_port: Option<u16>,
        stderr_log_path: &Path,
    ) -> Result<DevToolsEndpoint, CdpError> {
        if let Some(port) = configured_port {
            return Self::wait_configured(child, port, stderr_log_path);
        }

        let deadline = Instant::now() + DEVTOOLS_WAIT;

        loop {
            if let Ok(contents) = fs::read_to_string(active_port_file) {
                return Self::from_active_port_file(&contents);
            }

            if child.try_wait().context(IoSnafu)?.is_some() {
                return BrowserLaunchSnafu {
                    reason: String::from("Chrome exited before DevTools became ready"),
                }
                .fail();
            }

            if Instant::now() >= deadline {
                return BrowserLaunchSnafu {
                    reason: String::from("timed out waiting for Chrome DevToolsActivePort"),
                }
                .fail();
            }

            std::thread::sleep(DEVTOOLS_POLL);
        }
    }

    fn wait_configured(
        child: &mut Child,
        port: u16,
        stderr_log_path: &Path,
    ) -> Result<DevToolsEndpoint, CdpError> {
        let deadline = Instant::now() + DEVTOOLS_WAIT;
        let mut errors = Vec::new();

        loop {
            if let Some(browser_ws_url) =
                BrowserLaunchDiagnostics::stderr_devtools_url(stderr_log_path, port)
            {
                return Ok(DevToolsEndpoint {
                    port,
                    browser_ws_url,
                });
            }

            match PageTargetCreator::fetch_browser_ws_url(port) {
                Ok(browser_ws_url) => {
                    return Ok(DevToolsEndpoint {
                        port,
                        browser_ws_url,
                    });
                }
                Err(
                    error @ (CdpError::Io { .. }
                    | CdpError::InvalidJson { .. }
                    | CdpError::BrowserLaunch { .. }),
                ) => errors.push(error.to_string()),
                Err(error) => return Err(error),
            }

            if child.try_wait().context(IoSnafu)?.is_some() {
                return BrowserLaunchSnafu {
                    reason: String::from("Chrome exited before fixed-port DevTools became ready"),
                }
                .fail();
            }

            if Instant::now() >= deadline {
                let reason = errors.last().map_or_else(
                    || String::from("timed out waiting for Chrome fixed-port DevTools"),
                    |error| {
                        format!(
                            "timed out waiting for Chrome fixed-port DevTools; last error: {error}"
                        )
                    },
                );

                return BrowserLaunchSnafu { reason }.fail();
            }

            std::thread::sleep(DEVTOOLS_POLL);
        }
    }

    fn from_active_port_file(contents: &str) -> Result<DevToolsEndpoint, CdpError> {
        let mut lines = contents.lines();
        let Some(port_line) = lines.next() else {
            return BrowserLaunchSnafu {
                reason: String::from("Chrome DevToolsActivePort file did not include a port"),
            }
            .fail();
        };
        let port = port_line.parse::<u16>().map_err(|error| {
            BrowserLaunchSnafu {
                reason: error.to_string(),
            }
            .build()
        })?;
        let Some(browser_path) = lines.next() else {
            return BrowserLaunchSnafu {
                reason: String::from(
                    "Chrome DevToolsActivePort file did not include a browser websocket path",
                ),
            }
            .fail();
        };
        let browser_ws_url = if browser_path.starts_with("ws://") {
            browser_path.to_owned()
        } else {
            format!("ws://127.0.0.1:{port}{browser_path}")
        };

        Ok(DevToolsEndpoint {
            port,
            browser_ws_url,
        })
    }
}
