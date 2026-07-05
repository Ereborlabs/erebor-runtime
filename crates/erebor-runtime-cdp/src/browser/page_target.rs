use std::{
    process::Child,
    time::{Duration, Instant},
};

use cdp_protocol::{target, types::Method};
use serde::Deserialize;
use snafu::ResultExt;
use tokio_tungstenite::tungstenite::{connect, Message};

use super::http_json::{ChromeDevToolsHttp, ChromeTargetDescriptor, ChromeVersionDescriptor};
use crate::{
    error::{BrowserLaunchSnafu, InvalidProtocolSnafu, IoSnafu, WebSocketSnafu},
    CdpError,
};

const DEVTOOLS_WAIT: Duration = Duration::from_secs(10);
const DEVTOOLS_POLL: Duration = Duration::from_millis(50);

pub(super) struct PageTargetCreator;

impl PageTargetCreator {
    pub(super) fn create(browser_ws_url: &str, port: u16) -> Result<String, CdpError> {
        let (mut socket, _response) = connect(browser_ws_url).context(WebSocketSnafu)?;
        let create_target = target::CreateTarget {
            url: String::from("about:blank"),
            left: None,
            top: None,
            width: None,
            height: None,
            window_state: None,
            browser_context_id: None,
            enable_begin_frame_control: None,
            new_window: None,
            background: None,
            for_tab: None,
            hidden: None,
            focus: None,
        };
        let payload = serde_json::to_string(&create_target.to_method_call(1))
            .context(InvalidProtocolSnafu)?;
        socket
            .send(Message::Text(payload.into()))
            .context(WebSocketSnafu)?;

        loop {
            let message = socket.read().context(WebSocketSnafu)?;
            let Message::Text(text) = message else {
                continue;
            };
            let response: CdpMethodResponse<target::CreateTargetReturnObject> =
                serde_json::from_str(text.as_ref()).context(InvalidProtocolSnafu)?;

            if response.id != 1 {
                continue;
            }

            if let Some(error) = response.error {
                return BrowserLaunchSnafu {
                    reason: format!("Chrome rejected Target.createTarget: {}", error.message),
                }
                .fail();
            }

            let result = response.result.ok_or_else(|| {
                BrowserLaunchSnafu {
                    reason: String::from(
                        "Chrome Target.createTarget response did not include result",
                    ),
                }
                .build()
            })?;

            return Ok(format!(
                "ws://127.0.0.1:{port}/devtools/page/{}",
                result.target_id
            ));
        }
    }

    pub(super) fn wait_for_http(child: &mut Child, port: u16) -> Result<String, CdpError> {
        let deadline = Instant::now() + DEVTOOLS_WAIT;
        let mut errors = Vec::new();

        loop {
            match Self::fetch_page_ws_url(port) {
                Ok(page_ws_url) => return Ok(page_ws_url),
                Err(
                    error @ (CdpError::Io { .. }
                    | CdpError::InvalidJson { .. }
                    | CdpError::InvalidProtocol { .. }),
                ) => {
                    errors.push(error.to_string());
                }
                Err(error) => return Err(error),
            }

            if child.try_wait().context(IoSnafu)?.is_some() {
                return BrowserLaunchSnafu {
                    reason: String::from("Chrome exited before page target became ready"),
                }
                .fail();
            }

            if Instant::now() >= deadline {
                let reason = errors.last().map_or_else(
                    || String::from("timed out waiting for Chrome page websocket"),
                    |error| {
                        format!("timed out waiting for Chrome page websocket; last error: {error}")
                    },
                );

                return BrowserLaunchSnafu { reason }.fail();
            }

            std::thread::sleep(DEVTOOLS_POLL);
        }
    }

    pub(super) fn fetch_browser_ws_url(port: u16) -> Result<String, CdpError> {
        let version: ChromeVersionDescriptor = ChromeDevToolsHttp::get_json(port, "/json/version")?;
        version.web_socket_debugger_url.ok_or_else(|| {
            BrowserLaunchSnafu {
                reason: String::from("Chrome /json/version did not return a browser websocket"),
            }
            .build()
        })
    }

    fn fetch_page_ws_url(port: u16) -> Result<String, CdpError> {
        let targets: Vec<ChromeTargetDescriptor> =
            ChromeDevToolsHttp::get_json(port, "/json/list")?;

        if let Some(page_ws_url) = targets
            .into_iter()
            .find(|target| target.kind == "page")
            .and_then(|target| target.web_socket_debugger_url)
        {
            return Ok(page_ws_url);
        }

        Self::create_via_http(port)
    }

    fn create_via_http(port: u16) -> Result<String, CdpError> {
        let target: ChromeTargetDescriptor =
            ChromeDevToolsHttp::put_json(port, "/json/new?about:blank")?;

        target.web_socket_debugger_url.ok_or_else(|| {
            BrowserLaunchSnafu {
                reason: String::from("Chrome target creation did not return a page websocket"),
            }
            .build()
        })
    }
}

#[derive(Debug, Deserialize)]
struct CdpMethodResponse<T> {
    id: u32,
    result: Option<T>,
    error: Option<CdpMethodError>,
}

#[derive(Debug, Deserialize)]
struct CdpMethodError {
    message: String,
}
