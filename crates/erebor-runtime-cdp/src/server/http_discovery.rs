use std::net::SocketAddr;

mod response;
mod upstream;

use serde_json::{json, Value};
use snafu::{Location, ResultExt};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{sleep, timeout, Duration},
};

use self::{
    response::{HttpResponseView, SocketHost},
    upstream::{DiscoveryPayloadRewriter, UpstreamDiscovery},
};
use crate::{error::IoSnafu, CdpError};

const HEADER_LIMIT: usize = 8192;
const PEEK_ATTEMPTS: usize = 8;
const PEEK_TIMEOUT: Duration = Duration::from_millis(250);

pub(super) struct HttpDiscoveryProxy;

impl HttpDiscoveryProxy {
    pub(super) async fn handle(
        stream: &mut TcpStream,
        local_addr: SocketAddr,
        browser_url: &str,
    ) -> Result<bool, CdpError> {
        let Some(request) = Self::peek_request(stream).await? else {
            return Ok(false);
        };
        if HttpRequestView::new(&request).is_websocket_upgrade() {
            return Ok(false);
        }

        let response = Self::response(&request, local_addr, browser_url).await;
        stream
            .write_all(response.as_bytes())
            .await
            .context(IoSnafu)?;
        stream.shutdown().await.context(IoSnafu)?;
        Ok(true)
    }

    async fn peek_request(stream: &TcpStream) -> Result<Option<String>, CdpError> {
        let mut buffer = [0_u8; HEADER_LIMIT];

        for _attempt in 0..PEEK_ATTEMPTS {
            let bytes_read = match timeout(PEEK_TIMEOUT, stream.peek(&mut buffer)).await {
                Ok(Ok(bytes_read)) => bytes_read,
                Ok(Err(error)) => {
                    return Err(CdpError::Io {
                        source: error,
                        location: Location::default(),
                    });
                }
                Err(_) => return Ok(None),
            };
            if bytes_read == 0 {
                return Ok(None);
            }
            if !HttpRequestView::looks_like_http(&buffer[..bytes_read]) {
                return Ok(None);
            }
            if let Some(header_end) = HttpResponseView::header_end(&buffer[..bytes_read]) {
                return Ok(Some(
                    String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
                ));
            }

            sleep(Duration::from_millis(10)).await;
        }

        Ok(None)
    }

    async fn response(request: &str, local_addr: SocketAddr, browser_url: &str) -> String {
        let request = HttpRequestView::new(request);
        let Some((method, path)) = request.line() else {
            return HttpResponseView::response(
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                "bad request",
            );
        };
        let governed_ws_url = request.governed_websocket_url(local_addr);

        match DiscoveryPayload::load(method, path, &governed_ws_url, browser_url).await {
            Some(payload) => HttpResponseView::response(
                200,
                "OK",
                "application/json; charset=utf-8",
                &payload.to_string(),
            ),
            None => HttpResponseView::response(
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                "not found",
            ),
        }
    }
}

struct HttpRequestView<'a> {
    request: &'a str,
}

impl<'a> HttpRequestView<'a> {
    fn new(request: &'a str) -> Self {
        Self { request }
    }

    fn looks_like_http(bytes: &[u8]) -> bool {
        bytes.starts_with(b"GET ")
            || bytes.starts_with(b"PUT ")
            || bytes.starts_with(b"POST ")
            || bytes.starts_with(b"OPTIONS ")
            || bytes.starts_with(b"HEAD ")
    }

    fn is_websocket_upgrade(&self) -> bool {
        self.request.lines().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };

            name.trim().eq_ignore_ascii_case("upgrade")
                && value.trim().eq_ignore_ascii_case("websocket")
        })
    }

    fn line(&self) -> Option<(&str, &str)> {
        let mut parts = self.request.lines().next()?.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;
        Some((method, path))
    }

    fn governed_websocket_url(&self, local_addr: SocketAddr) -> String {
        let host = self
            .request
            .lines()
            .find_map(|line| {
                line.strip_prefix("Host: ")
                    .or_else(|| line.strip_prefix("host: "))
            })
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| SocketHost::format(local_addr));

        format!("ws://{host}/")
    }
}

struct DiscoveryPayload;

impl DiscoveryPayload {
    async fn load(
        method: &str,
        path: &str,
        governed_ws_url: &str,
        browser_url: &str,
    ) -> Option<Value> {
        let path_without_query = path.split('?').next().unwrap_or(path);

        if method == "GET" && matches!(path_without_query, "/json/version" | "/json" | "/json/list")
        {
            if let Some(mut payload) =
                UpstreamDiscovery::payload(browser_url, method, path_without_query).await
            {
                DiscoveryPayloadRewriter::rewrite(&mut payload, governed_ws_url);
                return Some(payload);
            }
        }

        match (method, path_without_query) {
            ("GET", "/json/version") => Some(json!({
                "Browser": "Erebor Runtime Governed Browser",
                "Protocol-Version": "1.3",
                "User-Agent": "Erebor Runtime",
                "V8-Version": "",
                "WebKit-Version": "",
                "webSocketDebuggerUrl": governed_ws_url
            })),
            ("GET", "/json") | ("GET", "/json/list") => {
                Some(json!([Self::target_descriptor(governed_ws_url)]))
            }
            ("GET", "/json/protocol") => Some(json!({
                "version": { "major": "1", "minor": "3" },
                "domains": []
            })),
            _ => None,
        }
    }

    fn target_descriptor(governed_ws_url: &str) -> Value {
        json!({
            "description": "Erebor governed browser endpoint",
            "devtoolsFrontendUrl": Self::devtools_frontend_url(governed_ws_url),
            "id": "erebor-governed-browser",
            "title": "Erebor Governed Browser",
            "type": "page",
            "url": "about:blank",
            "webSocketDebuggerUrl": governed_ws_url
        })
    }

    pub(super) fn devtools_frontend_url(governed_ws_url: &str) -> String {
        format!(
            "/devtools/inspector.html?ws={}",
            governed_ws_url.trim_start_matches("ws://")
        )
    }
}
