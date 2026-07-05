use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{timeout, Duration},
};

use super::{response::HttpResponseView, DiscoveryPayload};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct UpstreamDiscovery;

impl UpstreamDiscovery {
    pub(super) async fn payload(browser_url: &str, method: &str, path: &str) -> Option<Value> {
        let (host, port) = DevToolsHttpHost::parse(browser_url)?;
        let address = format!("{host}:{port}");
        let mut stream = timeout(UPSTREAM_TIMEOUT, TcpStream::connect(address.as_str()))
            .await
            .ok()?
            .ok()?;
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
        timeout(UPSTREAM_TIMEOUT, stream.write_all(request.as_bytes()))
            .await
            .ok()?
            .ok()?;

        let (head, body) = HttpResponseView::read_upstream(&mut stream).await?;
        if !head.starts_with("HTTP/1.1 200 ") && !head.starts_with("HTTP/1.0 200 ") {
            return None;
        }

        serde_json::from_str(&body).ok()
    }
}

pub(super) struct DiscoveryPayloadRewriter;

impl DiscoveryPayloadRewriter {
    pub(super) fn rewrite(payload: &mut Value, governed_ws_url: &str) {
        match payload {
            Value::Object(map) => {
                if map.contains_key("webSocketDebuggerUrl") {
                    map.insert(
                        String::from("webSocketDebuggerUrl"),
                        Value::String(governed_ws_url.to_owned()),
                    );
                }
                if map.contains_key("devtoolsFrontendUrl") {
                    map.insert(
                        String::from("devtoolsFrontendUrl"),
                        Value::String(DiscoveryPayload::devtools_frontend_url(governed_ws_url)),
                    );
                }
                for value in map.values_mut() {
                    Self::rewrite(value, governed_ws_url);
                }
            }
            Value::Array(values) => {
                for value in values {
                    Self::rewrite(value, governed_ws_url);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

struct DevToolsHttpHost;

impl DevToolsHttpHost {
    fn parse(browser_url: &str) -> Option<(String, u16)> {
        let without_scheme = browser_url
            .strip_prefix("ws://")
            .or_else(|| browser_url.strip_prefix("http://"))?;
        let authority = without_scheme.split('/').next()?;
        let (host, port) = authority.rsplit_once(':')?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = port.parse().ok()?;
        Some((host.to_owned(), port))
    }
}
