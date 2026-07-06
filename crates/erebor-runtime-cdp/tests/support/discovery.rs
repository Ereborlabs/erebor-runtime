use std::{
    io::{Read, Write},
    net::SocketAddr,
    time::Duration,
};

use erebor_runtime_e2e::{
    error::{IoSnafu, JsonSnafu},
    E2eError,
};
use serde_json::Value;
use snafu::ResultExt;

use crate::common::external_error;

pub struct GovernedDiscoveryClient {
    port: u16,
}

impl GovernedDiscoveryClient {
    pub fn from_endpoint(endpoint: &str) -> Result<Self, E2eError> {
        let port = endpoint
            .strip_prefix("ws://127.0.0.1:")
            .and_then(|suffix| suffix.trim_end_matches('/').parse::<u16>().ok())
            .ok_or_else(|| {
                external_error(
                    "governed endpoint parsing",
                    std::io::Error::other(format!("unexpected endpoint `{endpoint}`")),
                )
            })?;

        Ok(Self { port })
    }

    pub fn version(&self) -> Result<Value, E2eError> {
        self.http_get_json("/json/version")
    }

    pub fn targets(&self) -> Result<Value, E2eError> {
        self.http_get_json("/json/list")
    }

    fn http_get_json(&self, path: &str) -> Result<Value, E2eError> {
        let mut request = DiscoveryHttpRequest::connect(self.port)?;
        request.get(path)
    }
}

struct DiscoveryHttpRequest {
    port: u16,
    stream: std::net::TcpStream,
}

impl DiscoveryHttpRequest {
    fn connect(port: u16) -> Result<Self, E2eError> {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .context(IoSnafu)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .context(IoSnafu)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .context(IoSnafu)?;

        Ok(Self { port, stream })
    }

    fn get(&mut self, path: &str) -> Result<Value, E2eError> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            self.port
        );
        self.stream.write_all(request.as_bytes()).context(IoSnafu)?;

        let mut response = String::new();
        self.stream.read_to_string(&mut response).context(IoSnafu)?;
        let response = DiscoveryHttpResponse::parse(&response)?;
        response.json()
    }
}

struct DiscoveryHttpResponse<'a> {
    status_line: &'a str,
    body: &'a str,
}

impl<'a> DiscoveryHttpResponse<'a> {
    fn parse(source: &'a str) -> Result<Self, E2eError> {
        let Some((status_line, body)) = source.split_once("\r\n\r\n") else {
            return Err(external_error(
                "governed discovery response",
                std::io::Error::other("missing HTTP response body"),
            ));
        };

        Ok(Self { status_line, body })
    }

    fn json(&self) -> Result<Value, E2eError> {
        if !self.status_line.starts_with("HTTP/1.1 200 ") {
            return Err(external_error(
                "governed discovery status",
                std::io::Error::other(self.status_line.to_owned()),
            ));
        }

        serde_json::from_str(self.body).context(JsonSnafu)
    }
}
