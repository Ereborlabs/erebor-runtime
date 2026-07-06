use std::{
    io::{Read, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

use erebor_runtime_e2e::{
    error::{IoSnafu, JsonSnafu},
    E2eError,
};
use snafu::{Location, ResultExt};

use super::error_helpers::external_error;

const HTTP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct ChromeDevToolsHttpClient {
    port: u16,
}

impl ChromeDevToolsHttpClient {
    pub(super) const fn new(port: u16) -> Self {
        Self { port }
    }

    pub(super) fn page_ws_url(&self) -> Result<String, E2eError> {
        let targets: Vec<ChromeTargetDescriptor> = self.get_json("/json/list")?;

        if let Some(page_ws_url) = targets
            .into_iter()
            .find(|target| target.kind == "page")
            .and_then(|target| target.web_socket_debugger_url)
        {
            return Ok(page_ws_url);
        }

        self.create_page_ws_url()
    }

    fn create_page_ws_url(&self) -> Result<String, E2eError> {
        let target: ChromeTargetDescriptor = self.put_json("/json/new?about:blank")?;

        target
            .web_socket_debugger_url
            .ok_or_else(|| external_error("real Chrome page target", MissingPageTarget))
    }

    fn get_json<T>(&self, path: &str) -> Result<T, E2eError>
    where
        T: serde::de::DeserializeOwned,
    {
        self.json_request("GET", path)
    }

    fn put_json<T>(&self, path: &str) -> Result<T, E2eError>
    where
        T: serde::de::DeserializeOwned,
    {
        self.json_request("PUT", path)
    }

    fn json_request<T>(&self, method: &str, path: &str) -> Result<T, E2eError>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut request = ChromeHttpRequest::connect(self.port)?;
        let response = request.send(method, path)?;
        let body = response.success_body()?;

        serde_json::from_str(body).context(JsonSnafu)
    }
}

struct ChromeHttpRequest {
    port: u16,
    stream: std::net::TcpStream,
}

impl ChromeHttpRequest {
    fn connect(port: u16) -> Result<Self, E2eError> {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let stream =
            std::net::TcpStream::connect_timeout(&address, HTTP_TIMEOUT).context(IoSnafu)?;
        stream
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .context(IoSnafu)?;
        stream
            .set_write_timeout(Some(HTTP_TIMEOUT))
            .context(IoSnafu)?;
        Ok(Self { port, stream })
    }

    fn send(&mut self, method: &str, path: &str) -> Result<ChromeHttpResponse, E2eError> {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            self.port
        );
        self.stream.write_all(request.as_bytes()).context(IoSnafu)?;
        ChromeHttpResponse::read_from(&mut self.stream)
    }
}

struct ChromeHttpResponse {
    source: String,
}

impl ChromeHttpResponse {
    fn read_from(stream: &mut std::net::TcpStream) -> Result<Self, E2eError> {
        let deadline = Instant::now() + HTTP_TIMEOUT;
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8192];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    response.extend_from_slice(&buffer[..bytes_read]);
                    if Self::complete(&response) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if Self::complete(&response) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(E2eError::Io {
                            source: error,
                            location: Location::default(),
                        });
                    }
                }
                Err(error) => {
                    return Err(E2eError::Io {
                        source: error,
                        location: Location::default(),
                    });
                }
            }
        }

        Ok(Self {
            source: String::from_utf8(response)
                .map_err(|error| external_error("real Chrome HTTP response", error))?,
        })
    }

    fn success_body(&self) -> Result<&str, E2eError> {
        let Some((status_line, body)) = split_http_response(&self.source) else {
            return Err(external_error(
                "real Chrome HTTP response",
                InvalidHttpResponse,
            ));
        };

        if !is_success_status(status_line) {
            return Err(external_error(
                "real Chrome HTTP status",
                HttpStatus(status_line.to_owned()),
            ));
        }

        Ok(body)
    }

    fn complete(response: &[u8]) -> bool {
        let Ok(response) = std::str::from_utf8(response) else {
            return false;
        };
        let Some((headers, body)) = split_http_response(response) else {
            return false;
        };
        let Some(content_length) = content_length(headers) else {
            return false;
        };

        body.len() >= content_length
    }
}

#[derive(Debug, serde::Deserialize)]
struct ChromeTargetDescriptor {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: Option<String>,
}

#[derive(Debug)]
struct HttpStatus(String);

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "real Chrome returned HTTP status `{}`", self.0)
    }
}

impl std::error::Error for HttpStatus {}

#[derive(Debug)]
struct InvalidHttpResponse;

impl std::fmt::Display for InvalidHttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("real Chrome returned an invalid HTTP response")
    }
}

impl std::error::Error for InvalidHttpResponse {}

#[derive(Debug)]
struct MissingPageTarget;

impl std::fmt::Display for MissingPageTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("real Chrome did not expose a page target")
    }
}

impl std::error::Error for MissingPageTarget {}

fn split_http_response(response: &str) -> Option<(&str, &str)> {
    let (headers, body) = response.split_once("\r\n\r\n")?;
    let status_line = headers.lines().next()?;

    Some((status_line, body))
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;

        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

fn is_success_status(status_line: &str) -> bool {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .is_some_and(|status| (200..300).contains(&status))
}
