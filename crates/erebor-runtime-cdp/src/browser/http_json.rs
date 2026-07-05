use std::{
    io::{Read, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

use serde::Deserialize;
use snafu::ResultExt;

use crate::{
    error::{BrowserLaunchSnafu, InvalidJsonSnafu, IoSnafu},
    CdpError,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
pub(super) struct ChromeTargetDescriptor {
    #[serde(rename = "type")]
    pub(super) kind: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    pub(super) web_socket_debugger_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChromeVersionDescriptor {
    #[serde(rename = "webSocketDebuggerUrl")]
    pub(super) web_socket_debugger_url: Option<String>,
}

pub(super) struct ChromeDevToolsHttp;

impl ChromeDevToolsHttp {
    pub(super) fn get_json<T>(port: u16, path: &str) -> Result<T, CdpError>
    where
        T: serde::de::DeserializeOwned,
    {
        Self::json_request(port, "GET", path)
    }

    pub(super) fn put_json<T>(port: u16, path: &str) -> Result<T, CdpError>
    where
        T: serde::de::DeserializeOwned,
    {
        Self::json_request(port, "PUT", path)
    }

    fn json_request<T>(port: u16, method: &str, path: &str) -> Result<T, CdpError>
    where
        T: serde::de::DeserializeOwned,
    {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream =
            std::net::TcpStream::connect_timeout(&address, HTTP_TIMEOUT).context(IoSnafu)?;
        stream
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .context(IoSnafu)?;
        stream
            .set_write_timeout(Some(HTTP_TIMEOUT))
            .context(IoSnafu)?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).context(IoSnafu)?;
        let response = HttpResponseReader::read(&mut stream)?;
        let Some((status_line, body)) = HttpResponseReader::split(&response) else {
            return BrowserLaunchSnafu {
                reason: String::from("Chrome returned an invalid HTTP response"),
            }
            .fail();
        };

        if !HttpResponseReader::is_success_status(status_line) {
            return BrowserLaunchSnafu {
                reason: format!("Chrome returned HTTP status `{status_line}`"),
            }
            .fail();
        }

        serde_json::from_str(body).context(InvalidJsonSnafu)
    }
}

struct HttpResponseReader;

impl HttpResponseReader {
    fn read(stream: &mut std::net::TcpStream) -> Result<String, CdpError> {
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
                        return Err(CdpError::Io {
                            source: error,
                            location: snafu::Location::default(),
                        });
                    }
                }
                Err(error) => {
                    return Err(CdpError::Io {
                        source: error,
                        location: snafu::Location::default(),
                    });
                }
            }
        }

        String::from_utf8(response).map_err(|error| {
            BrowserLaunchSnafu {
                reason: format!("Chrome returned a non-UTF-8 HTTP response: {error}"),
            }
            .build()
        })
    }

    fn complete(response: &[u8]) -> bool {
        let Ok(response) = std::str::from_utf8(response) else {
            return false;
        };
        let Some((headers, body)) = Self::split(response) else {
            return false;
        };
        let Some(content_length) = Self::content_length(headers) else {
            return false;
        };

        body.len() >= content_length
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

    fn split(response: &str) -> Option<(&str, &str)> {
        let (headers, body) = response.split_once("\r\n\r\n")?;
        let status_line = headers.lines().next()?;

        Some((status_line, body))
    }
}
