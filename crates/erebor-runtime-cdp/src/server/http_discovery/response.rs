use std::net::SocketAddr;

use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{timeout, Duration},
};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct HttpResponseView;

impl HttpResponseView {
    pub(super) async fn read_upstream(stream: &mut TcpStream) -> Option<(String, String)> {
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8192];

        loop {
            let bytes_read = timeout(UPSTREAM_TIMEOUT, stream.read(&mut buffer))
                .await
                .ok()?
                .ok()?;
            if bytes_read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..bytes_read]);
            if Self::complete(&response) {
                break;
            }
        }

        Self::split(&response)
    }

    pub(super) fn response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    pub(super) fn header_end(bytes: &[u8]) -> Option<usize> {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some(position + 4);
        }

        bytes
            .windows(2)
            .position(|window| window == b"\n\n")
            .map(|position| position + 2)
    }

    fn complete(response: &[u8]) -> bool {
        let Some(header_end) = Self::header_end(response) else {
            return false;
        };
        let headers = String::from_utf8_lossy(&response[..header_end]);
        let Some(content_length) = Self::content_length(&headers) else {
            return false;
        };

        response.len() >= header_end + content_length
    }

    fn split(response: &[u8]) -> Option<(String, String)> {
        let header_end = Self::header_end(response)?;
        let head = String::from_utf8_lossy(&response[..header_end]).into_owned();
        let body = String::from_utf8(response[header_end..].to_vec()).ok()?;
        Some((head, body))
    }

    fn content_length(headers: &str) -> Option<usize> {
        headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
    }
}

pub(super) struct SocketHost;

impl SocketHost {
    pub(super) fn format(address: SocketAddr) -> String {
        if address.ip().is_ipv6() {
            format!("[{}]:{}", address.ip(), address.port())
        } else {
            address.to_string()
        }
    }
}
