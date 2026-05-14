use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_e2e::{E2eError, JsonWebSocketHandler};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::LocalPolicy;
use serde_json::json;

const HTTP_TIMEOUT: Duration = Duration::from_secs(2);

pub fn allow_all_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(r#"{ "rules": [] }"#)
        .map_err(|error| E2eError::external("allow-all policy setup", error))
}

pub fn deny_script_eval_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-script-eval",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_script_eval"
              },
              "decision": "deny",
              "reason": "script evaluation denied by e2e policy"
            }
          ]
        }
        "#,
    )
    .map_err(|error| E2eError::external("deny-script-eval policy setup", error))
}

pub fn require_approval_script_eval_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "approve-script-eval",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_script_eval"
              },
              "decision": "require_approval",
              "reason": "script evaluation requires approval by e2e policy"
            }
          ]
        }
        "#,
    )
    .map_err(|error| E2eError::external("require-approval-script-eval policy setup", error))
}

pub fn session_context() -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new("e2e-cdp-session"),
        actor: ActorIdentity {
            id: String::from("erebor-runtime-cdp-e2e"),
            kind: ActorKind::System,
        },
        timestamp: String::from("2026-05-14T00:00:00Z"),
    }
}

pub fn real_chrome_available() -> bool {
    chrome_binary_path().is_some()
}

pub fn mini_cdp_handler() -> JsonWebSocketHandler {
    Arc::new(|command| {
        command.get("id").cloned().map(|id| {
            json!({
                "id": id,
                "result": {
                    "ereborMiniCdp": true
                }
            })
        })
    })
}

pub struct RealChromeInstance {
    child: Child,
    user_data_dir: PathBuf,
    page_ws_url: String,
}

impl RealChromeInstance {
    pub fn launch() -> Result<Self, E2eError> {
        let Some(binary) = chrome_binary_path() else {
            return Err(E2eError::external(
                "real Chrome binary discovery",
                MissingChromeBinary,
            ));
        };
        let user_data_dir = temp_profile_dir();
        fs::create_dir_all(&user_data_dir).map_err(E2eError::io)?;
        let mut command = Command::new(binary);
        command
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-background-networking")
            .arg("--disable-extensions")
            .arg("--disable-sync")
            .arg("--metrics-recording-only")
            .arg("--remote-debugging-address=127.0.0.1")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(E2eError::io)?;
        let port = wait_for_devtools_port(&mut child, &user_data_dir.join("DevToolsActivePort"))?;
        let page_ws_url = wait_for_page_ws_url(&mut child, port)?;

        Ok(Self {
            child,
            user_data_dir,
            page_ws_url,
        })
    }

    pub fn page_ws_url(&self) -> &str {
        &self.page_ws_url
    }
}

impl Drop for RealChromeInstance {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _kill_result = self.child.kill();
            let _wait_result = self.child.wait();
        }

        let _cleanup_result = fs::remove_dir_all(&self.user_data_dir);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("no local Chrome or Chromium binary was found for CDP e2e")]
struct MissingChromeBinary;

#[derive(Debug, thiserror::Error)]
#[error("real Chrome exited before CDP became ready")]
struct ChromeExitedEarly;

#[derive(Debug, thiserror::Error)]
#[error("real Chrome DevToolsActivePort file did not include a port")]
struct MissingDevToolsPort;

#[derive(Debug, thiserror::Error)]
#[error("real Chrome did not expose a page target")]
struct MissingPageTarget;

#[derive(Debug, thiserror::Error)]
#[error("real Chrome returned an invalid HTTP response")]
struct InvalidHttpResponse;

#[derive(Debug, thiserror::Error)]
#[error("real Chrome returned HTTP status `{0}`")]
struct HttpStatus(String);

#[derive(Debug, serde::Deserialize)]
struct ChromeTargetDescriptor {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: Option<String>,
}

fn chrome_binary_path() -> Option<PathBuf> {
    std::env::var_os("EREBOR_E2E_CHROME_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            std::env::var_os("EREBOR_BROWSER_BIN")
                .map(PathBuf::from)
                .filter(|path| path.is_file())
        })
        .or_else(|| find_binary_on_path("google-chrome"))
        .or_else(|| find_binary_on_path("google-chrome-stable"))
        .or_else(|| find_binary_on_path("chromium"))
        .or_else(|| find_binary_on_path("chromium-browser"))
        .or_else(|| {
            chrome_app_binary("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        })
        .or_else(|| chrome_app_binary("/Applications/Chromium.app/Contents/MacOS/Chromium"))
}

fn find_binary_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn chrome_app_binary(path: &str) -> Option<PathBuf> {
    let path = PathBuf::from(path);
    path.is_file().then_some(path)
}

fn temp_profile_dir() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());

    std::env::temp_dir().join(format!(
        "erebor-runtime-cdp-e2e-{}-{timestamp}",
        std::process::id()
    ))
}

fn wait_for_devtools_port(child: &mut Child, active_port_file: &Path) -> Result<u16, E2eError> {
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        if let Ok(contents) = fs::read_to_string(active_port_file) {
            let Some(port_line) = contents.lines().next() else {
                return Err(E2eError::external(
                    "real Chrome DevTools port file",
                    MissingDevToolsPort,
                ));
            };

            return port_line
                .parse::<u16>()
                .map_err(|error| E2eError::external("real Chrome DevTools port parse", error));
        }

        if child.try_wait().map_err(E2eError::io)?.is_some() {
            return Err(E2eError::external("real Chrome startup", ChromeExitedEarly));
        }

        if Instant::now() >= deadline {
            return Err(E2eError::timeout("real Chrome DevTools startup"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_page_ws_url(child: &mut Child, port: u16) -> Result<String, E2eError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut errors = Vec::new();

    loop {
        match fetch_page_ws_url(port) {
            Ok(page_ws_url) => return Ok(page_ws_url),
            Err(
                error @ (E2eError::Io { .. } | E2eError::Json { .. } | E2eError::External { .. }),
            ) => {
                errors.push(error.to_string());
            }
            Err(error) => return Err(error),
        }

        if child.try_wait().map_err(E2eError::io)?.is_some() {
            return Err(E2eError::external("real Chrome startup", ChromeExitedEarly));
        }

        if Instant::now() >= deadline {
            let operation = errors.last().map_or_else(
                || String::from("real Chrome page websocket"),
                |error| format!("real Chrome page websocket; last error: {error}"),
            );

            return Err(E2eError::timeout(operation));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn fetch_page_ws_url(port: u16) -> Result<String, E2eError> {
    let targets: Vec<ChromeTargetDescriptor> = http_get_json(port, "/json/list")?;

    if let Some(page_ws_url) = targets
        .into_iter()
        .find(|target| target.kind == "page")
        .and_then(|target| target.web_socket_debugger_url)
    {
        return Ok(page_ws_url);
    }

    create_page_ws_url(port)
}

fn create_page_ws_url(port: u16) -> Result<String, E2eError> {
    let target: ChromeTargetDescriptor = http_put_json(port, "/json/new?about:blank")?;

    target
        .web_socket_debugger_url
        .ok_or_else(|| E2eError::external("real Chrome page target", MissingPageTarget))
}

fn http_get_json<T>(port: u16, path: &str) -> Result<T, E2eError>
where
    T: serde::de::DeserializeOwned,
{
    http_json_request(port, "GET", path)
}

fn http_put_json<T>(port: u16, path: &str) -> Result<T, E2eError>
where
    T: serde::de::DeserializeOwned,
{
    http_json_request(port, "PUT", path)
}

fn http_json_request<T>(port: u16, method: &str, path: &str) -> Result<T, E2eError>
where
    T: serde::de::DeserializeOwned,
{
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, HTTP_TIMEOUT).map_err(E2eError::io)?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .map_err(E2eError::io)?;
    stream
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .map_err(E2eError::io)?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(E2eError::io)?;
    let response = read_http_response(&mut stream)?;
    let Some((status_line, body)) = split_http_response(&response) else {
        return Err(E2eError::external(
            "real Chrome HTTP response",
            InvalidHttpResponse,
        ));
    };

    if !is_success_status(status_line) {
        return Err(E2eError::external(
            "real Chrome HTTP status",
            HttpStatus(status_line.to_owned()),
        ));
    }

    serde_json::from_str(body).map_err(E2eError::json)
}

fn read_http_response(stream: &mut std::net::TcpStream) -> Result<String, E2eError> {
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                response.extend_from_slice(&buffer[..bytes_read]);
                if http_response_complete(&response) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if http_response_complete(&response) {
                    break;
                }

                if Instant::now() >= deadline {
                    return Err(E2eError::io(error));
                }
            }
            Err(error) => return Err(E2eError::io(error)),
        }
    }

    String::from_utf8(response)
        .map_err(|error| E2eError::external("real Chrome HTTP response", error))
}

fn http_response_complete(response: &[u8]) -> bool {
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

fn split_http_response(response: &str) -> Option<(&str, &str)> {
    let (headers, body) = response.split_once("\r\n\r\n")?;
    let status_line = headers.lines().next()?;

    Some((status_line, body))
}
