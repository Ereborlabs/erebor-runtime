use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cdp_protocol::{target, types::Method};
use erebor_runtime_core::{BrowserCdpRuntimeConfig, BrowserLaunchConfig, LocalEnforcementEngine};
use erebor_runtime_events::{ActorIdentity, SessionId};
use erebor_runtime_policy::PolicySet;
use serde::Deserialize;
use tokio_tungstenite::tungstenite::{connect, Message};
use tracing::{debug, info};

use crate::{CdpError, CdpProxyServer, CdpProxyServerConfig, CdpSessionContext};

const DEVTOOLS_WAIT: Duration = Duration::from_secs(10);
const DEVTOOLS_POLL: Duration = Duration::from_millis(50);
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);

pub struct BrowserSessionManager {
    config: BrowserCdpRuntimeConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
}

impl BrowserSessionManager {
    #[must_use]
    pub fn new(
        config: BrowserCdpRuntimeConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
    ) -> Self {
        Self {
            config,
            policy_set,
            context,
        }
    }

    pub async fn create_session(self) -> Result<GovernedBrowserSession, CdpError> {
        let upstream = BrowserUpstream::prepare(&self.config)?;
        let auth_token = session_auth_token(&self.context);
        let policy_set_label = format!("local:{} policies", self.policy_set.policy_count());
        let engine = LocalEnforcementEngine::new(self.policy_set);
        let server = CdpProxyServer::bind(
            CdpProxyServerConfig {
                listen: self.config.listen(),
                browser_url: upstream.endpoint.clone(),
                context: self.context.clone(),
                auth_token: Some(auth_token.clone()),
            },
            engine,
        )
        .await?;
        let public_endpoint = governed_endpoint(server.local_addr()?, &auth_token);
        let lease_id = session_lease_id(&self.context);
        let metadata = BrowserSessionMetadata {
            session_id: self.context.session_id.clone(),
            actor: self.context.actor.clone(),
            agent: Some(self.context.actor.id.clone()),
            workspace: std::env::current_dir().ok(),
            policy_set: policy_set_label,
            browser_profile: upstream.browser_profile(),
            approval_channel: String::from("deferred"),
            audit_sink: String::from("runtime"),
            public_endpoint: public_endpoint.clone(),
            owned_browser: upstream.owned_browser.is_some(),
            lease_id: lease_id.clone(),
        };

        info!(
            endpoint = %public_endpoint,
            owned_browser = metadata.owned_browser,
            lease_id = %lease_id,
            "created governed browser session"
        );

        Ok(GovernedBrowserSession {
            server,
            owned_browser: upstream.owned_browser,
            metadata,
            public_endpoint,
            lease_id,
        })
    }
}

pub struct GovernedBrowserSession {
    server: CdpProxyServer,
    owned_browser: Option<OwnedBrowserProcess>,
    metadata: BrowserSessionMetadata,
    public_endpoint: String,
    lease_id: String,
}

impl GovernedBrowserSession {
    #[must_use]
    pub fn public_endpoint(&self) -> &str {
        &self.public_endpoint
    }

    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub const fn metadata(&self) -> &BrowserSessionMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn owns_browser(&self) -> bool {
        self.owned_browser.is_some()
    }

    pub(crate) async fn run(self) -> Result<(), CdpError> {
        let browser_guard = self.owned_browser;
        let result = self.server.run().await;
        drop(browser_guard);
        result
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BrowserSessionMetadata {
    pub session_id: SessionId,
    pub actor: ActorIdentity,
    pub agent: Option<String>,
    pub workspace: Option<PathBuf>,
    pub policy_set: String,
    pub browser_profile: Option<PathBuf>,
    pub approval_channel: String,
    pub audit_sink: String,
    pub public_endpoint: String,
    pub owned_browser: bool,
    pub lease_id: String,
}

struct BrowserUpstream {
    endpoint: String,
    owned_browser: Option<OwnedBrowserProcess>,
}

impl BrowserUpstream {
    fn prepare(config: &BrowserCdpRuntimeConfig) -> Result<Self, CdpError> {
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

    fn browser_profile(&self) -> Option<PathBuf> {
        self.owned_browser
            .as_ref()
            .map(|browser| browser.user_data_dir.clone())
    }
}

struct OwnedBrowserProcess {
    child: Child,
    user_data_dir: PathBuf,
    cleanup_user_data_dir: bool,
    browser_ws_url: String,
    page_ws_url: String,
}

impl OwnedBrowserProcess {
    fn launch(config: &BrowserLaunchConfig) -> Result<Self, CdpError> {
        let binary = config
            .executable()
            .map(Path::to_path_buf)
            .or_else(chrome_binary_path)
            .ok_or_else(|| {
                CdpError::browser_launch("no local Chrome or Chromium binary was found")
            })?;
        let (user_data_dir, cleanup_user_data_dir) = match config.user_data_dir() {
            Some(path) => (path.to_path_buf(), false),
            None => (temp_profile_dir(), true),
        };

        fs::create_dir_all(&user_data_dir).map_err(CdpError::io)?;
        let mut command = Command::new(&binary);
        if config.headless() {
            command.arg("--headless=new");
        }
        command
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

        debug!(
            binary = %binary.display(),
            profile = %user_data_dir.display(),
            headless = config.headless(),
            "launching owned browser"
        );
        let mut child = command.spawn().map_err(CdpError::io)?;
        let devtools =
            wait_for_devtools_endpoint(&mut child, &user_data_dir.join("DevToolsActivePort"))?;
        let page_ws_url =
            create_page_ws_url(&devtools.browser_ws_url, devtools.port).or_else(|ws_error| {
                wait_for_page_ws_url(&mut child, devtools.port).map_err(|http_error| {
                    CdpError::browser_launch(format!(
                        "could not create Chrome page target through browser websocket \
                         ({ws_error}) or HTTP discovery ({http_error})"
                    ))
                })
            })?;

        Ok(Self {
            child,
            user_data_dir,
            cleanup_user_data_dir,
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

struct DevToolsEndpoint {
    port: u16,
    browser_ws_url: String,
}

#[derive(Debug, Deserialize)]
struct ChromeTargetDescriptor {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: Option<String>,
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

fn wait_for_devtools_endpoint(
    child: &mut Child,
    active_port_file: &Path,
) -> Result<DevToolsEndpoint, CdpError> {
    let deadline = Instant::now() + DEVTOOLS_WAIT;

    loop {
        if let Ok(contents) = fs::read_to_string(active_port_file) {
            let mut lines = contents.lines();
            let Some(port_line) = lines.next() else {
                return Err(CdpError::browser_launch(
                    "Chrome DevToolsActivePort file did not include a port",
                ));
            };
            let port = port_line
                .parse::<u16>()
                .map_err(|error| CdpError::browser_launch(error.to_string()))?;
            let Some(browser_path) = lines.next() else {
                return Err(CdpError::browser_launch(
                    "Chrome DevToolsActivePort file did not include a browser websocket path",
                ));
            };
            let browser_ws_url = if browser_path.starts_with("ws://") {
                browser_path.to_owned()
            } else {
                format!("ws://127.0.0.1:{port}{browser_path}")
            };

            return Ok(DevToolsEndpoint {
                port,
                browser_ws_url,
            });
        }

        if child.try_wait().map_err(CdpError::io)?.is_some() {
            return Err(CdpError::browser_launch(
                "Chrome exited before DevTools became ready",
            ));
        }

        if Instant::now() >= deadline {
            return Err(CdpError::browser_launch(
                "timed out waiting for Chrome DevToolsActivePort",
            ));
        }

        std::thread::sleep(DEVTOOLS_POLL);
    }
}

fn create_page_ws_url(browser_ws_url: &str, port: u16) -> Result<String, CdpError> {
    let (mut socket, _response) = connect(browser_ws_url).map_err(CdpError::websocket)?;
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
        .map_err(CdpError::invalid_protocol)?;
    socket
        .send(Message::Text(payload.into()))
        .map_err(CdpError::websocket)?;

    loop {
        let message = socket.read().map_err(CdpError::websocket)?;
        let Message::Text(text) = message else {
            continue;
        };
        let response: CdpMethodResponse<target::CreateTargetReturnObject> =
            serde_json::from_str(text.as_ref()).map_err(CdpError::invalid_protocol)?;

        if response.id != 1 {
            continue;
        }

        if let Some(error) = response.error {
            return Err(CdpError::browser_launch(format!(
                "Chrome rejected Target.createTarget: {}",
                error.message
            )));
        }

        let result = response.result.ok_or_else(|| {
            CdpError::browser_launch("Chrome Target.createTarget response did not include result")
        })?;

        return Ok(format!(
            "ws://127.0.0.1:{port}/devtools/page/{}",
            result.target_id
        ));
    }
}

fn wait_for_page_ws_url(child: &mut Child, port: u16) -> Result<String, CdpError> {
    let deadline = Instant::now() + DEVTOOLS_WAIT;
    let mut errors = Vec::new();

    loop {
        match fetch_page_ws_url(port) {
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

        if child.try_wait().map_err(CdpError::io)?.is_some() {
            return Err(CdpError::browser_launch(
                "Chrome exited before page target became ready",
            ));
        }

        if Instant::now() >= deadline {
            let reason = errors.last().map_or_else(
                || String::from("timed out waiting for Chrome page websocket"),
                |error| format!("timed out waiting for Chrome page websocket; last error: {error}"),
            );

            return Err(CdpError::browser_launch(reason));
        }

        std::thread::sleep(DEVTOOLS_POLL);
    }
}

fn fetch_page_ws_url(port: u16) -> Result<String, CdpError> {
    let targets: Vec<ChromeTargetDescriptor> = http_get_json(port, "/json/list")?;

    if let Some(page_ws_url) = targets
        .into_iter()
        .find(|target| target.kind == "page")
        .and_then(|target| target.web_socket_debugger_url)
    {
        return Ok(page_ws_url);
    }

    create_page_ws_url_via_http(port)
}

fn create_page_ws_url_via_http(port: u16) -> Result<String, CdpError> {
    let target: ChromeTargetDescriptor = http_put_json(port, "/json/new?about:blank")?;

    target.web_socket_debugger_url.ok_or_else(|| {
        CdpError::browser_launch("Chrome target creation did not return a page websocket")
    })
}

fn http_get_json<T>(port: u16, path: &str) -> Result<T, CdpError>
where
    T: serde::de::DeserializeOwned,
{
    http_json_request(port, "GET", path)
}

fn http_put_json<T>(port: u16, path: &str) -> Result<T, CdpError>
where
    T: serde::de::DeserializeOwned,
{
    http_json_request(port, "PUT", path)
}

fn http_json_request<T>(port: u16, method: &str, path: &str) -> Result<T, CdpError>
where
    T: serde::de::DeserializeOwned,
{
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, HTTP_TIMEOUT).map_err(CdpError::io)?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .map_err(CdpError::io)?;
    stream
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .map_err(CdpError::io)?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(CdpError::io)?;
    let response = read_http_response(&mut stream)?;
    let Some((status_line, body)) = split_http_response(&response) else {
        return Err(CdpError::browser_launch(
            "Chrome returned an invalid HTTP response",
        ));
    };

    if !is_success_status(status_line) {
        return Err(CdpError::browser_launch(format!(
            "Chrome returned HTTP status `{status_line}`"
        )));
    }

    serde_json::from_str(body).map_err(CdpError::invalid_json)
}

fn read_http_response(stream: &mut std::net::TcpStream) -> Result<String, CdpError> {
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
                    return Err(CdpError::io(error));
                }
            }
            Err(error) => return Err(CdpError::io(error)),
        }
    }

    String::from_utf8(response).map_err(|error| {
        CdpError::browser_launch(format!(
            "Chrome returned a non-UTF-8 HTTP response: {error}"
        ))
    })
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

fn chrome_binary_path() -> Option<PathBuf> {
    std::env::var_os("EREBOR_BROWSER_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
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
        "erebor-runtime-owned-browser-{}-{timestamp}",
        std::process::id()
    ))
}

fn governed_endpoint(address: SocketAddr, token: &str) -> String {
    format!("ws://{address}/?erebor_session={token}")
}

fn session_auth_token(context: &CdpSessionContext) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());

    format!(
        "{}-{}-{timestamp}",
        sanitize_token_part(context.session_id.as_str()),
        std::process::id()
    )
}

fn session_lease_id(context: &CdpSessionContext) -> String {
    format!(
        "browser-{}",
        sanitize_token_part(context.session_id.as_str())
    )
}

fn sanitize_token_part(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}
