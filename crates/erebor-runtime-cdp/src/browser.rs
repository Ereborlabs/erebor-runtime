use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cdp_protocol::{target, types::Method};
use erebor_runtime_core::{
    BrowserCdpSurfaceConfig, BrowserLaunchConfig, LocalEnforcementEngine, RuntimeAuditConfig,
};
use erebor_runtime_events::{ActorIdentity, SessionId};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_telemetry::{debug, info};
use serde::Deserialize;
use snafu::ResultExt;
use tokio_tungstenite::tungstenite::{connect, Message};

use crate::{
    error::{BrowserLaunchSnafu, InvalidJsonSnafu, InvalidProtocolSnafu, IoSnafu, WebSocketSnafu},
    CdpError, CdpProxyServer, CdpProxyServerConfig, CdpSessionContext,
};

const DEVTOOLS_WAIT: Duration = Duration::from_secs(10);
const DEVTOOLS_POLL: Duration = Duration::from_millis(50);
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const CHROME_STDERR_LOG: &str = "chrome-stderr.log";
const CHROME_STDERR_EXCERPT_LIMIT: usize = 4_000;
const DEFAULT_BROWSER_FLAGS: &[&str] = &[
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-extensions",
    "--disable-sync",
    "--disable-breakpad",
    "--disable-crash-reporter",
    "--disable-dev-shm-usage",
    "--metrics-recording-only",
    "--remote-debugging-address=127.0.0.1",
];

pub struct BrowserSessionManager {
    config: BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    audit: RuntimeAuditConfig,
}

impl BrowserSessionManager {
    #[must_use]
    pub fn new(
        config: BrowserCdpSurfaceConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
    ) -> Self {
        Self {
            config,
            policy_set,
            context,
            audit_jsonl: None,
            audit: RuntimeAuditConfig::default(),
        }
    }

    #[must_use]
    pub fn with_audit_jsonl(mut self, path: impl Into<PathBuf>) -> Self {
        self.audit_jsonl = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_audit_config(mut self, audit: RuntimeAuditConfig) -> Self {
        self.audit = audit;
        self
    }

    pub async fn create_session(self) -> Result<GovernedBrowserSession, CdpError> {
        let upstream = BrowserUpstream::prepare(&self.config)?;
        let policy_set_label = format!("local:{} policies", self.policy_set.policy_count());
        let engine = LocalEnforcementEngine::new(self.policy_set);
        let audit_sink_label = self.audit_jsonl.as_ref().map_or_else(
            || String::from("runtime"),
            |path| path.display().to_string(),
        );
        let server = CdpProxyServer::bind(
            CdpProxyServerConfig {
                listen: self.config.listen(),
                browser_url: upstream.endpoint.clone(),
                context: self.context.clone(),
                audit_jsonl: self.audit_jsonl,
                audit: self.audit,
            },
            engine,
        )
        .await?;
        let public_endpoint = governed_endpoint(server.local_addr()?);
        let lease_id = session_lease_id(&self.context);
        let metadata = BrowserSessionMetadata {
            session_id: self.context.session_id.clone(),
            actor: self.context.actor.clone(),
            agent: Some(self.context.actor.id.clone()),
            workspace: std::env::current_dir().ok(),
            policy_set: policy_set_label,
            browser_profile: upstream.browser_profile(),
            approval_channel: String::from("deferred"),
            audit_sink: audit_sink_label,
            public_endpoint: public_endpoint.clone(),
            owned_browser: upstream.owned_browser.is_some(),
            lease_id: lease_id.clone(),
        };

        info!(
            session_id = %metadata.session_id.as_str(),
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
    fn prepare(config: &BrowserCdpSurfaceConfig) -> Result<Self, CdpError> {
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
        let launch = OwnedBrowserLaunch::from_config(config)?;
        let stderr_log = fs::File::create(&launch.stderr_log_path).context(IoSnafu)?;

        let mut command = Command::new(&launch.executable.path);
        command
            .args(&launch.args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log));

        debug!(
            browser = %launch.executable.label(),
            binary = %launch.executable.path.display(),
            profile = %launch.user_data_dir.display(),
            stderr = %launch.stderr_log_path.display(),
            headless = launch.options.headless,
            args = ?launch.args,
            "launching owned browser"
        );
        let mut child = command.spawn().context(IoSnafu)?;
        let devtools = wait_for_devtools_endpoint(
            &mut child,
            &launch.user_data_dir.join("DevToolsActivePort"),
            launch.options.remote_debugging_port,
            &launch.stderr_log_path,
        )
        .map_err(|error| enrich_browser_launch_error(error, &launch.stderr_log_path))?;
        let page_ws_url =
            create_page_ws_url(&devtools.browser_ws_url, devtools.port).or_else(|ws_error| {
                wait_for_page_ws_url(&mut child, devtools.port).map_err(|http_error| {
                    BrowserLaunchSnafu {
                        reason: format!(
                            "could not create Chrome page target through browser websocket \
                         ({ws_error}) or HTTP discovery ({http_error})"
                        ),
                    }
                    .build()
                })
            })?;

        Ok(Self {
            child,
            user_data_dir: launch.user_data_dir,
            cleanup_user_data_dir: launch.cleanup_user_data_dir,
            browser_ws_url: devtools.browser_ws_url,
            page_ws_url,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedBrowserLaunch {
    executable: BrowserExecutable,
    user_data_dir: PathBuf,
    cleanup_user_data_dir: bool,
    stderr_log_path: PathBuf,
    options: OwnedBrowserLaunchOptions,
    args: Vec<String>,
}

impl OwnedBrowserLaunch {
    fn from_config(config: &BrowserLaunchConfig) -> Result<Self, CdpError> {
        let executable = BrowserExecutable::from_config(config)?;
        let (user_data_dir, cleanup_user_data_dir) = match config.user_data_dir() {
            Some(path) => (path.to_path_buf(), false),
            None => (temp_profile_dir(), true),
        };
        fs::create_dir_all(&user_data_dir).context(IoSnafu)?;

        let stderr_log_path = user_data_dir.join(CHROME_STDERR_LOG);
        let options = OwnedBrowserLaunchOptions {
            headless: config.headless(),
            user_data_dir: user_data_dir.clone(),
            remote_debugging_port: config.remote_debugging_port(),
        };
        let args = build_browser_launch_args(&options);

        Ok(Self {
            executable,
            user_data_dir,
            cleanup_user_data_dir,
            stderr_log_path,
            options,
            args,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedBrowserLaunchOptions {
    headless: bool,
    user_data_dir: PathBuf,
    remote_debugging_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BrowserExecutable {
    path: PathBuf,
    source: BrowserExecutableSource,
}

impl BrowserExecutable {
    fn from_config(config: &BrowserLaunchConfig) -> Result<Self, CdpError> {
        if let Some(path) = config.executable() {
            return browser_executable_from_config(path);
        }

        browser_executable_from_env()
            .or_else(discover_browser_executable)
            .ok_or_else(|| {
                BrowserLaunchSnafu {
                    reason: String::from("no local Chrome or Chromium binary was found"),
                }
                .build()
            })
    }

    fn label(&self) -> &'static str {
        match &self.source {
            BrowserExecutableSource::Config => "configured",
            BrowserExecutableSource::Env => "env",
            BrowserExecutableSource::Discovered(browser_type) => browser_type.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BrowserExecutableSource {
    Config,
    Env,
    Discovered(BrowserType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserType {
    Chrome,
    Chromium,
}

impl BrowserType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
        }
    }

    fn search_order() -> &'static [Self] {
        &[Self::Chrome, Self::Chromium]
    }

    fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Chrome => &[
                "google-chrome",
                "google-chrome-stable",
                "chrome",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ],
            Self::Chromium => &[
                "chromium",
                "chromium-browser",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ],
        }
    }

    fn find_executable(self) -> Option<PathBuf> {
        self.candidates()
            .iter()
            .find_map(|candidate| resolve_browser_candidate(candidate))
    }
}

fn browser_executable_from_config(path: &Path) -> Result<BrowserExecutable, CdpError> {
    if !is_executable(path) {
        return BrowserLaunchSnafu {
            reason: format!(
                "configured browser executable `{}` was not found or is not executable",
                path.display()
            ),
        }
        .fail();
    }

    Ok(BrowserExecutable {
        path: path.to_path_buf(),
        source: BrowserExecutableSource::Config,
    })
}

fn discover_browser_executable() -> Option<BrowserExecutable> {
    BrowserType::search_order().iter().find_map(|browser_type| {
        browser_type
            .find_executable()
            .map(|path| BrowserExecutable {
                path,
                source: BrowserExecutableSource::Discovered(*browser_type),
            })
    })
}

fn browser_executable_from_env() -> Option<BrowserExecutable> {
    std::env::var_os("EREBOR_BROWSER_BIN")
        .map(PathBuf::from)
        .filter(|path| is_executable(path))
        .map(|path| BrowserExecutable {
            path,
            source: BrowserExecutableSource::Env,
        })
}

fn resolve_browser_candidate(candidate: &str) -> Option<PathBuf> {
    let path = Path::new(candidate);
    if path.is_absolute() {
        return is_executable(path).then(|| path.to_path_buf());
    }

    find_binary_on_path(candidate)
}

fn build_browser_launch_args(options: &OwnedBrowserLaunchOptions) -> Vec<String> {
    let mut args = Vec::new();
    if options.headless {
        push_unique(&mut args, String::from("--headless=new"));
    }
    for flag in DEFAULT_BROWSER_FLAGS {
        push_unique(&mut args, (*flag).to_owned());
    }
    push_unique(
        &mut args,
        format!(
            "--remote-debugging-port={}",
            options.remote_debugging_port.unwrap_or(0)
        ),
    );
    push_unique(
        &mut args,
        format!("--user-data-dir={}", options.user_data_dir.display()),
    );
    push_unique(&mut args, String::from("about:blank"));
    args
}

fn push_unique(args: &mut Vec<String>, arg: String) {
    if !args.iter().any(|existing| existing == &arg) {
        args.push(arg);
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
struct ChromeVersionDescriptor {
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
    configured_port: Option<u16>,
    stderr_log_path: &Path,
) -> Result<DevToolsEndpoint, CdpError> {
    if let Some(port) = configured_port {
        return wait_for_configured_devtools_endpoint(child, port, stderr_log_path);
    }

    let deadline = Instant::now() + DEVTOOLS_WAIT;

    loop {
        if let Ok(contents) = fs::read_to_string(active_port_file) {
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

            return Ok(DevToolsEndpoint {
                port,
                browser_ws_url,
            });
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

fn wait_for_configured_devtools_endpoint(
    child: &mut Child,
    port: u16,
    stderr_log_path: &Path,
) -> Result<DevToolsEndpoint, CdpError> {
    let deadline = Instant::now() + DEVTOOLS_WAIT;
    let mut errors = Vec::new();

    loop {
        if let Some(browser_ws_url) = chrome_stderr_devtools_url(stderr_log_path, port) {
            return Ok(DevToolsEndpoint {
                port,
                browser_ws_url,
            });
        }

        match fetch_browser_ws_url(port) {
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
                    format!("timed out waiting for Chrome fixed-port DevTools; last error: {error}")
                },
            );

            return BrowserLaunchSnafu { reason }.fail();
        }

        std::thread::sleep(DEVTOOLS_POLL);
    }
}

fn enrich_browser_launch_error(error: CdpError, stderr_log_path: &Path) -> CdpError {
    let CdpError::BrowserLaunch { reason, .. } = error else {
        return error;
    };

    let Some(stderr) = chrome_stderr_excerpt(stderr_log_path) else {
        return BrowserLaunchSnafu { reason }.build();
    };

    BrowserLaunchSnafu {
        reason: format!("{reason}; Chrome stderr: {stderr}"),
    }
    .build()
}

fn chrome_stderr_excerpt(stderr_log_path: &Path) -> Option<String> {
    let source = fs::read_to_string(stderr_log_path).ok()?;
    let source = source.trim();
    if source.is_empty() {
        return None;
    }

    if source.chars().count() <= CHROME_STDERR_EXCERPT_LIMIT {
        return Some(source.to_owned());
    }

    let mut tail = source
        .chars()
        .rev()
        .take(CHROME_STDERR_EXCERPT_LIMIT)
        .collect::<Vec<_>>();
    tail.reverse();
    Some(format!("...{}", tail.into_iter().collect::<String>()))
}

fn chrome_stderr_devtools_url(stderr_log_path: &Path, expected_port: u16) -> Option<String> {
    let source = fs::read_to_string(stderr_log_path).ok()?;
    source.lines().find_map(|line| {
        let url = line.trim().strip_prefix("DevTools listening on ")?;
        if endpoint_port(url) == Some(expected_port) {
            Some(url.to_owned())
        } else {
            None
        }
    })
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    let endpoint = endpoint
        .strip_prefix("ws://")
        .or_else(|| endpoint.strip_prefix("http://"))?;
    let host = endpoint.split('/').next().unwrap_or(endpoint);
    host.rsplit_once(':')?.1.parse().ok()
}

fn create_page_ws_url(browser_ws_url: &str, port: u16) -> Result<String, CdpError> {
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
    let payload =
        serde_json::to_string(&create_target.to_method_call(1)).context(InvalidProtocolSnafu)?;
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
                reason: String::from("Chrome Target.createTarget response did not include result"),
            }
            .build()
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

        if child.try_wait().context(IoSnafu)?.is_some() {
            return BrowserLaunchSnafu {
                reason: String::from("Chrome exited before page target became ready"),
            }
            .fail();
        }

        if Instant::now() >= deadline {
            let reason = errors.last().map_or_else(
                || String::from("timed out waiting for Chrome page websocket"),
                |error| format!("timed out waiting for Chrome page websocket; last error: {error}"),
            );

            return BrowserLaunchSnafu { reason }.fail();
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

fn fetch_browser_ws_url(port: u16) -> Result<String, CdpError> {
    let version: ChromeVersionDescriptor = http_get_json(port, "/json/version")?;
    version.web_socket_debugger_url.ok_or_else(|| {
        BrowserLaunchSnafu {
            reason: String::from("Chrome /json/version did not return a browser websocket"),
        }
        .build()
    })
}

fn create_page_ws_url_via_http(port: u16) -> Result<String, CdpError> {
    let target: ChromeTargetDescriptor = http_put_json(port, "/json/new?about:blank")?;

    target.web_socket_debugger_url.ok_or_else(|| {
        BrowserLaunchSnafu {
            reason: String::from("Chrome target creation did not return a page websocket"),
        }
        .build()
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
        std::net::TcpStream::connect_timeout(&address, HTTP_TIMEOUT).context(IoSnafu)?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .context(IoSnafu)?;
    stream
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .context(IoSnafu)?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).context(IoSnafu)?;
    let response = read_http_response(&mut stream)?;
    let Some((status_line, body)) = split_http_response(&response) else {
        return BrowserLaunchSnafu {
            reason: String::from("Chrome returned an invalid HTTP response"),
        }
        .fail();
    };

    if !is_success_status(status_line) {
        return BrowserLaunchSnafu {
            reason: format!("Chrome returned HTTP status `{status_line}`"),
        }
        .fail();
    }

    serde_json::from_str(body).context(InvalidJsonSnafu)
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

fn find_binary_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| is_executable(candidate))
    })
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
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

fn governed_endpoint(address: SocketAddr) -> String {
    format!("ws://{address}/")
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{
        build_browser_launch_args, chrome_stderr_devtools_url, OwnedBrowserLaunchOptions,
        DEFAULT_BROWSER_FLAGS,
    };

    fn has_arg(args: &[String], expected: &str) -> bool {
        args.iter().any(|arg| arg == expected)
    }

    #[test]
    fn browser_launch_args_keep_owned_browser_debugging_flags() {
        let args = build_browser_launch_args(&OwnedBrowserLaunchOptions {
            headless: true,
            user_data_dir: PathBuf::from("/tmp/erebor-owned-browser-test"),
            remote_debugging_port: None,
        });

        assert!(has_arg(&args, "--headless=new"));
        for flag in DEFAULT_BROWSER_FLAGS {
            assert!(has_arg(&args, flag));
        }
        assert!(has_arg(
            &args,
            "--user-data-dir=/tmp/erebor-owned-browser-test"
        ));
        assert_eq!(args.last().map(String::as_str), Some("about:blank"));
    }

    #[test]
    fn browser_launch_args_omit_headless_when_disabled() {
        let args = build_browser_launch_args(&OwnedBrowserLaunchOptions {
            headless: false,
            user_data_dir: PathBuf::from("/tmp/erebor-owned-browser-test"),
            remote_debugging_port: None,
        });

        assert!(!has_arg(&args, "--headless=new"));
        assert!(has_arg(&args, "--remote-debugging-address=127.0.0.1"));
        assert!(has_arg(&args, "--remote-debugging-port=0"));
    }

    #[test]
    fn browser_launch_args_can_pin_private_debugging_port() {
        let args = build_browser_launch_args(&OwnedBrowserLaunchOptions {
            headless: true,
            user_data_dir: PathBuf::from("/tmp/erebor-owned-browser-test"),
            remote_debugging_port: Some(1001),
        });

        assert!(has_arg(&args, "--remote-debugging-address=127.0.0.1"));
        assert!(has_arg(&args, "--remote-debugging-port=1001"));
        assert!(!has_arg(&args, "--remote-debugging-port=0"));
    }

    #[test]
    fn chrome_stderr_devtools_url_matches_expected_port() -> Result<(), Box<dyn std::error::Error>>
    {
        let path =
            std::env::temp_dir().join(format!("erebor-chrome-stderr-{}.log", std::process::id()));
        fs::write(
            &path,
            "DevTools listening on ws://127.0.0.1:1001/devtools/browser/test\n",
        )?;

        assert_eq!(
            chrome_stderr_devtools_url(&path, 1001),
            Some(String::from("ws://127.0.0.1:1001/devtools/browser/test"))
        );
        assert_eq!(chrome_stderr_devtools_url(&path, 1002), None);

        fs::remove_file(path)?;
        Ok(())
    }
}
