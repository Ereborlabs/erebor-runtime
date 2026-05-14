#![allow(dead_code)]

use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_cdp::{
    BrowserCdpRuntime, CdpProxyServer, CdpProxyServerConfig, CdpSessionContext,
};
use erebor_runtime_core::{
    GovernanceRuntime, RunningRuntime, RuntimeConfig, RuntimeError, RuntimeStartPlan,
};
use erebor_runtime_e2e::{
    send_json_request, E2eError, JsonWebSocketHandler, MiniJsonWebSocketServer, MiniSystem,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicySet};
use serde_json::{json, Value};
use tokio::runtime::Runtime;
use tracing::error;

pub struct CdpE2eHarness {
    _system: MiniSystem,
    runtime_host: Option<RuntimeHost>,
    upstream: Option<MiniJsonWebSocketServer>,
    browser: Option<RealChromeInstance>,
    endpoint: String,
    direct_browser_endpoint: Option<String>,
    running_runtime: Option<RunningRuntime>,
}

impl CdpE2eHarness {
    pub async fn start_proxy_with_mini_upstream(policy: LocalPolicy) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
        let endpoint = spawn_proxy_server(&mut system, policy, upstream.endpoint().to_owned())
            .await
            .map(|address| format!("ws://{address}"))?;

        Ok(Self {
            _system: system,
            runtime_host: None,
            upstream: Some(upstream),
            browser: None,
            endpoint,
            direct_browser_endpoint: None,
            running_runtime: None,
        })
    }

    pub async fn start_proxy_with_browser_url(
        policy: LocalPolicy,
        browser_url: String,
    ) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let endpoint = spawn_proxy_server(&mut system, policy, browser_url.clone())
            .await
            .map(|address| format!("ws://{address}"))?;

        Ok(Self {
            _system: system,
            runtime_host: None,
            upstream: None,
            browser: None,
            endpoint,
            direct_browser_endpoint: Some(browser_url),
            running_runtime: None,
        })
    }

    pub async fn start_runtime_with_mini_upstream(policy: LocalPolicy) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
        let browser_url = upstream.endpoint().to_owned();
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, browser_url))
                .await
                .map_err(|error| E2eError::external("CDP runtime task", error))??;

        Ok(Self {
            _system: system,
            runtime_host: Some(runtime_host),
            upstream: Some(upstream),
            browser: None,
            endpoint: format!("ws://{}", running_runtime.endpoint()),
            direct_browser_endpoint: None,
            running_runtime: Some(running_runtime),
        })
    }

    pub async fn start_runtime_with_browser_url(
        policy: LocalPolicy,
        browser_url: String,
    ) -> Result<Self, E2eError> {
        let direct_browser_endpoint = browser_url.clone();
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, browser_url))
                .await
                .map_err(|error| E2eError::external("CDP runtime task", error))??;

        Ok(Self {
            _system: MiniSystem::new(),
            runtime_host: Some(runtime_host),
            upstream: None,
            browser: None,
            endpoint: format!("ws://{}", running_runtime.endpoint()),
            direct_browser_endpoint: Some(direct_browser_endpoint),
            running_runtime: Some(running_runtime),
        })
    }

    pub async fn start_proxy_with_real_chrome(policy: LocalPolicy) -> Result<Self, E2eError> {
        let browser = tokio::task::spawn_blocking(RealChromeInstance::launch)
            .await
            .map_err(|error| E2eError::external("real Chrome launch task", error))??;
        let direct_browser_endpoint = browser.page_ws_url().to_owned();
        let mut system = MiniSystem::new();
        let endpoint = spawn_proxy_server(&mut system, policy, direct_browser_endpoint.clone())
            .await
            .map(|address| format!("ws://{address}"))?;

        Ok(Self {
            _system: system,
            runtime_host: None,
            upstream: None,
            browser: Some(browser),
            endpoint,
            direct_browser_endpoint: Some(direct_browser_endpoint),
            running_runtime: None,
        })
    }

    pub async fn start_runtime_with_real_chrome(policy: LocalPolicy) -> Result<Self, E2eError> {
        let browser = tokio::task::spawn_blocking(RealChromeInstance::launch)
            .await
            .map_err(|error| E2eError::external("real Chrome launch task", error))??;
        let direct_browser_endpoint = browser.page_ws_url().to_owned();
        let (runtime_host, running_runtime) = tokio::task::spawn_blocking({
            let browser_url = direct_browser_endpoint.clone();
            move || start_browser_cdp_runtime(policy, browser_url)
        })
        .await
        .map_err(|error| E2eError::external("CDP runtime task", error))??;

        Ok(Self {
            _system: MiniSystem::new(),
            runtime_host: Some(runtime_host),
            upstream: None,
            browser: Some(browser),
            endpoint: format!("ws://{}", running_runtime.endpoint()),
            direct_browser_endpoint: Some(direct_browser_endpoint),
            running_runtime: Some(running_runtime),
        })
    }

    pub async fn send_command(&self, command: Value) -> Result<Value, E2eError> {
        let _keep_runtime_alive = (&self.runtime_host, &self.browser);
        send_json_request(&self.endpoint, command).await
    }

    pub async fn send_direct_browser_command(&self, command: Value) -> Result<Value, E2eError> {
        let endpoint = self
            .direct_browser_endpoint
            .as_deref()
            .ok_or_else(|| E2eError::closed("direct browser CDP endpoint"))?;

        send_json_request(endpoint, command).await
    }

    pub async fn next_upstream_command(&mut self) -> Result<Value, E2eError> {
        self.upstream
            .as_mut()
            .ok_or_else(|| E2eError::external("mini CDP upstream access", MissingMiniUpstream))?
            .next_message()
            .await
    }

    pub async fn assert_no_upstream_command(&mut self, duration: Duration) -> Result<(), E2eError> {
        self.upstream
            .as_mut()
            .ok_or_else(|| E2eError::external("mini CDP upstream access", MissingMiniUpstream))?
            .assert_no_message(duration)
            .await
    }

    pub fn running_runtime(&self) -> Option<&RunningRuntime> {
        self.running_runtime.as_ref()
    }
}

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

fn mini_cdp_handler() -> JsonWebSocketHandler {
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

async fn spawn_proxy_server(
    system: &mut MiniSystem,
    policy: LocalPolicy,
    browser_url: String,
) -> Result<SocketAddr, E2eError> {
    let engine =
        erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![policy]));
    let server = CdpProxyServer::bind(
        CdpProxyServerConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            browser_url,
            context: session_context(),
        },
        engine,
    )
    .await
    .map_err(|error| E2eError::external("CDP proxy bind", error))?;
    let proxy_addr = server
        .local_addr()
        .map_err(|error| E2eError::external("CDP proxy local address", error))?;

    system.spawn("cdp-proxy-server", async move {
        if let Err(error) = server.run().await {
            error!(error = %error, "CDP e2e proxy server exited");
        }
    });

    Ok(proxy_addr)
}

fn start_browser_cdp_runtime(
    policy: LocalPolicy,
    browser_url: String,
) -> Result<(RuntimeHost, RunningRuntime), E2eError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RuntimeError::build_async_runtime)
        .map_err(|error| E2eError::external("CDP runtime executor", error))?;
    let (failures, _failure_rx) = mpsc::channel();
    let browser_runtime = BrowserCdpRuntime::new(
        browser_cdp_runtime_config(&browser_url)?,
        PolicySet::from_policies(vec![policy]),
        session_context(),
    );
    let running_runtime = Box::new(browser_runtime)
        .start(&runtime, failures)
        .map_err(|error| E2eError::external("CDP runtime start", error))?;

    Ok((RuntimeHost::new(runtime), running_runtime))
}

fn browser_cdp_runtime_config(
    browser_url: &str,
) -> Result<erebor_runtime_core::BrowserCdpRuntimeConfig, E2eError> {
    let config = RuntimeConfig::from_json_str(
        &json!({
            "policies": ["policies/e2e/browser.json"],
            "governance": {
                "browser_cdp": {
                    "enabled": true,
                    "listen": "127.0.0.1:0",
                    "browser_url": browser_url
                }
            }
        })
        .to_string(),
    )
    .map_err(|error| E2eError::external("browser CDP runtime config", error))?;
    let start_plan = RuntimeStartPlan::from_config(&config)
        .map_err(|error| E2eError::external("browser CDP runtime start plan", error))?;

    start_plan
        .browser_cdp()
        .cloned()
        .ok_or_else(|| E2eError::external("browser CDP runtime start plan", MissingRuntimeConfig))
}

struct RealChromeInstance {
    child: Child,
    user_data_dir: PathBuf,
    page_ws_url: String,
}

impl RealChromeInstance {
    fn launch() -> Result<Self, E2eError> {
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

    fn page_ws_url(&self) -> &str {
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

struct RuntimeHost {
    runtime: Option<Runtime>,
}

impl RuntimeHost {
    fn new(runtime: Runtime) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }
}

impl Drop for RuntimeHost {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mini upstream is not configured for this CDP harness")]
struct MissingMiniUpstream;

#[derive(Debug, thiserror::Error)]
#[error("browser CDP runtime config was missing from the start plan")]
struct MissingRuntimeConfig;

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
        .or_else(|| find_binary_on_path("google-chrome"))
        .or_else(|| find_binary_on_path("google-chrome-stable"))
        .or_else(|| find_binary_on_path("chromium"))
        .or_else(|| find_binary_on_path("chromium-browser"))
}

fn find_binary_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| candidate.is_file())
    })
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
            return Err(E2eError::timeout("real Chrome DevToolsActivePort"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_page_ws_url(child: &mut Child, port: u16) -> Result<String, E2eError> {
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        match fetch_page_ws_url(port) {
            Ok(page_ws_url) => return Ok(page_ws_url),
            Err(E2eError::Io { .. }) => {}
            Err(E2eError::Json { .. }) => {}
            Err(error) => return Err(error),
        }

        if child.try_wait().map_err(E2eError::io)?.is_some() {
            return Err(E2eError::external(
                "real Chrome page discovery",
                ChromeExitedEarly,
            ));
        }

        if Instant::now() >= deadline {
            return Err(E2eError::timeout("real Chrome page websocket"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn fetch_page_ws_url(port: u16) -> Result<String, E2eError> {
    let targets: Vec<ChromeTargetDescriptor> = http_get_json(port, "/json/list")?;

    targets
        .into_iter()
        .find(|target| target.kind == "page")
        .and_then(|target| target.web_socket_debugger_url)
        .ok_or_else(|| E2eError::external("real Chrome page discovery", MissingPageTarget))
}

fn http_get_json<T>(port: u16, path: &str) -> Result<T, E2eError>
where
    T: serde::de::DeserializeOwned,
{
    let mut stream = std::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
        .map_err(E2eError::io)?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(E2eError::io)?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(E2eError::io)?;
    let Some((status_line, body)) = split_http_response(&response) else {
        return Err(E2eError::external(
            "real Chrome HTTP response parse",
            InvalidHttpResponse,
        ));
    };

    if !status_line.contains("200") {
        return Err(E2eError::external(
            "real Chrome HTTP response status",
            HttpStatus(status_line.to_owned()),
        ));
    }

    serde_json::from_str(body).map_err(E2eError::json)
}

fn split_http_response(response: &str) -> Option<(&str, &str)> {
    let (headers, body) = response.split_once("\r\n\r\n")?;
    let status_line = headers.lines().next()?;

    Some((status_line, body))
}
