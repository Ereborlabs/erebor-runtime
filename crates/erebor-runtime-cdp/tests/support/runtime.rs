use std::{
    sync::{mpsc, OnceLock},
    time::Duration,
};

use erebor_runtime_cdp::{BrowserCdpSurface, BrowserSessionManager, GovernedBrowserSession};
use erebor_runtime_core::{RunningSessionSurface, RuntimeError, SessionSurfaceService};
use erebor_runtime_e2e::{
    assert_json_request_has_no_response, send_json_request, E2eError, MiniJsonWebSocketServer,
    MiniSystem,
};
use erebor_runtime_policy::{LocalPolicy, PolicySet};
use serde_json::Value;
use snafu::Location;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, MutexGuard};

#[path = "browser_client.rs"]
mod browser_client;
#[path = "discovery.rs"]
mod discovery;
#[path = "runtime_config.rs"]
mod runtime_config;

pub use crate::common::{
    allow_all_policy, deny_payload_script_eval_policy, deny_script_eval_policy,
    deny_target_script_eval_policy, real_chrome_available, require_approval_script_eval_policy,
};
pub use browser_client::BrowserLevelCdpClient;
pub use discovery::GovernedDiscoveryClient;

use crate::common::{
    closed_error, external_error, mini_cdp_handler, session_context, RealChromeInstance,
};
use runtime_config::BrowserCdpRuntimeConfigFixture;

pub struct CdpE2eHarness {
    _system: MiniSystem,
    runtime_host: RuntimeHost,
    upstream: Option<MiniJsonWebSocketServer>,
    browser: Option<RealChromeInstance>,
    endpoint: String,
    direct_browser_endpoint: Option<String>,
    running_runtime: RunningSessionSurface,
}

static OWNED_BROWSER_E2E_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub async fn owned_browser_e2e_guard() -> MutexGuard<'static, ()> {
    OWNED_BROWSER_E2E_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await
}

impl CdpE2eHarness {
    pub async fn start_runtime_with_mini_upstream(policy: LocalPolicy) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
        let browser_url = upstream.endpoint().to_owned();
        let config = BrowserCdpRuntimeConfigFixture::for_upstream(&browser_url)?;
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, config))
                .await
                .map_err(|error| external_error("CDP runtime task", error))??;

        Ok(Self {
            _system: system,
            runtime_host,
            upstream: Some(upstream),
            browser: None,
            endpoint: running_runtime.endpoint().to_owned(),
            direct_browser_endpoint: None,
            running_runtime,
        })
    }

    pub async fn start_runtime_with_real_chrome(policy: LocalPolicy) -> Result<Self, E2eError> {
        let browser = tokio::task::spawn_blocking(RealChromeInstance::launch)
            .await
            .map_err(|error| external_error("real Chrome launch task", error))??;
        let direct_browser_endpoint = browser.page_ws_url().to_owned();
        let config = BrowserCdpRuntimeConfigFixture::for_upstream(&direct_browser_endpoint)?;
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, config))
                .await
                .map_err(|error| external_error("CDP runtime task", error))??;

        Ok(Self {
            _system: MiniSystem::new(),
            runtime_host,
            upstream: None,
            browser: Some(browser),
            endpoint: running_runtime.endpoint().to_owned(),
            direct_browser_endpoint: Some(direct_browser_endpoint),
            running_runtime,
        })
    }

    pub async fn start_runtime_with_owned_browser(policy: LocalPolicy) -> Result<Self, E2eError> {
        let config = BrowserCdpRuntimeConfigFixture::owned_browser()?;
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, config))
                .await
                .map_err(|error| external_error("CDP runtime task", error))??;

        Ok(Self {
            _system: MiniSystem::new(),
            runtime_host,
            upstream: None,
            browser: None,
            endpoint: running_runtime.endpoint().to_owned(),
            direct_browser_endpoint: None,
            running_runtime,
        })
    }

    pub async fn send_command(&self, command: Value) -> Result<Value, E2eError> {
        let _keep_runtime_alive = (&self.runtime_host, &self.browser);
        send_json_request(&self.endpoint, command).await
    }

    pub async fn browser_level_client(&self) -> Result<BrowserLevelCdpClient, E2eError> {
        let _keep_runtime_alive = (&self.runtime_host, &self.browser);
        BrowserLevelCdpClient::connect(&self.endpoint).await
    }

    pub async fn assert_command_has_no_response(
        &self,
        command: Value,
        duration: Duration,
    ) -> Result<(), E2eError> {
        let _keep_runtime_alive = (&self.runtime_host, &self.browser);
        assert_json_request_has_no_response(&self.endpoint, command, duration).await
    }

    pub async fn send_direct_browser_command(&self, command: Value) -> Result<Value, E2eError> {
        let endpoint = self
            .direct_browser_endpoint
            .as_deref()
            .ok_or_else(|| closed_error("direct browser CDP endpoint"))?;

        send_json_request(endpoint, command).await
    }

    pub async fn next_upstream_command(&mut self) -> Result<Value, E2eError> {
        self.upstream
            .as_mut()
            .ok_or_else(|| external_error("mini CDP upstream access", MissingMiniUpstream))?
            .next_message()
            .await
    }

    pub async fn assert_no_upstream_command(&mut self, duration: Duration) -> Result<(), E2eError> {
        self.upstream
            .as_mut()
            .ok_or_else(|| external_error("mini CDP upstream access", MissingMiniUpstream))?
            .assert_no_message(duration)
            .await
    }

    pub const fn running_runtime(&self) -> &RunningSessionSurface {
        &self.running_runtime
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

pub async fn create_governed_session_with_mini_upstream(
    policy: LocalPolicy,
) -> Result<GovernedBrowserSession, E2eError> {
    let mut system = MiniSystem::new();
    let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
    let config = BrowserCdpRuntimeConfigFixture::for_upstream(upstream.endpoint())?;

    BrowserSessionManager::new(
        config,
        PolicySet::from_policies(vec![policy]),
        session_context(),
    )
    .create_session()
    .await
    .map_err(|error| external_error("governed browser session creation", error))
}

fn start_browser_cdp_runtime(
    policy: LocalPolicy,
    config: erebor_runtime_core::BrowserCdpSurfaceConfig,
) -> Result<(RuntimeHost, RunningSessionSurface), E2eError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| RuntimeError::BuildAsyncRuntime {
            source,
            location: Location::default(),
        })
        .map_err(|error| external_error("CDP runtime executor", error))?;
    let (failures, _failure_rx) = mpsc::channel();
    let browser_runtime = BrowserCdpSurface::new(
        config,
        PolicySet::from_policies(vec![policy]),
        session_context(),
    );
    let running_runtime = Box::new(browser_runtime)
        .start(&runtime, failures)
        .map_err(|error| external_error("CDP runtime start", error))?;

    Ok((RuntimeHost::new(runtime), running_runtime))
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

macro_rules! simple_error {
    ($name:ident, $message:literal) => {
        #[derive(Debug)]
        struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str($message)
            }
        }

        impl std::error::Error for $name {}
    };
}

simple_error!(
    MissingMiniUpstream,
    "mini upstream is not configured for this CDP harness"
);
