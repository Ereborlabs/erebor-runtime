use std::{sync::mpsc, time::Duration};

use erebor_runtime_cdp::{BrowserCdpRuntime, BrowserSessionManager, GovernedBrowserSession};
use erebor_runtime_core::{
    GovernanceRuntime, RunningRuntime, RuntimeConfig, RuntimeError, RuntimeStartPlan,
};
use erebor_runtime_e2e::{
    assert_json_request_has_no_response, send_json_request, E2eError, MiniJsonWebSocketServer,
    MiniSystem,
};
use erebor_runtime_policy::{LocalPolicy, PolicySet};
use serde_json::{json, Value};
use tokio::runtime::Runtime;

pub use crate::common::{
    allow_all_policy, deny_script_eval_policy, real_chrome_available,
    require_approval_script_eval_policy,
};
use crate::common::{mini_cdp_handler, session_context, RealChromeInstance};

pub struct CdpE2eHarness {
    _system: MiniSystem,
    runtime_host: RuntimeHost,
    upstream: Option<MiniJsonWebSocketServer>,
    browser: Option<RealChromeInstance>,
    endpoint: String,
    direct_browser_endpoint: Option<String>,
    running_runtime: RunningRuntime,
}

impl CdpE2eHarness {
    pub async fn start_runtime_with_mini_upstream(policy: LocalPolicy) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
        let browser_url = upstream.endpoint().to_owned();
        let config = browser_cdp_runtime_config(&browser_url)?;
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, config))
                .await
                .map_err(|error| E2eError::external("CDP runtime task", error))??;

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
            .map_err(|error| E2eError::external("real Chrome launch task", error))??;
        let direct_browser_endpoint = browser.page_ws_url().to_owned();
        let config = browser_cdp_runtime_config(&direct_browser_endpoint)?;
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, config))
                .await
                .map_err(|error| E2eError::external("CDP runtime task", error))??;

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
        let config = owned_browser_cdp_runtime_config()?;
        let (runtime_host, running_runtime) =
            tokio::task::spawn_blocking(move || start_browser_cdp_runtime(policy, config))
                .await
                .map_err(|error| E2eError::external("CDP runtime task", error))??;

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

    pub const fn running_runtime(&self) -> &RunningRuntime {
        &self.running_runtime
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

pub fn deny_payload_script_eval_policy(needle: &str) -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        &json!({
            "rules": [
                {
                    "id": "deny-payload-script-eval",
                    "match": {
                        "surface": "browser_cdp",
                        "action": "browser_script_eval",
                        "payload_contains": needle
                    },
                    "decision": "deny",
                    "reason": "script payload denied by e2e policy"
                }
            ]
        })
        .to_string(),
    )
    .map_err(|error| E2eError::external("deny-payload-script-eval policy setup", error))
}

pub fn deny_target_script_eval_policy(target: &str) -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        &json!({
            "rules": [
                {
                    "id": "deny-target-script-eval",
                    "match": {
                        "surface": "browser_cdp",
                        "action": "browser_script_eval",
                        "target_contains": target
                    },
                    "decision": "deny",
                    "reason": "script evaluation denied for this page"
                }
            ]
        })
        .to_string(),
    )
    .map_err(|error| E2eError::external("deny-target-script-eval policy setup", error))
}

pub async fn create_governed_session_with_mini_upstream(
    policy: LocalPolicy,
) -> Result<GovernedBrowserSession, E2eError> {
    let mut system = MiniSystem::new();
    let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
    let config = browser_cdp_runtime_config(upstream.endpoint())?;

    BrowserSessionManager::new(
        config,
        PolicySet::from_policies(vec![policy]),
        session_context(),
    )
    .create_session()
    .await
    .map_err(|error| E2eError::external("governed browser session creation", error))
}

fn start_browser_cdp_runtime(
    policy: LocalPolicy,
    config: erebor_runtime_core::BrowserCdpRuntimeConfig,
) -> Result<(RuntimeHost, RunningRuntime), E2eError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RuntimeError::build_async_runtime)
        .map_err(|error| E2eError::external("CDP runtime executor", error))?;
    let (failures, _failure_rx) = mpsc::channel();
    let browser_runtime = BrowserCdpRuntime::new(
        config,
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

fn owned_browser_cdp_runtime_config(
) -> Result<erebor_runtime_core::BrowserCdpRuntimeConfig, E2eError> {
    let config = RuntimeConfig::from_json_str(
        &json!({
            "policies": ["policies/e2e/browser.json"],
            "governance": {
                "browser_cdp": {
                    "enabled": true,
                    "listen": "127.0.0.1:0",
                    "browser": {
                        "headless": true
                    }
                }
            }
        })
        .to_string(),
    )
    .map_err(|error| E2eError::external("owned browser CDP runtime config", error))?;
    let start_plan = RuntimeStartPlan::from_config(&config)
        .map_err(|error| E2eError::external("owned browser CDP runtime start plan", error))?;

    start_plan.browser_cdp().cloned().ok_or_else(|| {
        E2eError::external("owned browser CDP runtime start plan", MissingRuntimeConfig)
    })
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
