use std::{net::SocketAddr, time::Duration};

use erebor_runtime_cdp::{CdpProxyServer, CdpProxyServerConfig};
use erebor_runtime_e2e::{
    assert_json_request_has_no_response, send_json_request, E2eError, MiniJsonWebSocketServer,
    MiniSystem,
};
use erebor_runtime_policy::{LocalPolicy, PolicySet};
use erebor_runtime_telemetry::error;
use serde_json::Value;

pub use crate::common::{
    allow_all_policy, deny_script_eval_policy, real_chrome_available,
    require_approval_script_eval_policy,
};
use crate::common::{
    closed_error, external_error, mini_cdp_handler, session_context, RealChromeInstance,
};

pub struct CdpE2eHarness {
    _system: MiniSystem,
    upstream: Option<MiniJsonWebSocketServer>,
    browser: Option<RealChromeInstance>,
    endpoint: String,
    direct_browser_endpoint: Option<String>,
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
            upstream: Some(upstream),
            browser: None,
            endpoint,
            direct_browser_endpoint: None,
        })
    }

    pub async fn start_proxy_with_real_chrome(policy: LocalPolicy) -> Result<Self, E2eError> {
        let browser = tokio::task::spawn_blocking(RealChromeInstance::launch)
            .await
            .map_err(|error| external_error("real Chrome launch task", error))??;
        let direct_browser_endpoint = browser.page_ws_url().to_owned();
        let mut system = MiniSystem::new();
        let endpoint = spawn_proxy_server(&mut system, policy, direct_browser_endpoint.clone())
            .await
            .map(|address| format!("ws://{address}"))?;

        Ok(Self {
            _system: system,
            upstream: None,
            browser: Some(browser),
            endpoint,
            direct_browser_endpoint: Some(direct_browser_endpoint),
        })
    }

    pub async fn send_command(&self, command: Value) -> Result<Value, E2eError> {
        let _keep_browser_alive = &self.browser;
        send_json_request(&self.endpoint, command).await
    }

    pub async fn assert_command_has_no_response(
        &self,
        command: Value,
        duration: Duration,
    ) -> Result<(), E2eError> {
        let _keep_browser_alive = &self.browser;
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
            audit_jsonl: None,
            audit: erebor_runtime_core::RuntimeAuditConfig::default(),
        },
        engine,
    )
    .await
    .map_err(|error| external_error("CDP proxy bind", error))?;
    let proxy_addr = server
        .local_addr()
        .map_err(|error| external_error("CDP proxy local address", error))?;

    system.spawn("cdp-proxy-server", async move {
        if let Err(error) = server.run().await {
            error!(%error; "CDP e2e proxy server exited");
        }
    });

    Ok(proxy_addr)
}

#[derive(Debug)]
struct MissingMiniUpstream;

impl std::fmt::Display for MissingMiniUpstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("mini upstream is not configured for this CDP harness")
    }
}

impl std::error::Error for MissingMiniUpstream {}
