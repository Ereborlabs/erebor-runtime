use std::{net::SocketAddr, sync::Arc, time::Duration};

use erebor_runtime_cdp::{CdpProxyServer, CdpProxyServerConfig, CdpSessionContext};
use erebor_runtime_core::LocalEnforcementEngine;
use erebor_runtime_e2e::{
    send_json_request, E2eError, JsonWebSocketHandler, MiniJsonWebSocketServer, MiniSystem,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicySet};
use serde_json::{json, Value};
use tracing::error;

struct CdpProxyE2eHarness {
    system: MiniSystem,
    upstream: Option<MiniJsonWebSocketServer>,
    proxy_addr: SocketAddr,
}

impl CdpProxyE2eHarness {
    async fn start_with_mini_upstream(policy: LocalPolicy) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let upstream = system.json_websocket_server(mini_cdp_handler()).await?;
        let browser_url = upstream.endpoint().to_owned();
        let proxy_addr = spawn_proxy(&mut system, policy, browser_url).await?;

        Ok(Self {
            system,
            upstream: Some(upstream),
            proxy_addr,
        })
    }

    async fn start_with_browser_url(
        policy: LocalPolicy,
        browser_url: String,
    ) -> Result<Self, E2eError> {
        let mut system = MiniSystem::new();
        let proxy_addr = spawn_proxy(&mut system, policy, browser_url).await?;

        Ok(Self {
            system,
            upstream: None,
            proxy_addr,
        })
    }

    fn proxy_url(&self) -> String {
        let _keep_system_alive = &self.system;
        format!("ws://{}", self.proxy_addr)
    }

    async fn send_command(&self, command: Value) -> Result<Value, E2eError> {
        send_json_request(&self.proxy_url(), command).await
    }

    async fn next_upstream_command(&mut self) -> Result<Value, E2eError> {
        self.upstream
            .as_mut()
            .ok_or_else(|| E2eError::external("mini CDP upstream access", MissingMiniUpstream))?
            .next_message()
            .await
    }

    async fn assert_no_upstream_command(&mut self, duration: Duration) -> Result<(), E2eError> {
        self.upstream
            .as_mut()
            .ok_or_else(|| E2eError::external("mini CDP upstream access", MissingMiniUpstream))?
            .assert_no_message(duration)
            .await
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mini upstream is not configured for this CDP harness")]
struct MissingMiniUpstream;

#[tokio::test]
async fn cdp_proxy_forwards_allowed_commands_to_mini_upstream() -> Result<(), E2eError> {
    let mut harness = CdpProxyE2eHarness::start_with_mini_upstream(allow_all_policy()?).await?;
    let command = json!({
        "id": 1,
        "method": "Page.navigate",
        "params": {
            "url": "https://example.com/"
        }
    });

    let response = harness.send_command(command).await?;
    let upstream_command = harness.next_upstream_command().await?;

    assert_eq!(
        response.pointer("/result/ereborMiniCdp"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        upstream_command.pointer("/method"),
        Some(&Value::String(String::from("Page.navigate")))
    );
    Ok(())
}

#[tokio::test]
async fn cdp_proxy_blocks_denied_commands_before_upstream() -> Result<(), E2eError> {
    let mut harness =
        CdpProxyE2eHarness::start_with_mini_upstream(deny_script_eval_policy()?).await?;
    let command = json!({
        "id": 7,
        "method": "Runtime.evaluate",
        "params": {
            "expression": "window.localStorage.clear()"
        }
    });

    let response = harness.send_command(command).await?;

    assert_eq!(response.pointer("/id"), Some(&Value::from(7)));
    assert_eq!(
        response.pointer("/error/message"),
        Some(&Value::String(String::from(
            "script evaluation denied by e2e policy"
        )))
    );
    harness
        .assert_no_upstream_command(Duration::from_millis(100))
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires EREBOR_E2E_CHROME_WS to point at a running Chrome browser websocket"]
async fn cdp_proxy_can_forward_to_real_chrome_when_configured() -> Result<(), E2eError> {
    let browser_url = std::env::var("EREBOR_E2E_CHROME_WS")
        .map_err(|_| E2eError::missing_env("EREBOR_E2E_CHROME_WS"))?;
    let harness =
        CdpProxyE2eHarness::start_with_browser_url(allow_all_policy()?, browser_url).await?;
    let response = harness
        .send_command(json!({
            "id": 1,
            "method": "Browser.getVersion"
        }))
        .await?;

    assert_eq!(response.pointer("/id"), Some(&Value::from(1)));
    assert!(response.get("result").is_some());
    Ok(())
}

async fn spawn_proxy(
    system: &mut MiniSystem,
    policy: LocalPolicy,
    browser_url: String,
) -> Result<SocketAddr, E2eError> {
    let engine = LocalEnforcementEngine::new(PolicySet::from_policies(vec![policy]));
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

fn allow_all_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(r#"{ "rules": [] }"#)
        .map_err(|error| E2eError::external("allow-all policy setup", error))
}

fn deny_script_eval_policy() -> Result<LocalPolicy, E2eError> {
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

fn session_context() -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new("e2e-cdp-session"),
        actor: ActorIdentity {
            id: String::from("erebor-runtime-cdp-e2e"),
            kind: ActorKind::System,
        },
        timestamp: String::from("2026-05-14T00:00:00Z"),
    }
}
