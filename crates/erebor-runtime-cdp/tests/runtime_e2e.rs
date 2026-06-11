use std::{
    io::{Read, Write},
    net::SocketAddr,
    time::Duration,
};

use erebor_runtime_core::SessionSurfaceKind;
use erebor_runtime_e2e::E2eError;
use serde_json::{json, Value};

#[path = "support/common.rs"]
mod common;
#[path = "support/runtime.rs"]
mod support;

use support::{
    allow_all_policy, create_governed_session_with_mini_upstream, deny_payload_script_eval_policy,
    deny_script_eval_policy, deny_target_script_eval_policy, owned_browser_e2e_guard,
    real_chrome_available, require_approval_script_eval_policy, CdpE2eHarness,
};

#[tokio::test]
async fn browser_session_manager_creates_governed_session_with_public_endpoint(
) -> Result<(), E2eError> {
    let session = create_governed_session_with_mini_upstream(allow_all_policy()?).await?;

    assert!(!session.owns_browser());
    assert!(session.public_endpoint().starts_with("ws://127.0.0.1:"));
    assert!(!session.public_endpoint().contains('?'));
    assert_eq!(
        session.metadata().public_endpoint,
        session.public_endpoint()
    );
    assert_eq!(session.metadata().session_id.as_str(), "e2e-cdp-session");
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_starts_and_forwards_allowed_commands() -> Result<(), E2eError> {
    let mut harness = CdpE2eHarness::start_runtime_with_mini_upstream(allow_all_policy()?).await?;
    let running_runtime = harness.running_runtime();

    assert_eq!(running_runtime.surface(), SessionSurfaceKind::BrowserCdp);
    assert!(!harness.endpoint().contains('?'));
    let response = harness
        .send_command(json!({
            "id": 1,
            "method": "Page.navigate",
            "params": {
                "url": "https://example.com/"
            }
        }))
        .await?;
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
async fn browser_cdp_runtime_exposes_governed_discovery_endpoints() -> Result<(), E2eError> {
    let harness = CdpE2eHarness::start_runtime_with_mini_upstream(allow_all_policy()?).await?;
    let endpoint = harness.endpoint().to_owned();
    let port = governed_endpoint_port(&endpoint)?;
    let version = http_get_json(port, "/json/version")?;
    let targets = http_get_json(port, "/json/list")?;

    assert_eq!(
        version.pointer("/webSocketDebuggerUrl"),
        Some(&Value::String(endpoint.clone()))
    );
    assert_eq!(
        targets.pointer("/0/webSocketDebuggerUrl"),
        Some(&Value::String(endpoint))
    );
    assert!(
        !version.to_string().contains("/devtools/browser/"),
        "discovery must not expose Chrome's private browser endpoint"
    );
    assert!(
        !targets.to_string().contains("/devtools/browser/"),
        "target discovery must not expose Chrome's private browser endpoint"
    );
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_masks_owned_browser_discovery_targets() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(allow_all_policy()?).await?;
    let endpoint = harness.endpoint().to_owned();
    let mut client = harness.browser_level_client().await?;
    client
        .navigate("data:text/html,erebor-discovery-target")
        .await?;
    let targets = http_get_json(governed_endpoint_port(&endpoint)?, "/json/list")?;
    let target_list = targets.as_array().ok_or_else(|| {
        E2eError::external(
            "owned browser discovery target list",
            std::io::Error::other("expected JSON array"),
        )
    })?;

    assert!(target_list.iter().any(|target| {
        target
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| url.contains("erebor-discovery-target"))
    }));
    assert!(target_list.iter().all(|target| {
        target.pointer("/webSocketDebuggerUrl") == Some(&Value::String(endpoint.clone()))
    }));
    assert!(
        !targets.to_string().contains("/devtools/"),
        "owned-browser discovery must not expose Chrome's private endpoint paths"
    );
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_blocks_denied_commands_before_upstream() -> Result<(), E2eError> {
    let mut harness =
        CdpE2eHarness::start_runtime_with_mini_upstream(deny_script_eval_policy()?).await?;
    let response = harness
        .send_command(json!({
            "id": 7,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.localStorage.clear()"
            }
        }))
        .await?;

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
async fn browser_cdp_runtime_holds_approval_required_commands_before_upstream(
) -> Result<(), E2eError> {
    let mut harness =
        CdpE2eHarness::start_runtime_with_mini_upstream(require_approval_script_eval_policy()?)
            .await?;
    let running_runtime = harness.running_runtime();

    assert_eq!(running_runtime.surface(), SessionSurfaceKind::BrowserCdp);
    harness
        .assert_command_has_no_response(
            json!({
                "id": 9,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": "window.localStorage.clear()"
                }
            }),
            Duration::from_millis(100),
        )
        .await?;

    harness
        .assert_no_upstream_command(Duration::from_millis(100))
        .await?;
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_executes_commands_against_owned_chrome() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = support::owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(allow_all_policy()?).await?;
    let running_runtime = harness.running_runtime();

    assert_eq!(running_runtime.surface(), SessionSurfaceKind::BrowserCdp);
    assert!(!harness.endpoint().contains('?'));
    let mut client = harness.browser_level_client().await?;
    let response = client
        .evaluate("window.__erebor = 'owned-allowed'; window.__erebor")
        .await?;

    assert_eq!(
        response.pointer("/result/result/value"),
        Some(&Value::String(String::from("owned-allowed")))
    );
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_blocks_owned_chrome_script_eval_side_effects() -> Result<(), E2eError>
{
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = support::owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(deny_payload_script_eval_policy(
        "owned-denied",
    )?)
    .await?;
    let mut client = harness.browser_level_client().await?;
    let denied = client
        .evaluate("window.__erebor = 'owned-denied'; window.__erebor")
        .await?;
    let browser_state = client.evaluate("window.__erebor ?? null").await?;

    assert_eq!(
        denied.pointer("/error/message"),
        Some(&Value::String(String::from(
            "script payload denied by e2e policy"
        )))
    );
    assert_eq!(
        browser_state.pointer("/result/result/value"),
        Some(&Value::Null)
    );
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_keeps_page_context_across_client_reconnects() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = support::owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(deny_target_script_eval_policy(
        "mail.example.test",
    )?)
    .await?;
    let mut client = harness.browser_level_client().await?;
    let target_id = client.target_id().to_owned();
    client.navigate("data:text/html,mail.example.test").await?;
    let denied = client
        .evaluate("window.__erebor = 'blocked-by-page-context'; window.__erebor")
        .await?;
    let mut reconnected =
        support::BrowserLevelCdpClient::reconnect_to(harness.endpoint(), target_id).await?;
    reconnected.navigate("about:blank").await?;
    let allowed = reconnected
        .evaluate("window.__erebor = 'allowed-by-page-context'; window.__erebor")
        .await?;

    assert_eq!(
        denied.pointer("/error/message"),
        Some(&Value::String(String::from(
            "script evaluation denied for this page"
        )))
    );
    assert_eq!(
        allowed.pointer("/result/result/value"),
        Some(&Value::String(String::from("allowed-by-page-context")))
    );
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_distinguishes_two_owned_browser_targets() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = support::owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(deny_target_script_eval_policy(
        "mail.example.test",
    )?)
    .await?;
    let mut mail_client = harness.browser_level_client().await?;
    mail_client
        .navigate("data:text/html,mail.example.test")
        .await?;
    let calendar_target = mail_client.create_page_target("about:blank").await?;
    let mut calendar_client =
        support::BrowserLevelCdpClient::reconnect_to(harness.endpoint(), calendar_target).await?;
    calendar_client
        .navigate("data:text/html,calendar.example.test")
        .await?;

    let denied = mail_client
        .evaluate("window.__erebor = 'blocked-in-mail'; window.__erebor")
        .await?;
    let allowed = calendar_client
        .evaluate("window.__erebor = 'allowed-in-calendar'; window.__erebor")
        .await?;

    assert_eq!(
        denied.pointer("/error/message"),
        Some(&Value::String(String::from(
            "script evaluation denied for this page"
        )))
    );
    assert_eq!(
        allowed.pointer("/result/result/value"),
        Some(&Value::String(String::from("allowed-in-calendar")))
    );
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_closed_owned_target_commands_fail_safely() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = support::owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(allow_all_policy()?).await?;
    let mut client = harness.browser_level_client().await?;
    let target_id = client.target_id().to_owned();

    let close_response = client.close_target(&target_id).await?;
    let stale_command = client
        .evaluate("window.__erebor = 'should-not-run'; window.__erebor")
        .await?;

    assert!(close_response.get("error").is_none());
    assert!(stale_command.get("error").is_some());
    Ok(())
}

#[tokio::test]
#[ignore = "slow real Chrome validation"]
async fn browser_cdp_runtime_executes_governed_commands_against_real_chrome() -> Result<(), E2eError>
{
    if !real_chrome_available() {
        return Ok(());
    }

    let harness = CdpE2eHarness::start_runtime_with_real_chrome(allow_all_policy()?).await?;
    let running_runtime = harness.running_runtime();

    assert_eq!(running_runtime.surface(), SessionSurfaceKind::BrowserCdp);
    let response = harness
        .send_command(json!({
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor = 'runtime-allowed'; window.__erebor",
                "returnByValue": true
            }
        }))
        .await?;
    let browser_state = harness
        .send_direct_browser_command(json!({
            "id": 2,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor ?? null",
                "returnByValue": true
            }
        }))
        .await?;

    assert_eq!(
        response.pointer("/result/result/value"),
        Some(&Value::String(String::from("runtime-allowed")))
    );
    assert_eq!(
        browser_state.pointer("/result/result/value"),
        Some(&Value::String(String::from("runtime-allowed")))
    );
    Ok(())
}

#[tokio::test]
#[ignore = "slow real Chrome validation"]
async fn browser_cdp_runtime_blocks_real_chrome_script_eval_side_effects() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let harness = CdpE2eHarness::start_runtime_with_real_chrome(deny_script_eval_policy()?).await?;
    let running_runtime = harness.running_runtime();

    assert_eq!(running_runtime.surface(), SessionSurfaceKind::BrowserCdp);
    let response = harness
        .send_command(json!({
            "id": 7,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor = 'runtime-denied'; window.__erebor",
                "returnByValue": true
            }
        }))
        .await?;
    let browser_state = harness
        .send_direct_browser_command(json!({
            "id": 8,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor ?? null",
                "returnByValue": true
            }
        }))
        .await?;

    assert_eq!(response.pointer("/id"), Some(&Value::from(7)));
    assert_eq!(
        response.pointer("/error/message"),
        Some(&Value::String(String::from(
            "script evaluation denied by e2e policy"
        )))
    );
    assert_eq!(
        browser_state.pointer("/result/result/value"),
        Some(&Value::Null)
    );
    Ok(())
}

fn governed_endpoint_port(endpoint: &str) -> Result<u16, E2eError> {
    endpoint
        .strip_prefix("ws://127.0.0.1:")
        .and_then(|suffix| suffix.trim_end_matches('/').parse::<u16>().ok())
        .ok_or_else(|| {
            E2eError::external(
                "governed endpoint parsing",
                std::io::Error::other(format!("unexpected endpoint `{endpoint}`")),
            )
        })
}

fn http_get_json(port: u16, path: &str) -> Result<Value, E2eError> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(E2eError::io)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(E2eError::io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(E2eError::io)?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(E2eError::io)?;

    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(E2eError::io)?;
    let Some((status_line, body)) = response.split_once("\r\n\r\n") else {
        return Err(E2eError::external(
            "governed discovery response",
            std::io::Error::other("missing HTTP response body"),
        ));
    };
    if !status_line.starts_with("HTTP/1.1 200 ") {
        return Err(E2eError::external(
            "governed discovery status",
            std::io::Error::other(status_line.to_owned()),
        ));
    }

    serde_json::from_str(body).map_err(E2eError::json)
}
