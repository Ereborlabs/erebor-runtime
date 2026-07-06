use std::time::Duration;

use erebor_runtime_core::SessionSurfaceKind;
use erebor_runtime_e2e::E2eError;
use serde_json::{json, Value};

use crate::support::{
    allow_all_policy, deny_script_eval_policy, require_approval_script_eval_policy, CdpE2eHarness,
    GovernedDiscoveryClient,
};

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
    let discovery = GovernedDiscoveryClient::from_endpoint(&endpoint)?;
    let version = discovery.version()?;
    let targets = discovery.targets()?;

    assert_eq!(
        version.pointer("/webSocketDebuggerUrl"),
        Some(&Value::String(endpoint.clone()))
    );
    assert_eq!(
        targets.pointer("/0/webSocketDebuggerUrl"),
        Some(&Value::String(endpoint))
    );
    assert!(!version.to_string().contains("/devtools/browser/"));
    assert!(!targets.to_string().contains("/devtools/browser/"));
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
