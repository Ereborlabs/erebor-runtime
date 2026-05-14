use std::time::Duration;

use erebor_runtime_e2e::E2eError;
use serde_json::{json, Value};

mod support;

use support::{
    allow_all_policy, deny_script_eval_policy, real_chrome_available,
    require_approval_script_eval_policy, CdpE2eHarness,
};

#[tokio::test]
async fn cdp_proxy_forwards_allowed_commands_to_mini_upstream() -> Result<(), E2eError> {
    let mut harness = CdpE2eHarness::start_proxy_with_mini_upstream(allow_all_policy()?).await?;
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
async fn cdp_proxy_blocks_denied_commands_before_upstream() -> Result<(), E2eError> {
    let mut harness =
        CdpE2eHarness::start_proxy_with_mini_upstream(deny_script_eval_policy()?).await?;
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
async fn cdp_proxy_holds_approval_required_commands_before_upstream() -> Result<(), E2eError> {
    let mut harness =
        CdpE2eHarness::start_proxy_with_mini_upstream(require_approval_script_eval_policy()?)
            .await?;
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
#[ignore = "slow real Chrome validation"]
async fn cdp_proxy_executes_governed_commands_against_real_chrome() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let harness = CdpE2eHarness::start_proxy_with_real_chrome(allow_all_policy()?).await?;
    let response = harness
        .send_command(json!({
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor = 'proxy-allowed'; window.__erebor",
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
        Some(&Value::String(String::from("proxy-allowed")))
    );
    assert_eq!(
        browser_state.pointer("/result/result/value"),
        Some(&Value::String(String::from("proxy-allowed")))
    );
    Ok(())
}

#[tokio::test]
#[ignore = "slow real Chrome validation"]
async fn cdp_proxy_blocks_real_chrome_script_eval_side_effects() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let harness = CdpE2eHarness::start_proxy_with_real_chrome(deny_script_eval_policy()?).await?;
    let response = harness
        .send_command(json!({
            "id": 7,
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor = 'proxy-denied'; window.__erebor",
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
