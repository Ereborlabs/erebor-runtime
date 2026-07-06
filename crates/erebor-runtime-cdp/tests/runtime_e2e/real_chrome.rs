use erebor_runtime_core::SessionSurfaceKind;
use erebor_runtime_e2e::E2eError;
use serde_json::{json, Value};

use crate::support::{
    allow_all_policy, deny_script_eval_policy, real_chrome_available, CdpE2eHarness,
};

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
