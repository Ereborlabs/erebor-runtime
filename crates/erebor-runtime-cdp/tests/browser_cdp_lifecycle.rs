use erebor_runtime_core::SessionSurfaceKind;
use erebor_runtime_e2e::E2eError;
use serde_json::Value;

#[path = "support/common.rs"]
#[allow(dead_code, unused_imports)]
mod common;
#[path = "support/runtime.rs"]
#[allow(dead_code, unused_imports)]
mod support;

use support::{
    deny_payload_script_eval_policy, owned_browser_e2e_guard, real_chrome_available, CdpE2eHarness,
    GovernedDiscoveryClient,
};

#[tokio::test]
async fn owned_browser_lifecycle_masks_raw_cdp_and_blocks_denied_script_payload(
) -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = owned_browser_e2e_guard().await;
    let harness = CdpE2eHarness::start_runtime_with_owned_browser(deny_payload_script_eval_policy(
        "lifecycle-denied",
    )?)
    .await?;
    let endpoint = harness.endpoint().to_owned();

    assert_eq!(
        harness.running_runtime().surface(),
        SessionSurfaceKind::BrowserCdp
    );
    assert!(endpoint.starts_with("ws://127.0.0.1:"));
    assert!(!endpoint.contains('?'));

    let discovery = GovernedDiscoveryClient::from_endpoint(&endpoint)?;
    let version = discovery.version()?;
    let targets = discovery.targets()?;
    assert_eq!(
        version.pointer("/webSocketDebuggerUrl"),
        Some(&Value::String(endpoint.clone()))
    );
    assert!(targets.to_string().contains("webSocketDebuggerUrl"));
    assert!(
        !version.to_string().contains("/devtools/"),
        "version discovery must not expose Chrome's private endpoint path"
    );
    assert!(
        !targets.to_string().contains("/devtools/"),
        "target discovery must not expose Chrome's private endpoint paths"
    );

    let mut client = harness.browser_level_client().await?;
    client
        .navigate("data:text/html,erebor-cdp-lifecycle")
        .await?;
    let denied = client
        .evaluate("window.__ereborLifecycle = 'lifecycle-denied'; window.__ereborLifecycle")
        .await?;
    let browser_state = client.evaluate("window.__ereborLifecycle ?? null").await?;

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
