use erebor_runtime_core::SessionSurfaceKind;
use erebor_runtime_e2e::E2eError;
use serde_json::Value;

use crate::common::external_error;
use crate::support::{
    allow_all_policy, deny_payload_script_eval_policy, deny_target_script_eval_policy,
    owned_browser_e2e_guard, real_chrome_available, BrowserLevelCdpClient, CdpE2eHarness,
    GovernedDiscoveryClient,
};

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
    let targets = GovernedDiscoveryClient::from_endpoint(&endpoint)?.targets()?;
    let target_list = targets.as_array().ok_or_else(|| {
        external_error(
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
    assert!(!targets.to_string().contains("/devtools/"));
    Ok(())
}

#[tokio::test]
async fn browser_cdp_runtime_executes_commands_against_owned_chrome() -> Result<(), E2eError> {
    if !real_chrome_available() {
        return Ok(());
    }

    let _owned_browser_guard = owned_browser_e2e_guard().await;
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

    let _owned_browser_guard = owned_browser_e2e_guard().await;
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

    let _owned_browser_guard = owned_browser_e2e_guard().await;
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
        BrowserLevelCdpClient::reconnect_to(harness.endpoint(), target_id).await?;
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

    let _owned_browser_guard = owned_browser_e2e_guard().await;
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
        BrowserLevelCdpClient::reconnect_to(harness.endpoint(), calendar_target).await?;
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

    let _owned_browser_guard = owned_browser_e2e_guard().await;
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
