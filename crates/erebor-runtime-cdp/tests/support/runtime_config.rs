use erebor_runtime_core::{BrowserCdpSurfaceConfig, RuntimeConfig, SessionSurfaceStartPlan};
use erebor_runtime_e2e::E2eError;
use serde_json::json;

use crate::common::external_error;

pub(super) struct BrowserCdpRuntimeConfigFixture;

impl BrowserCdpRuntimeConfigFixture {
    pub(super) fn for_upstream(browser_url: &str) -> Result<BrowserCdpSurfaceConfig, E2eError> {
        let config = RuntimeConfig::from_json_str(
            &json!({
                "policies": ["policies/e2e/browser.json"],
                "surfaces": {
                    "browser_cdp": {
                        "enabled": true,
                        "listen": "127.0.0.1:0",
                        "browser_url": browser_url
                    }
                }
            })
            .to_string(),
        )
        .map_err(|error| external_error("browser CDP runtime config", error))?;
        Self::browser_cdp_config(config, "browser CDP runtime")
    }

    pub(super) fn owned_browser() -> Result<BrowserCdpSurfaceConfig, E2eError> {
        let config = RuntimeConfig::from_json_str(
            &json!({
                "policies": ["policies/e2e/browser.json"],
                "surfaces": {
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
        .map_err(|error| external_error("owned browser CDP runtime config", error))?;
        Self::browser_cdp_config(config, "owned browser CDP runtime")
    }

    fn browser_cdp_config(
        config: RuntimeConfig,
        operation: &'static str,
    ) -> Result<BrowserCdpSurfaceConfig, E2eError> {
        let start_plan = SessionSurfaceStartPlan::from_config(&config)
            .map_err(|error| external_error(format!("{operation} start plan"), error))?;

        start_plan
            .browser_cdp()
            .cloned()
            .ok_or_else(|| external_error(format!("{operation} start plan"), MissingRuntimeConfig))
    }
}

#[derive(Debug)]
struct MissingRuntimeConfig;

impl std::fmt::Display for MissingRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("browser CDP runtime config was missing from the start plan")
    }
}

impl std::error::Error for MissingRuntimeConfig {}
