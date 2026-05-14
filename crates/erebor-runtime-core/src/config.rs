use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::RuntimeConfigError;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct RuntimeConfig {
    pub policies: Vec<PathBuf>,
    pub governance: GovernanceLayers,
}

impl RuntimeConfig {
    pub fn from_json_str(source: &str) -> Result<Self, RuntimeConfigError> {
        if source.trim().is_empty() {
            return Err(RuntimeConfigError::empty_config());
        }

        let config: Self =
            serde_json::from_str(source).map_err(RuntimeConfigError::invalid_json)?;
        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.policies.is_empty() {
            return Err(RuntimeConfigError::missing_policy());
        }

        if self
            .policies
            .iter()
            .any(|policy| policy.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_policy_path());
        }

        if self.governance.enabled_layers().is_empty() {
            return Err(RuntimeConfigError::no_governance_layers());
        }

        if self.governance.browser_cdp.enabled {
            let Some(browser_url) = self.governance.browser_cdp.browser_url.as_deref() else {
                return Err(RuntimeConfigError::browser_cdp_missing_browser_url());
            };

            if !browser_url.starts_with("ws://") {
                return Err(RuntimeConfigError::browser_cdp_invalid_browser_url());
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn enabled_layers(&self) -> Vec<GovernanceLayer> {
        self.governance.enabled_layers()
    }

    pub fn start_plan(&self) -> Result<RuntimeStartPlan, RuntimeConfigError> {
        RuntimeStartPlan::from_config(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStartPlan {
    policies: Vec<PathBuf>,
    layers: Vec<GovernanceLayer>,
    browser_cdp: Option<BrowserCdpRuntimeConfig>,
}

impl RuntimeStartPlan {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            layers: config.enabled_layers(),
            browser_cdp: config
                .governance
                .browser_cdp
                .enabled
                .then(|| BrowserCdpRuntimeConfig {
                    listen: config.governance.browser_cdp.listen,
                    browser_url: config
                        .governance
                        .browser_cdp
                        .browser_url
                        .clone()
                        .unwrap_or_default(),
                }),
        })
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub fn layers(&self) -> &[GovernanceLayer] {
        &self.layers
    }

    #[must_use]
    pub fn contains_layer(&self, layer: GovernanceLayer) -> bool {
        self.layers.contains(&layer)
    }

    #[must_use]
    pub fn browser_cdp(&self) -> Option<&BrowserCdpRuntimeConfig> {
        self.browser_cdp.as_ref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct GovernanceLayers {
    #[serde(default)]
    pub browser_cdp: BrowserCdpLayerConfig,
    #[serde(default)]
    pub mcp: GovernanceLayerConfig,
    #[serde(default)]
    pub terminal: GovernanceLayerConfig,
    #[serde(default)]
    pub network: GovernanceLayerConfig,
    #[serde(default)]
    pub saas: GovernanceLayerConfig,
    #[serde(default)]
    pub desktop: GovernanceLayerConfig,
    #[serde(default)]
    pub internal_system: GovernanceLayerConfig,
}

impl GovernanceLayers {
    #[must_use]
    pub fn enabled_layers(&self) -> Vec<GovernanceLayer> {
        let candidates = [
            (GovernanceLayer::BrowserCdp, self.browser_cdp.enabled),
            (GovernanceLayer::Mcp, self.mcp.enabled),
            (GovernanceLayer::Terminal, self.terminal.enabled),
            (GovernanceLayer::Network, self.network.enabled),
            (GovernanceLayer::Saas, self.saas.enabled),
            (GovernanceLayer::Desktop, self.desktop.enabled),
            (
                GovernanceLayer::InternalSystem,
                self.internal_system.enabled,
            ),
        ];

        candidates
            .into_iter()
            .filter_map(|(layer, enabled)| enabled.then_some(layer))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct BrowserCdpLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub browser_url: Option<String>,
    #[serde(default = "default_browser_cdp_listen")]
    pub listen: SocketAddr,
}

impl Default for BrowserCdpLayerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            browser_url: None,
            listen: default_browser_cdp_listen(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct GovernanceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserCdpRuntimeConfig {
    listen: SocketAddr,
    browser_url: String,
}

impl BrowserCdpRuntimeConfig {
    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    #[must_use]
    pub fn browser_url(&self) -> &str {
        &self.browser_url
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernanceLayer {
    BrowserCdp,
    Mcp,
    Terminal,
    Network,
    Saas,
    Desktop,
    InternalSystem,
}

impl GovernanceLayer {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserCdp => "browser_cdp",
            Self::Mcp => "mcp",
            Self::Terminal => "terminal",
            Self::Network => "network",
            Self::Saas => "saas",
            Self::Desktop => "desktop",
            Self::InternalSystem => "internal_system",
        }
    }
}

pub fn validate_policy_path(path: &Path) -> Result<(), RuntimeConfigError> {
    if path.as_os_str().is_empty() {
        Err(RuntimeConfigError::empty_policy_path())
    } else {
        Ok(())
    }
}

fn default_browser_cdp_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::{GovernanceLayer, RuntimeConfig, RuntimeConfigError};

    #[test]
    fn loads_config_with_multiple_governance_layers() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;

        assert_eq!(
            config.enabled_layers(),
            vec![GovernanceLayer::BrowserCdp, GovernanceLayer::Terminal]
        );

        Ok(())
    }

    #[test]
    fn rejects_config_without_policies() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::MissingPolicy { .. })
        ));
    }

    #[test]
    fn rejects_empty_policy_paths() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [""],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptyPolicyPath { .. })
        ));
    }

    #[test]
    fn rejects_config_without_enabled_governance_layers() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {}
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::NoGovernanceLayers { .. })
        ));
    }

    #[test]
    fn creates_start_plan_from_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json", "policies/terminal.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo",
                  "listen": "127.0.0.1:3738"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = config.start_plan()?;

        assert_eq!(plan.policies().len(), 2);
        assert!(plan.contains_layer(GovernanceLayer::BrowserCdp));
        assert!(plan.contains_layer(GovernanceLayer::Terminal));
        assert!(!plan.contains_layer(GovernanceLayer::Mcp));
        assert_eq!(
            plan.browser_cdp().map(|config| config.browser_url()),
            Some("ws://127.0.0.1:9222/devtools/browser/demo")
        );
        assert_eq!(
            plan.browser_cdp().map(|config| config.listen()),
            Some(SocketAddr::from(([127, 0, 0, 1], 3738)))
        );

        Ok(())
    }

    #[test]
    fn rejects_browser_cdp_without_browser_url() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": { "enabled": true }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::BrowserCdpMissingBrowserUrl { .. })
        ));
    }

    #[test]
    fn rejects_browser_cdp_without_local_ws_url() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "wss://browser.example/ws"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::BrowserCdpInvalidBrowserUrl { .. })
        ));
    }
}
