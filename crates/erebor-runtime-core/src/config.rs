use std::path::{Path, PathBuf};

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
            return Err(RuntimeConfigError::EmptyConfig);
        }

        let config: Self =
            serde_json::from_str(source).map_err(|error| RuntimeConfigError::InvalidJson {
                reason: error.to_string(),
            })?;
        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.policies.is_empty() {
            return Err(RuntimeConfigError::MissingPolicy);
        }

        if self
            .policies
            .iter()
            .any(|policy| policy.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::EmptyPolicyPath);
        }

        if self.governance.enabled_layers().is_empty() {
            return Err(RuntimeConfigError::NoGovernanceLayers);
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
}

impl RuntimeStartPlan {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            layers: config.enabled_layers(),
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct GovernanceLayers {
    #[serde(default)]
    pub browser_cdp: GovernanceLayerConfig,
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
            (GovernanceLayer::BrowserCdp, &self.browser_cdp),
            (GovernanceLayer::Mcp, &self.mcp),
            (GovernanceLayer::Terminal, &self.terminal),
            (GovernanceLayer::Network, &self.network),
            (GovernanceLayer::Saas, &self.saas),
            (GovernanceLayer::Desktop, &self.desktop),
            (GovernanceLayer::InternalSystem, &self.internal_system),
        ];

        candidates
            .into_iter()
            .filter_map(|(layer, config)| config.enabled.then_some(layer))
            .collect()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct GovernanceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
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
        Err(RuntimeConfigError::EmptyPolicyPath)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{GovernanceLayer, RuntimeConfig, RuntimeConfigError};

    #[test]
    fn loads_config_with_multiple_governance_layers() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": { "enabled": true },
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
                "browser_cdp": { "enabled": true }
              }
            }
            "#,
        );

        assert_eq!(error, Err(RuntimeConfigError::MissingPolicy));
    }

    #[test]
    fn rejects_empty_policy_paths() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [""],
              "governance": {
                "browser_cdp": { "enabled": true }
              }
            }
            "#,
        );

        assert_eq!(error, Err(RuntimeConfigError::EmptyPolicyPath));
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

        assert_eq!(error, Err(RuntimeConfigError::NoGovernanceLayers));
    }

    #[test]
    fn creates_start_plan_from_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json", "policies/terminal.json"],
              "governance": {
                "browser_cdp": { "enabled": true },
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

        Ok(())
    }
}
