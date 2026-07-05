use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use super::SurfacePolicyResolver;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct BrowserCdpSurfaceLayerConfig {
    pub enabled: bool,
    pub policies: Vec<PathBuf>,
    pub browser_url: Option<String>,
    pub listen: SocketAddr,
    pub browser: BrowserLaunchLayerConfig,
}

impl Default for BrowserCdpSurfaceLayerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policies: Vec::new(),
            browser_url: None,
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            browser: BrowserLaunchLayerConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct BrowserLaunchLayerConfig {
    pub executable: Option<PathBuf>,
    pub user_data_dir: Option<PathBuf>,
    pub remote_debugging_port: Option<u16>,
    pub headless: bool,
}

impl Default for BrowserLaunchLayerConfig {
    fn default() -> Self {
        Self {
            executable: None,
            user_data_dir: None,
            remote_debugging_port: None,
            headless: true,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserCdpSurfaceConfig {
    policies: Vec<PathBuf>,
    listen: SocketAddr,
    browser_url: Option<String>,
    browser: BrowserLaunchConfig,
}

impl BrowserCdpSurfaceConfig {
    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(in crate::config) fn set_listen(&mut self, listen: SocketAddr) {
        self.listen = listen;
    }

    #[must_use]
    pub fn from_template_for_runtime_browser(
        template: &Self,
        listen: SocketAddr,
        remote_debugging_port: Option<u16>,
    ) -> Self {
        let mut config = template.clone();
        config.listen = listen;
        config.browser.remote_debugging_port = remote_debugging_port;
        config
    }

    #[must_use]
    pub fn browser_url(&self) -> Option<&str> {
        self.browser_url.as_deref()
    }

    #[must_use]
    pub const fn browser(&self) -> &BrowserLaunchConfig {
        &self.browser
    }

    #[must_use]
    pub const fn owns_browser(&self) -> bool {
        self.browser_url.is_none()
    }

    pub(in crate::config) fn from_layer(
        config: &BrowserCdpSurfaceLayerConfig,
        default_policies: Vec<PathBuf>,
    ) -> Self {
        Self {
            policies: SurfacePolicyResolver::resolve(&config.policies, default_policies),
            listen: config.listen,
            browser_url: config.browser_url.clone(),
            browser: config.browser.clone().into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserLaunchConfig {
    executable: Option<PathBuf>,
    user_data_dir: Option<PathBuf>,
    remote_debugging_port: Option<u16>,
    headless: bool,
}

impl BrowserLaunchConfig {
    #[must_use]
    pub fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    #[must_use]
    pub fn user_data_dir(&self) -> Option<&Path> {
        self.user_data_dir.as_deref()
    }

    #[must_use]
    pub const fn remote_debugging_port(&self) -> Option<u16> {
        self.remote_debugging_port
    }

    #[must_use]
    pub const fn headless(&self) -> bool {
        self.headless
    }
}

impl From<BrowserLaunchLayerConfig> for BrowserLaunchConfig {
    fn from(config: BrowserLaunchLayerConfig) -> Self {
        Self {
            executable: config.executable,
            user_data_dir: config.user_data_dir,
            remote_debugging_port: config.remote_debugging_port,
            headless: config.headless,
        }
    }
}

#[cfg(test)]
mod tests;
