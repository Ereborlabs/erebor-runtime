use std::path::{Path, PathBuf};

use erebor_runtime_core::BrowserLaunchConfig;

use crate::{error::BrowserLaunchSnafu, CdpError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BrowserExecutable {
    pub(super) path: PathBuf,
    source: BrowserExecutableSource,
}

impl BrowserExecutable {
    pub(super) fn from_config(config: &BrowserLaunchConfig) -> Result<Self, CdpError> {
        if let Some(path) = config.executable() {
            return Self::from_config_path(path);
        }

        Self::from_env().or_else(Self::discover).ok_or_else(|| {
            BrowserLaunchSnafu {
                reason: String::from("no local Chrome or Chromium binary was found"),
            }
            .build()
        })
    }

    pub(super) fn label(&self) -> &'static str {
        match &self.source {
            BrowserExecutableSource::Config => "configured",
            BrowserExecutableSource::Env => "env",
            BrowserExecutableSource::Discovered(browser_type) => browser_type.as_str(),
        }
    }

    fn from_config_path(path: &Path) -> Result<Self, CdpError> {
        if !Self::is_executable(path) {
            return BrowserLaunchSnafu {
                reason: format!(
                    "configured browser executable `{}` was not found or is not executable",
                    path.display()
                ),
            }
            .fail();
        }

        Ok(Self {
            path: path.to_path_buf(),
            source: BrowserExecutableSource::Config,
        })
    }

    fn discover() -> Option<Self> {
        BrowserType::search_order().iter().find_map(|browser_type| {
            browser_type.find_executable().map(|path| Self {
                path,
                source: BrowserExecutableSource::Discovered(*browser_type),
            })
        })
    }

    fn from_env() -> Option<Self> {
        std::env::var_os("EREBOR_BROWSER_BIN")
            .map(PathBuf::from)
            .filter(|path| Self::is_executable(path))
            .map(|path| Self {
                path,
                source: BrowserExecutableSource::Env,
            })
    }

    fn resolve_candidate(candidate: &str) -> Option<PathBuf> {
        let path = Path::new(candidate);
        if path.is_absolute() {
            return Self::is_executable(path).then(|| path.to_path_buf());
        }

        Self::find_binary_on_path(candidate)
    }

    fn find_binary_on_path(name: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|entry| entry.join(name))
                .find(|candidate| Self::is_executable(candidate))
        })
    }

    fn is_executable(path: &Path) -> bool {
        if !path.is_file() {
            return false;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            path.metadata()
                .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }

        #[cfg(not(unix))]
        {
            true
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BrowserExecutableSource {
    Config,
    Env,
    Discovered(BrowserType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserType {
    Chrome,
    Chromium,
}

impl BrowserType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
        }
    }

    fn search_order() -> &'static [Self] {
        &[Self::Chrome, Self::Chromium]
    }

    fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Chrome => &[
                "google-chrome",
                "google-chrome-stable",
                "chrome",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ],
            Self::Chromium => &[
                "chromium",
                "chromium-browser",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ],
        }
    }

    fn find_executable(self) -> Option<PathBuf> {
        self.candidates()
            .iter()
            .find_map(|candidate| BrowserExecutable::resolve_candidate(candidate))
    }
}
