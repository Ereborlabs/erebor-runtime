use std::{fs, path::Path};

use crate::{error::BrowserLaunchSnafu, CdpError};

const CHROME_STDERR_EXCERPT_LIMIT: usize = 4_000;

pub(super) struct BrowserLaunchDiagnostics;

impl BrowserLaunchDiagnostics {
    pub(super) fn enrich(error: CdpError, stderr_log_path: &Path) -> CdpError {
        let CdpError::BrowserLaunch { reason, .. } = error else {
            return error;
        };

        let Some(stderr) = Self::stderr_excerpt(stderr_log_path) else {
            return BrowserLaunchSnafu { reason }.build();
        };

        BrowserLaunchSnafu {
            reason: format!("{reason}; Chrome stderr: {stderr}"),
        }
        .build()
    }

    pub(super) fn page_target_error(ws_error: CdpError, http_error: CdpError) -> CdpError {
        BrowserLaunchSnafu {
            reason: format!(
                "could not create Chrome page target through browser websocket \
                 ({ws_error}) or HTTP discovery ({http_error})"
            ),
        }
        .build()
    }

    pub(super) fn stderr_devtools_url(
        stderr_log_path: &Path,
        expected_port: u16,
    ) -> Option<String> {
        let source = fs::read_to_string(stderr_log_path).ok()?;
        source.lines().find_map(|line| {
            let url = line.trim().strip_prefix("DevTools listening on ")?;
            if Self::endpoint_port(url) == Some(expected_port) {
                Some(url.to_owned())
            } else {
                None
            }
        })
    }

    fn stderr_excerpt(stderr_log_path: &Path) -> Option<String> {
        let source = fs::read_to_string(stderr_log_path).ok()?;
        let source = source.trim();
        if source.is_empty() {
            return None;
        }

        if source.chars().count() <= CHROME_STDERR_EXCERPT_LIMIT {
            return Some(source.to_owned());
        }

        let mut tail = source
            .chars()
            .rev()
            .take(CHROME_STDERR_EXCERPT_LIMIT)
            .collect::<Vec<_>>();
        tail.reverse();
        Some(format!("...{}", tail.into_iter().collect::<String>()))
    }

    fn endpoint_port(endpoint: &str) -> Option<u16> {
        let endpoint = endpoint
            .strip_prefix("ws://")
            .or_else(|| endpoint.strip_prefix("http://"))?;
        let host = endpoint.split('/').next().unwrap_or(endpoint);
        host.rsplit_once(':')?.1.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::BrowserLaunchDiagnostics;

    #[test]
    fn chrome_stderr_devtools_url_matches_expected_port() -> Result<(), Box<dyn std::error::Error>>
    {
        let path =
            std::env::temp_dir().join(format!("erebor-chrome-stderr-{}.log", std::process::id()));
        fs::write(
            &path,
            "DevTools listening on ws://127.0.0.1:1001/devtools/browser/test\n",
        )?;

        assert_eq!(
            BrowserLaunchDiagnostics::stderr_devtools_url(&path, 1001),
            Some(String::from("ws://127.0.0.1:1001/devtools/browser/test"))
        );
        assert_eq!(
            BrowserLaunchDiagnostics::stderr_devtools_url(&path, 1002),
            None
        );

        fs::remove_file(path)?;
        Ok(())
    }
}
