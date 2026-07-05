use std::{fs, path::PathBuf};

use erebor_runtime_core::BrowserLaunchConfig;
use snafu::ResultExt;

use super::{executable::BrowserExecutable, profile::BrowserProfilePath};
use crate::{error::IoSnafu, CdpError};

const CHROME_STDERR_LOG: &str = "chrome-stderr.log";
const DEFAULT_BROWSER_FLAGS: &[&str] = &[
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-extensions",
    "--disable-sync",
    "--disable-breakpad",
    "--disable-crash-reporter",
    "--disable-dev-shm-usage",
    "--metrics-recording-only",
    "--remote-debugging-address=127.0.0.1",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnedBrowserLaunch {
    pub(super) executable: BrowserExecutable,
    pub(super) user_data_dir: PathBuf,
    pub(super) cleanup_user_data_dir: bool,
    pub(super) stderr_log_path: PathBuf,
    pub(super) options: OwnedBrowserLaunchOptions,
    pub(super) args: Vec<String>,
}

impl OwnedBrowserLaunch {
    pub(super) fn from_config(config: &BrowserLaunchConfig) -> Result<Self, CdpError> {
        let executable = BrowserExecutable::from_config(config)?;
        let (user_data_dir, cleanup_user_data_dir) = match config.user_data_dir() {
            Some(path) => (path.to_path_buf(), false),
            None => (BrowserProfilePath::temporary(), true),
        };
        fs::create_dir_all(&user_data_dir).context(IoSnafu)?;

        let stderr_log_path = user_data_dir.join(CHROME_STDERR_LOG);
        let options = OwnedBrowserLaunchOptions {
            headless: config.headless(),
            user_data_dir: user_data_dir.clone(),
            remote_debugging_port: config.remote_debugging_port(),
        };
        let args = options.browser_args();

        Ok(Self {
            executable,
            user_data_dir,
            cleanup_user_data_dir,
            stderr_log_path,
            options,
            args,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnedBrowserLaunchOptions {
    pub(super) headless: bool,
    user_data_dir: PathBuf,
    pub(super) remote_debugging_port: Option<u16>,
}

impl OwnedBrowserLaunchOptions {
    fn browser_args(&self) -> Vec<String> {
        let mut args = BrowserArgSet::default();
        if self.headless {
            args.push("--headless=new");
        }
        for flag in DEFAULT_BROWSER_FLAGS {
            args.push(*flag);
        }
        args.push(format!(
            "--remote-debugging-port={}",
            self.remote_debugging_port.unwrap_or(0)
        ));
        args.push(format!("--user-data-dir={}", self.user_data_dir.display()));
        args.push("about:blank");
        args.into_vec()
    }
}

#[derive(Default)]
struct BrowserArgSet {
    args: Vec<String>,
}

impl BrowserArgSet {
    fn push(&mut self, arg: impl Into<String>) {
        let arg = arg.into();
        if !self.args.iter().any(|existing| existing == &arg) {
            self.args.push(arg);
        }
    }

    fn into_vec(self) -> Vec<String> {
        self.args
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{OwnedBrowserLaunchOptions, DEFAULT_BROWSER_FLAGS};

    #[test]
    fn browser_launch_args_keep_owned_browser_debugging_flags() {
        let args = OwnedBrowserLaunchOptions {
            headless: true,
            user_data_dir: PathBuf::from("/tmp/erebor-owned-browser-test"),
            remote_debugging_port: None,
        }
        .browser_args();

        assert!(has_arg(&args, "--headless=new"));
        for flag in DEFAULT_BROWSER_FLAGS {
            assert!(has_arg(&args, flag));
        }
        assert!(has_arg(
            &args,
            "--user-data-dir=/tmp/erebor-owned-browser-test"
        ));
        assert_eq!(args.last().map(String::as_str), Some("about:blank"));
    }

    #[test]
    fn browser_launch_args_omit_headless_when_disabled() {
        let args = OwnedBrowserLaunchOptions {
            headless: false,
            user_data_dir: PathBuf::from("/tmp/erebor-owned-browser-test"),
            remote_debugging_port: None,
        }
        .browser_args();

        assert!(!has_arg(&args, "--headless=new"));
        assert!(has_arg(&args, "--remote-debugging-address=127.0.0.1"));
        assert!(has_arg(&args, "--remote-debugging-port=0"));
    }

    #[test]
    fn browser_launch_args_can_pin_private_debugging_port() {
        let args = OwnedBrowserLaunchOptions {
            headless: true,
            user_data_dir: PathBuf::from("/tmp/erebor-owned-browser-test"),
            remote_debugging_port: Some(1001),
        }
        .browser_args();

        assert!(has_arg(&args, "--remote-debugging-address=127.0.0.1"));
        assert!(has_arg(&args, "--remote-debugging-port=1001"));
        assert!(!has_arg(&args, "--remote-debugging-port=0"));
    }

    fn has_arg(args: &[String], expected: &str) -> bool {
        args.iter().any(|arg| arg == expected)
    }
}
