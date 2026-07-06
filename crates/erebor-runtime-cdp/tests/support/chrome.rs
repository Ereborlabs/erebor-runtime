use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_e2e::{error::IoSnafu, E2eError};
use snafu::ResultExt;

use super::chrome_http::ChromeDevToolsHttpClient;
use super::error_helpers::{external_error, timeout_error};

pub fn real_chrome_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();

    *AVAILABLE.get_or_init(|| RealChromeInstance::launch().is_ok())
}

pub struct RealChromeInstance {
    child: Child,
    user_data_dir: PathBuf,
    page_ws_url: String,
}

impl RealChromeInstance {
    pub fn launch() -> Result<Self, E2eError> {
        let Some(binary) = chrome_binary_path() else {
            return Err(external_error(
                "real Chrome binary discovery",
                MissingChromeBinary,
            ));
        };
        let user_data_dir = temp_profile_dir();
        fs::create_dir_all(&user_data_dir).context(IoSnafu)?;
        let mut command = Command::new(binary);
        command
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-background-networking")
            .arg("--disable-extensions")
            .arg("--disable-sync")
            .arg("--metrics-recording-only")
            .arg("--remote-debugging-address=127.0.0.1")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().context(IoSnafu)?;
        let port = wait_for_devtools_port(&mut child, &user_data_dir.join("DevToolsActivePort"))?;
        let page_ws_url = wait_for_page_ws_url(&mut child, port)?;

        Ok(Self {
            child,
            user_data_dir,
            page_ws_url,
        })
    }

    pub fn page_ws_url(&self) -> &str {
        &self.page_ws_url
    }
}

impl Drop for RealChromeInstance {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _kill_result = self.child.kill();
            let _wait_result = self.child.wait();
        }

        let _cleanup_result = fs::remove_dir_all(&self.user_data_dir);
    }
}

fn chrome_binary_path() -> Option<PathBuf> {
    std::env::var_os("EREBOR_E2E_CHROME_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            std::env::var_os("EREBOR_BROWSER_BIN")
                .map(PathBuf::from)
                .filter(|path| path.is_file())
        })
        .or_else(|| find_binary_on_path("google-chrome"))
        .or_else(|| find_binary_on_path("google-chrome-stable"))
        .or_else(|| find_binary_on_path("chromium"))
        .or_else(|| find_binary_on_path("chromium-browser"))
        .or_else(|| {
            chrome_app_binary("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        })
        .or_else(|| chrome_app_binary("/Applications/Chromium.app/Contents/MacOS/Chromium"))
}

fn find_binary_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|entry| entry.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn chrome_app_binary(path: &str) -> Option<PathBuf> {
    let path = PathBuf::from(path);
    path.is_file().then_some(path)
}

fn temp_profile_dir() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());

    std::env::temp_dir().join(format!(
        "erebor-runtime-cdp-e2e-{}-{timestamp}",
        std::process::id()
    ))
}

fn wait_for_devtools_port(child: &mut Child, active_port_file: &Path) -> Result<u16, E2eError> {
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        if let Ok(contents) = fs::read_to_string(active_port_file) {
            let Some(port_line) = contents.lines().next() else {
                return Err(external_error(
                    "real Chrome DevTools port file",
                    MissingDevToolsPort,
                ));
            };

            return port_line
                .parse::<u16>()
                .map_err(|error| external_error("real Chrome DevTools port parse", error));
        }

        if child.try_wait().context(IoSnafu)?.is_some() {
            return Err(external_error("real Chrome startup", ChromeExitedEarly));
        }

        if Instant::now() >= deadline {
            return Err(timeout_error("real Chrome DevTools startup"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_page_ws_url(child: &mut Child, port: u16) -> Result<String, E2eError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let client = ChromeDevToolsHttpClient::new(port);
    let mut errors = Vec::new();

    loop {
        match client.page_ws_url() {
            Ok(page_ws_url) => return Ok(page_ws_url),
            Err(
                error @ (E2eError::Io { .. } | E2eError::Json { .. } | E2eError::External { .. }),
            ) => {
                errors.push(error.to_string());
            }
            Err(error) => return Err(error),
        }

        if child.try_wait().context(IoSnafu)?.is_some() {
            return Err(external_error("real Chrome startup", ChromeExitedEarly));
        }

        if Instant::now() >= deadline {
            let operation = errors.last().map_or_else(
                || String::from("real Chrome page websocket"),
                |error| format!("real Chrome page websocket; last error: {error}"),
            );

            return Err(timeout_error(operation));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

macro_rules! simple_error {
    ($name:ident, $message:literal) => {
        #[derive(Debug)]
        struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str($message)
            }
        }

        impl std::error::Error for $name {}
    };
}

simple_error!(
    MissingChromeBinary,
    "no local Chrome or Chromium binary was found for CDP e2e"
);
simple_error!(
    ChromeExitedEarly,
    "real Chrome exited before CDP became ready"
);
simple_error!(
    MissingDevToolsPort,
    "real Chrome DevToolsActivePort file did not include a port"
);
