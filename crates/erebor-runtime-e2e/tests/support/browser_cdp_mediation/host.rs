use std::{
    env,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub struct BrowserCdpMediationHost {
    browser_bin: PathBuf,
}

impl BrowserCdpMediationHost {
    pub fn detect() -> Option<Self> {
        if !command_available("timeout") {
            return None;
        }

        ChromeBinary::discover().map(|browser_bin| Self { browser_bin })
    }

    pub fn browser_bin(&self) -> &Path {
        &self.browser_bin
    }
}

struct ChromeBinary;

impl ChromeBinary {
    fn discover() -> Option<PathBuf> {
        env::var_os("EREBOR_E2E_CHROME_BIN")
            .map(PathBuf::from)
            .filter(|path| is_executable_file(path))
            .or_else(|| {
                env::var_os("EREBOR_BROWSER_BIN")
                    .map(PathBuf::from)
                    .filter(|path| is_executable_file(path))
            })
            .or_else(|| find_binary_on_path("google-chrome"))
            .or_else(|| find_binary_on_path("google-chrome-stable"))
            .or_else(|| find_binary_on_path("chromium"))
            .or_else(|| find_binary_on_path("chromium-browser"))
    }
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn find_binary_on_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| is_executable_file(candidate))
    })
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}
