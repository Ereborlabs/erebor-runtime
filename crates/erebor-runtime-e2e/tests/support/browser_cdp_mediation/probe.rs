use std::{
    env,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use erebor_runtime_e2e::{error::IoSnafu, E2eError};
use snafu::ResultExt;

use crate::cli::external_error;

pub struct OriginalBrowserCommandProbe {
    bin_dir: PathBuf,
    marker_path: PathBuf,
}

impl OriginalBrowserCommandProbe {
    pub fn install(workspace: &Path) -> Result<Self, E2eError> {
        let bin_dir = workspace.join("original-browser-bin");
        let marker_path = workspace.join("original-google-chrome-executed");
        fs::create_dir_all(&bin_dir).context(IoSnafu)?;
        let script_path = bin_dir.join("google-chrome");
        fs::write(&script_path, marker_script(&marker_path)).context(IoSnafu)?;
        let mut permissions = fs::metadata(&script_path).context(IoSnafu)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).context(IoSnafu)?;

        Ok(Self {
            bin_dir,
            marker_path,
        })
    }

    pub fn path_value(&self) -> Result<OsString, E2eError> {
        let mut paths = vec![self.bin_dir.as_path().to_path_buf()];
        if let Some(existing) = env::var_os("PATH") {
            paths.extend(env::split_paths(&existing));
        }
        env::join_paths(paths).map_err(|error| external_error("join fake browser PATH", error))
    }

    pub fn assert_not_executed(&self) -> Result<(), E2eError> {
        if !self.marker_path.exists() {
            return Ok(());
        }

        let contents = fs::read_to_string(&self.marker_path).unwrap_or_default();
        Err(external_error(
            "assert original browser command was mediated",
            std::io::Error::other(format!(
                "original google-chrome command executed unexpectedly: {contents}"
            )),
        ))
    }
}

fn marker_script(marker_path: &Path) -> String {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 23\n",
        shell_quote(marker_path)
    )
}

fn shell_quote(path: &Path) -> String {
    let mut quoted = String::from("'");
    for character in path.display().to_string().chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}
