use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_e2e::{error::IoSnafu, E2eError};
use snafu::{Location, ResultExt};

pub struct EreborCliFixture {
    binary: PathBuf,
}

impl EreborCliFixture {
    pub fn build() -> Result<Self, E2eError> {
        if let Some(binary) = std::env::var_os("CARGO_BIN_EXE_erebor-runtime") {
            return Ok(Self {
                binary: PathBuf::from(binary),
            });
        }

        let workspace_root = WorkspaceRoot::resolve()?;
        let output = Command::new("cargo")
            .args([
                "build",
                "-p",
                "erebor-runtime-cli",
                "--bin",
                "erebor-runtime",
            ])
            .current_dir(workspace_root.path())
            .output()
            .context(IoSnafu)?;
        if !output.status.success() {
            return Err(command_error("cargo build erebor-runtime", output));
        }

        Ok(Self {
            binary: workspace_root.binary_path("erebor-runtime"),
        })
    }

    pub fn run_in<'a>(
        &self,
        cwd: &Path,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, E2eError> {
        let output = self.command_in(cwd, args).output().context(IoSnafu)?;
        if !output.status.success() {
            return Err(command_error("erebor-runtime command", output));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn command_in<'a>(&self, cwd: &Path, args: impl IntoIterator<Item = &'a str>) -> Command {
        let mut command = Command::new(&self.binary);
        command.current_dir(cwd).args(args);
        command
    }

    pub fn run_expect_failure_in<'a>(
        &self,
        cwd: &Path,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, E2eError> {
        self.run_expect_failure_in_env(cwd, args, std::iter::empty::<(String, OsString)>())
    }

    pub fn run_expect_failure_in_env<'a>(
        &self,
        cwd: &Path,
        args: impl IntoIterator<Item = &'a str>,
        env: impl IntoIterator<Item = (String, OsString)>,
    ) -> Result<String, E2eError> {
        let output = Command::new(&self.binary)
            .current_dir(cwd)
            .args(args)
            .envs(env)
            .output()
            .context(IoSnafu)?;
        if output.status.success() {
            return Err(external_error(
                "erebor-runtime command expected failure",
                std::io::Error::other(format!(
                    "command unexpectedly succeeded: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )),
            ));
        }
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub struct E2eWorkspace {
    path: PathBuf,
}

impl E2eWorkspace {
    pub fn create(name: &str) -> Result<Self, E2eError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| external_error("system clock", error))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "erebor-runtime-e2e-{name}-{nanos}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).context(IoSnafu)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for E2eWorkspace {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.path);
    }
}

pub fn external_error(
    operation: impl Into<String>,
    source: impl std::error::Error + Send + Sync + 'static,
) -> E2eError {
    E2eError::External {
        operation: operation.into(),
        source: Box::new(source),
        location: Location::default(),
    }
}

struct WorkspaceRoot {
    path: PathBuf,
}

impl WorkspaceRoot {
    fn resolve() -> Result<Self, E2eError> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                external_error(
                    "resolve workspace root",
                    std::io::Error::other("e2e crate is not under workspace crates directory"),
                )
            })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn binary_path(&self, name: &str) -> PathBuf {
        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.path.join("target"));
        target_dir
            .join("debug")
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
    }
}

fn command_error(operation: &str, output: Output) -> E2eError {
    external_error(
        operation,
        std::io::Error::other(format!(
            "status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )),
    )
}
