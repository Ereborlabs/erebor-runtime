use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_core::ProcessInterceptionHandlerConfig;
use snafu::ResultExt;

use crate::{
    error::{GuardConfigSnafu, GuardIoSnafu},
    SessionExecutionError,
};

use super::{
    env::{interception_env_field, process_interception_executable_env},
    inputs::ProcessExecMediationInput,
};

#[derive(Clone, Debug)]
pub(crate) struct LinuxProcessInterceptionBundle {
    shim_dir: PathBuf,
    handlers: Vec<LinuxProcessInterceptionHandler>,
}

impl LinuxProcessInterceptionBundle {
    pub(crate) fn prepare(
        guard_path: &Path,
        session_dir: &Path,
        process_exec: Option<&ProcessExecMediationInput<'_>>,
    ) -> Result<Option<Self>, SessionExecutionError> {
        let Some(process_exec) = process_exec else {
            return Ok(None);
        };
        if !process_exec.enabled() {
            return Ok(None);
        }
        process_exec.ensure_supported_mode();

        let shim_dir = session_dir.join("shims");
        fs::create_dir_all(&shim_dir).context(GuardIoSnafu)?;

        let handlers = process_exec
            .handlers()
            .iter()
            .map(|handler| LinuxProcessInterceptionHandler::prepare(handler, guard_path, &shim_dir))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(Self { shim_dir, handlers }))
    }

    pub(crate) fn environment(
        &self,
        _browser_cdp_endpoint: Option<&str>,
    ) -> Result<Vec<(String, String)>, SessionExecutionError> {
        let mut environment = vec![
            (
                String::from("EREBOR_PROCESS_INTERCEPTION"),
                String::from("linux-ptrace"),
            ),
            (
                String::from("EREBOR_PROCESS_INTERCEPTION_HANDLERS"),
                self.handlers_env(),
            ),
            (
                String::from("EREBOR_PROCESS_INTERCEPTION_SHIM_DIR"),
                self.shim_dir.display().to_string(),
            ),
        ];

        if self.handlers.iter().any(|handler| handler.prepend_path) {
            let path = std::env::var("PATH").unwrap_or_default();
            let shim_path = self.shim_dir.display().to_string();
            let value = if path.is_empty() {
                shim_path
            } else {
                format!("{shim_path}:{path}")
            };
            environment.push((String::from("PATH"), value));
        }

        for handler in &self.handlers {
            let Some(primary_shim) = handler.primary_shim_path() else {
                continue;
            };
            for variable in handler.executable_env_vars() {
                environment.push((variable, primary_shim.display().to_string()));
            }
        }

        Ok(environment)
    }

    fn handlers_env(&self) -> String {
        self.handlers
            .iter()
            .map(LinuxProcessInterceptionHandler::to_env_line)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Clone, Debug)]
struct LinuxProcessInterceptionHandler {
    id: String,
    executables: Vec<String>,
    executable_env: Vec<String>,
    prepend_path: bool,
    shim_paths: Vec<PathBuf>,
}

impl LinuxProcessInterceptionHandler {
    fn prepare(
        handler: &ProcessInterceptionHandlerConfig,
        guard_path: &Path,
        shim_dir: &Path,
    ) -> Result<Self, SessionExecutionError> {
        let mut shim_paths = Vec::new();
        let mut executables = Vec::new();

        for executable in handler.matcher().executables() {
            let shim_name = executable_basename(executable).ok_or_else(|| {
                GuardConfigSnafu {
                    reason: format!(
                        "process interception handler `{}` executable `{}` is not a valid executable name",
                        handler.id(),
                        executable
                    ),
                }
                .build()
            })?;
            let shim_path = shim_dir.join(&shim_name);
            std::os::unix::fs::symlink(guard_path, &shim_path).context(GuardIoSnafu)?;
            executables.push(shim_name);
            shim_paths.push(shim_path);
        }

        Ok(Self {
            id: handler.id().to_owned(),
            executables,
            executable_env: process_interception_executable_env(handler),
            prepend_path: handler.environment().prepend_path(),
            shim_paths,
        })
    }

    fn primary_shim_path(&self) -> Option<&Path> {
        self.shim_paths.first().map(PathBuf::as_path)
    }

    fn executable_env_vars(&self) -> Vec<String> {
        self.executable_env.clone()
    }

    fn to_env_line(&self) -> String {
        [
            interception_env_field(&self.id),
            interception_env_field(self.executables.join(",")),
        ]
        .join("\t")
    }
}

fn executable_basename(value: &str) -> Option<String> {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
}
