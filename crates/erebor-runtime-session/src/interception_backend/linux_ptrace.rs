use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{SessionExecutionError, SessionPlanContext, SessionStorage};
use erebor_runtime_core::{
    DockerSessionCommandOptions, DockerSessionMount, LinuxHostSessionCommandOptions,
    SessionInterceptionConfig, SessionInterceptionOperation,
};

use super::{
    guard_artifact::LinuxProcessGuardArtifact,
    inputs::{FileOperationInterceptionInput, ProcessExecInterceptionInput},
    path::{linux_cgroup_component, linux_ptrace_backend_session_dir},
    process_bundle::LinuxProcessInterceptionBundle,
};

const DOCKER_GUARD_DIR: &str = "/erebor/guard";
const LINUX_PROCESS_GUARD_PATH: &str = "/erebor/guard/erebor-linux-process-guard";
static SESSION_BACKEND_BUNDLE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct LinuxPtraceInterceptionBackendBundle {
    session_dir: PathBuf,
    guard_path: PathBuf,
    session_id: String,
    operations: LinuxPtraceInterceptionOperations,
    terminal_tty: bool,
    interception: Option<LinuxProcessInterceptionBundle>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LinuxPtraceInterceptionOperations {
    process_exec: bool,
    file_open: bool,
    file_read: bool,
    file_mutation: bool,
}

impl LinuxPtraceInterceptionOperations {
    pub(crate) fn from_inputs(
        interception: &SessionInterceptionConfig,
        process_exec: Option<&ProcessExecInterceptionInput<'_>>,
        file_operations: FileOperationInterceptionInput,
    ) -> Self {
        Self {
            process_exec: process_exec.is_some()
                && interception.operation_supported(SessionInterceptionOperation::ProcessExec),
            file_open: file_operations.open
                && interception.operation_supported(SessionInterceptionOperation::FileOpen),
            file_read: file_operations.read
                && interception.operation_supported(SessionInterceptionOperation::FileRead),
            file_mutation: file_operations.mutation
                && interception.operation_supported(SessionInterceptionOperation::FileMutation),
        }
    }

    pub(crate) const fn any(self) -> bool {
        self.process_exec || self.file_open || self.file_read || self.file_mutation
    }

    fn env_value(self) -> String {
        let mut operations = Vec::new();
        if self.process_exec {
            operations.push("process_exec");
        }
        if self.file_open {
            operations.push("file_open");
        }
        if self.file_read {
            operations.push("file_read");
        }
        if self.file_mutation {
            operations.push("file_mutation");
        }
        operations.join("\n")
    }
}

impl LinuxPtraceInterceptionBackendBundle {
    pub(crate) fn prepare(
        process_exec: Option<ProcessExecInterceptionInput<'_>>,
        operations: LinuxPtraceInterceptionOperations,
        plan: &impl SessionPlanContext,
        _storage: Option<&SessionStorage>,
    ) -> Result<Self, SessionExecutionError> {
        let guard_path = LinuxProcessGuardArtifact::resolve()?;
        let instance_id = SESSION_BACKEND_BUNDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_dir = linux_ptrace_backend_session_dir(plan.session_id().as_str(), instance_id);

        let interception = LinuxProcessInterceptionBundle::prepare(
            &guard_path,
            &session_dir,
            process_exec
                .as_ref()
                .map(ProcessExecInterceptionInput::mediation),
        )?;
        Ok(Self {
            session_dir,
            guard_path,
            session_id: plan.session_id().as_str().to_owned(),
            operations,
            terminal_tty: process_exec
                .as_ref()
                .is_some_and(ProcessExecInterceptionInput::tty),
            interception,
        })
    }

    pub(crate) fn docker_options(&self) -> DockerSessionCommandOptions {
        let guard_host_dir = self
            .guard_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut options = DockerSessionCommandOptions::default();
        options.add_mount(DockerSessionMount::new(
            guard_host_dir,
            DOCKER_GUARD_DIR,
            true,
        ));
        options.set_entrypoint(LINUX_PROCESS_GUARD_PATH);
        options.add_environment("EREBOR_PROCESS_GUARD", "linux-ptrace");
        options.add_environment(
            "EREBOR_GUARD_INTERCEPTION_OPERATIONS",
            self.operations.env_value(),
        );
        options.add_environment("EREBOR_TERMINAL_TTY", self.terminal_tty.to_string());

        options
    }

    pub(crate) fn linux_host_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        let mut options = LinuxHostSessionCommandOptions::default();
        options.add_wrapper_program(&self.guard_path);
        options.add_environment("EREBOR_PROCESS_GUARD", "linux-ptrace");
        options.add_environment(
            "EREBOR_GUARD_INTERCEPTION_OPERATIONS",
            self.operations.env_value(),
        );
        options.add_environment("EREBOR_TERMINAL_TTY", self.terminal_tty.to_string());
        options.add_environment(
            "EREBOR_GUARD_CGROUP_DIR",
            format!(
                "/sys/fs/cgroup/erebor/{}",
                linux_cgroup_component(&self.session_id)
            ),
        );

        if let Some(interception) = self.interception.as_ref() {
            for (key, value) in interception.environment(browser_cdp_endpoint)? {
                options.add_environment(key, value);
            }
        }

        Ok(options)
    }

    pub(crate) fn linux_host_adopt_options(
        &self,
        pid: i32,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        let mut options = self.linux_host_options(browser_cdp_endpoint)?;
        options.set_adopt_pid(pid);
        Ok(options)
    }
}

impl Drop for LinuxPtraceInterceptionBackendBundle {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.session_dir);
    }
}
