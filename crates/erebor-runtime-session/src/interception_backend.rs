use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use erebor_runtime_core::{
    AuditCommandLogLevel, DockerSessionCommandOptions, DockerSessionMount,
    LinuxHostSessionCommandOptions, ProcessInterceptionDecision, ProcessInterceptionHandlerConfig,
    ProcessInterceptionHandlerKind, ProcessMediationPrivateEndpointConfig,
    ProcessMediationReplacementSurface, SessionInterceptionBackendKind, SessionInterceptionConfig,
    SessionInterceptionOperation,
};

use crate::{
    SessionExecutionError, SessionInterceptionHandler, SessionMediationIntent, SessionPlanContext,
    SessionStorage,
};

const LINUX_PROCESS_GUARD_BINARY: &str = "erebor-linux-process-guard";
const DOCKER_GUARD_DIR: &str = "/erebor/guard";
const LINUX_PROCESS_GUARD_PATH: &str = "/erebor/guard/erebor-linux-process-guard";
const DOCKER_AUDIT_DIR: &str = "/erebor/audit";
static SESSION_BACKEND_BUNDLE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct SessionInterceptionBackendBundle {
    backend: SessionInterceptionBackend,
}

enum SessionInterceptionBackend {
    LinuxPtrace(LinuxPtraceInterceptionBackendBundle),
}

impl SessionInterceptionBackendBundle {
    pub(crate) fn prepare(
        interception: &SessionInterceptionConfig,
        process_exec: Option<ProcessExecInterceptionInput<'_>>,
        plan: &impl SessionPlanContext,
        storage: Option<&SessionStorage>,
    ) -> Result<Option<Self>, SessionExecutionError> {
        if !interception.operation_supported(SessionInterceptionOperation::ProcessExec) {
            return Ok(None);
        }

        let Some(process_exec) = process_exec else {
            return Ok(None);
        };

        match interception.backend() {
            SessionInterceptionBackendKind::LinuxPtrace => {
                LinuxPtraceInterceptionBackendBundle::prepare(process_exec, plan, storage)
                    .map(SessionInterceptionBackend::LinuxPtrace)
                    .map(|backend| Self { backend })
                    .map(Some)
            }
        }
    }

    pub(crate) fn backend_kind(&self) -> &'static str {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(_) => {
                SessionInterceptionBackendKind::LinuxPtrace.as_str()
            }
        }
    }

    pub(crate) fn docker_options(&self) -> DockerSessionCommandOptions {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => bundle.docker_options(),
        }
    }

    pub(crate) fn linux_host_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => {
                bundle.linux_host_options(browser_cdp_endpoint)
            }
        }
    }

    pub(crate) fn linux_host_adopt_options(
        &self,
        pid: i32,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => {
                bundle.linux_host_adopt_options(pid, browser_cdp_endpoint)
            }
        }
    }

    pub(crate) fn control_handlers(
        &self,
    ) -> Result<Vec<SessionInterceptionHandler>, SessionExecutionError> {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => bundle.control_handlers(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessExecMediationMode {
    Shim,
}

pub(crate) struct ProcessExecMediationInput<'a> {
    enabled: bool,
    mode: ProcessExecMediationMode,
    handlers: &'a [ProcessInterceptionHandlerConfig],
}

impl<'a> ProcessExecMediationInput<'a> {
    pub(crate) const fn new(
        enabled: bool,
        mode: ProcessExecMediationMode,
        handlers: &'a [ProcessInterceptionHandlerConfig],
    ) -> Self {
        Self {
            enabled,
            mode,
            handlers,
        }
    }

    const fn enabled(&self) -> bool {
        self.enabled
    }

    const fn ensure_supported_mode(&self) {
        match self.mode {
            ProcessExecMediationMode::Shim => {}
        }
    }

    fn handlers(&self) -> &[ProcessInterceptionHandlerConfig] {
        self.handlers
    }
}

pub(crate) struct ProcessExecInterceptionInput<'a> {
    mediation: ProcessExecMediationInput<'a>,
    audit_level: AuditCommandLogLevel,
    audit_debug_commands: Vec<String>,
    tty: bool,
}

impl<'a> ProcessExecInterceptionInput<'a> {
    pub(crate) fn new(
        mediation: ProcessExecMediationInput<'a>,
        audit_level: AuditCommandLogLevel,
        audit_debug_commands: Vec<String>,
        tty: bool,
    ) -> Self {
        Self {
            mediation,
            audit_level,
            audit_debug_commands,
            tty,
        }
    }

    const fn mediation(&self) -> &ProcessExecMediationInput<'a> {
        &self.mediation
    }

    const fn audit_level(&self) -> AuditCommandLogLevel {
        self.audit_level
    }

    fn audit_debug_commands(&self) -> &[String] {
        &self.audit_debug_commands
    }

    const fn tty(&self) -> bool {
        self.tty
    }
}

struct LinuxPtraceInterceptionBackendBundle {
    session_dir: PathBuf,
    guard_path: PathBuf,
    session_id: String,
    audit_path: Option<PathBuf>,
    audit_filename: Option<String>,
    audit_terminal_level: AuditCommandLogLevel,
    audit_terminal_debug_commands: Vec<String>,
    terminal_tty: bool,
    interception: Option<LinuxProcessInterceptionBundle>,
}

impl LinuxPtraceInterceptionBackendBundle {
    fn prepare(
        process_exec: ProcessExecInterceptionInput<'_>,
        plan: &impl SessionPlanContext,
        storage: Option<&SessionStorage>,
    ) -> Result<Self, SessionExecutionError> {
        let guard_path = linux_process_guard_executable()?;
        let instance_id = SESSION_BACKEND_BUNDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_dir = linux_ptrace_backend_session_dir(plan.session_id().as_str(), instance_id);

        let interception = LinuxProcessInterceptionBundle::prepare(
            &guard_path,
            &session_dir,
            process_exec.mediation(),
        )?;
        let mut audit_jsonl_path = None;
        let mut audit_filename = None;

        if let Some(audit_path) = storage.map(SessionStorage::audit_path) {
            let audit_parent = audit_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::create_dir_all(audit_parent).map_err(SessionExecutionError::guard_io)?;
            audit_filename = Some(
                audit_path
                    .file_name()
                    .ok_or_else(|| {
                        SessionExecutionError::guard_config(
                            "audit JSONL path must include a file name",
                        )
                    })?
                    .to_string_lossy()
                    .to_string(),
            );
            audit_jsonl_path = Some(audit_path.to_path_buf());
        }

        Ok(Self {
            session_dir,
            guard_path,
            session_id: plan.session_id().as_str().to_owned(),
            audit_path: audit_jsonl_path,
            audit_filename,
            audit_terminal_level: process_exec.audit_level(),
            audit_terminal_debug_commands: process_exec.audit_debug_commands().to_vec(),
            terminal_tty: process_exec.tty(),
            interception,
        })
    }

    fn docker_options(&self) -> DockerSessionCommandOptions {
        let guard_host_dir = self
            .guard_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut options = DockerSessionCommandOptions::new()
            .with_mount(DockerSessionMount::new(guard_host_dir, DOCKER_GUARD_DIR).read_only())
            .with_entrypoint(LINUX_PROCESS_GUARD_PATH)
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace")
            .with_environment("EREBOR_TERMINAL_TTY", self.terminal_tty.to_string());

        if let Some(audit_path) = self.audit_path.as_ref() {
            let audit_parent = audit_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let Some(audit_filename) = self.audit_filename.as_ref() else {
                return options;
            };
            let container_audit_path = format!("{DOCKER_AUDIT_DIR}/{audit_filename}");
            options = options
                .with_mount(DockerSessionMount::new(audit_parent, DOCKER_AUDIT_DIR))
                .with_environment("EREBOR_GUARD_AUDIT_JSONL", container_audit_path)
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_LEVEL",
                    audit_command_level_env(self.audit_terminal_level),
                )
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS",
                    self.audit_terminal_debug_commands.join("\n"),
                );
        }

        options
    }

    fn linux_host_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        let mut options = LinuxHostSessionCommandOptions::new()
            .with_wrapper_program(&self.guard_path)
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace")
            .with_environment("EREBOR_TERMINAL_TTY", self.terminal_tty.to_string())
            .with_environment(
                "EREBOR_GUARD_CGROUP_DIR",
                format!(
                    "/sys/fs/cgroup/erebor/{}",
                    linux_cgroup_component(&self.session_id)
                ),
            );

        if let Some(audit_path) = self.audit_path.as_ref() {
            options = options
                .with_environment("EREBOR_GUARD_AUDIT_JSONL", audit_path.display().to_string())
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_LEVEL",
                    audit_command_level_env(self.audit_terminal_level),
                )
                .with_environment(
                    "EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS",
                    self.audit_terminal_debug_commands.join("\n"),
                );
        }

        if let Some(interception) = self.interception.as_ref() {
            for (key, value) in interception.environment(browser_cdp_endpoint)? {
                options = options.with_environment(key, value);
            }
        }

        Ok(options)
    }

    fn linux_host_adopt_options(
        &self,
        pid: i32,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        Ok(self
            .linux_host_options(browser_cdp_endpoint)?
            .with_adopt_pid(pid))
    }

    fn control_handlers(&self) -> Result<Vec<SessionInterceptionHandler>, SessionExecutionError> {
        self.interception.as_ref().map_or_else(
            || Ok(Vec::new()),
            LinuxProcessInterceptionBundle::control_handlers,
        )
    }
}

impl Drop for LinuxPtraceInterceptionBackendBundle {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.session_dir);
    }
}

#[derive(Clone, Debug)]
struct LinuxProcessInterceptionBundle {
    shim_dir: PathBuf,
    handlers: Vec<LinuxProcessInterceptionHandler>,
}

impl LinuxProcessInterceptionBundle {
    fn prepare(
        guard_path: &Path,
        session_dir: &Path,
        process_exec: &ProcessExecMediationInput<'_>,
    ) -> Result<Option<Self>, SessionExecutionError> {
        if !process_exec.enabled() {
            return Ok(None);
        }
        process_exec.ensure_supported_mode();

        let shim_dir = session_dir.join("shims");
        fs::create_dir_all(&shim_dir).map_err(SessionExecutionError::guard_io)?;

        let handlers = process_exec
            .handlers()
            .iter()
            .map(|handler| LinuxProcessInterceptionHandler::prepare(handler, guard_path, &shim_dir))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(Self { shim_dir, handlers }))
    }

    fn environment(
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

    fn control_handlers(&self) -> Result<Vec<SessionInterceptionHandler>, SessionExecutionError> {
        self.handlers
            .iter()
            .map(LinuxProcessInterceptionHandler::to_control_handler)
            .collect()
    }
}

#[derive(Clone, Debug)]
struct LinuxProcessInterceptionHandler {
    id: String,
    decision: ProcessInterceptionDecision,
    kind: ProcessInterceptionHandlerKind,
    replacement_surface: ProcessMediationReplacementSurface,
    private_endpoint: ProcessMediationPrivateEndpointConfig,
    executables: Vec<String>,
    allowed_ports: Vec<u16>,
    executable_env: Vec<String>,
    print_devtools_listening_line: bool,
    keepalive: bool,
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
                SessionExecutionError::guard_config(format!(
                    "process interception handler `{}` executable `{}` is not a valid executable name",
                    handler.id(),
                    executable
                ))
            })?;
            let shim_path = shim_dir.join(&shim_name);
            std::os::unix::fs::symlink(guard_path, &shim_path)
                .map_err(SessionExecutionError::guard_io)?;
            executables.push(shim_name);
            shim_paths.push(shim_path);
        }

        Ok(Self {
            id: handler.id().to_owned(),
            decision: handler.decision(),
            kind: handler.kind(),
            replacement_surface: handler.replacement().surface(),
            private_endpoint: *handler.replacement().private_endpoint(),
            executables,
            allowed_ports: handler.requested_endpoint().allowed_ports().to_vec(),
            executable_env: process_interception_executable_env(handler),
            print_devtools_listening_line: handler.compatibility().print_devtools_listening_line(),
            keepalive: handler.compatibility().keepalive(),
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

    fn to_control_handler(&self) -> Result<SessionInterceptionHandler, SessionExecutionError> {
        let reason = match self.decision {
            ProcessInterceptionDecision::Allow => "process launch allowed by Erebor broker",
            ProcessInterceptionDecision::Deny => "process launch denied by Erebor broker",
            ProcessInterceptionDecision::RequireApproval => {
                "process launch requires approval from Erebor broker"
            }
            ProcessInterceptionDecision::Mediate => "process launch mediated by Erebor broker",
        };

        let handler = match self.decision {
            ProcessInterceptionDecision::Allow => {
                SessionInterceptionHandler::allow(&self.id, reason)
            }
            ProcessInterceptionDecision::Deny => SessionInterceptionHandler::deny(&self.id, reason),
            ProcessInterceptionDecision::RequireApproval => {
                SessionInterceptionHandler::require_approval(&self.id, reason)
            }
            ProcessInterceptionDecision::Mediate => SessionInterceptionHandler::mediate(
                &self.id,
                reason,
                SessionMediationIntent::new(
                    self.kind.as_str(),
                    replacement_surface_name(self.replacement_surface),
                )
                .with_lease_id(format!("{}-lease", self.id))
                .with_allowed_ports(self.allowed_ports.clone())
                .with_private_endpoint(self.private_endpoint)
                .with_compatibility_line(self.print_devtools_listening_line)
                .with_keepalive(self.keepalive),
            ),
        };

        Ok(handler)
    }
}

fn linux_cgroup_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn linux_process_guard_executable() -> Result<PathBuf, SessionExecutionError> {
    let current_exe = std::env::current_exe().map_err(SessionExecutionError::guard_io)?;
    let candidates = linux_process_guard_executable_candidates(&current_exe);
    candidates
        .iter()
        .find(|candidate| is_executable_file(candidate))
        .cloned()
        .ok_or_else(|| {
            let searched = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            SessionExecutionError::guard_config(format!(
                "could not find shipped `{LINUX_PROCESS_GUARD_BINARY}` executable; searched: {searched}"
            ))
        })
}

fn linux_process_guard_executable_candidates(current_exe: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(binary_dir) = current_exe.parent() {
        candidates.push(binary_dir.join(LINUX_PROCESS_GUARD_BINARY));

        if binary_dir
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new("deps"))
        {
            if let Some(target_dir) = binary_dir.parent() {
                candidates.push(target_dir.join(LINUX_PROCESS_GUARD_BINARY));
            }
        }
    }

    if let Some(build_process_guard) = option_env!("EREBOR_BUILD_LINUX_PROCESS_GUARD") {
        candidates.push(PathBuf::from(build_process_guard));
    }

    candidates
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn linux_ptrace_backend_session_dir(session_id: &str, instance_id: u64) -> PathBuf {
    std::env::temp_dir()
        .join("erebor-runtime")
        .join("sessions")
        .join(path_component(session_id, "unknown-session"))
        .join("interception")
        .join(SessionInterceptionBackendKind::LinuxPtrace.as_str())
        .join("process-guard")
        .join(std::process::id().to_string())
        .join(instance_id.to_string())
}

fn path_component(value: &str, fallback: &str) -> String {
    let component = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();

    if component.is_empty() || matches!(component.as_str(), "." | "..") {
        fallback.to_owned()
    } else {
        component
    }
}

fn audit_command_level_env(level: AuditCommandLogLevel) -> &'static str {
    match level {
        AuditCommandLogLevel::All => "all",
        AuditCommandLogLevel::Signal => "signal",
        AuditCommandLogLevel::NonAllow => "non_allow",
    }
}

pub(crate) fn process_interception_executable_env(
    handler: &ProcessInterceptionHandlerConfig,
) -> Vec<String> {
    if !handler.environment().executable_env().is_empty() {
        return handler.environment().executable_env().to_vec();
    }

    match handler.kind() {
        ProcessInterceptionHandlerKind::ManagedBrowserCdp => [
            "CHROME_PATH",
            "BROWSER",
            "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
            "PUPPETEER_EXECUTABLE_PATH",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

fn replacement_surface_name(surface: ProcessMediationReplacementSurface) -> &'static str {
    match surface {
        ProcessMediationReplacementSurface::BrowserCdp => "browser_cdp",
    }
}

fn executable_basename(value: &str) -> Option<String> {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
}

fn interception_env_field(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}
