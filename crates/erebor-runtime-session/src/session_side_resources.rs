use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use erebor_runtime_cdp::BrowserCdpSurface;
use erebor_runtime_core::{
    CodexHookShellKind, RuntimeConfig, SessionAdoptPlan, SessionInterceptionOperation,
    SessionRunPlan, SessionRunnerKind, SessionSurfaceDefinition, SessionSurfaceKind,
    SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
};
use erebor_runtime_filesystem::{LinuxOverlaySessionView, LinuxReadOnlySessionView};
use snafu::ResultExt;

use crate::{
    agents::codex::{
        CodexArtifactProjection, CodexCommandDispatch, CodexContextDag, CodexGuardLifecycleHandler,
        CodexHookBroker, CodexInvocationLeaseOwner, CodexInvocationLeaseProfile,
        CodexInvocationLeaseTrust, CodexManagedSession, CodexPromptReconciliation,
    },
    error::{
        CodexSessionSnafu, FilesystemSurfaceSnafu, GuardConfigSnafu, InvalidConfigSnafu,
        RuntimeSnafu,
    },
    interception_backend::{FileOperationInterceptionInput, SessionInterceptionBackendBundle},
    interception_setup::SessionInterceptionSetup,
    policies::read_policy_set,
    registry_lifecycle::PreparedSession,
    session_context::{CdpSessionContexts, SessionPlanContext},
    session_resources::SessionSideResources,
    surfaces::{
        filesystem::{FilesystemFileOperationHandler, FilesystemSessionContext},
        terminal::{LazyBrowserCdpProcessMediation, TerminalProcessSurface},
    },
    SessionExecutionError,
};

pub(crate) fn start_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionSideResources, SessionExecutionError> {
    let codex_managed_session =
        CodexManagedSession::for_run(config, plan).context(CodexSessionSnafu)?;
    let start_plan = config
        .surface_start_plan_for_session(plan)
        .context(InvalidConfigSnafu)?;
    start_session_side_resources_from_start_plan(
        config,
        plan,
        start_plan,
        prepared_session,
        codex_managed_session,
    )
}

pub(crate) fn start_adopt_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionAdoptPlan,
) -> Result<SessionSideResources, SessionExecutionError> {
    let process_exec_interception = config
        .session_interception_capabilities()
        .operations()
        .iter()
        .any(|operation| {
            operation.operation() == SessionInterceptionOperation::ProcessExec
                && operation.effective()
        });
    if plan.runner().kind() == SessionRunnerKind::LinuxHost && !process_exec_interception {
        return GuardConfigSnafu {
            reason: String::from(
                "linux-host adoption requires session.interception process_exec support",
            ),
        }
        .fail();
    }

    let start_plan = config
        .surface_start_plan_for_runner_kind(plan.runner().kind())
        .context(InvalidConfigSnafu)?;
    start_session_side_resources_from_start_plan(config, plan, start_plan, None, None)
}

fn start_session_side_resources_from_start_plan(
    _config: &RuntimeConfig,
    plan: &impl SessionPlanContext,
    start_plan: erebor_runtime_core::SessionSurfaceStartPlan,
    prepared_session: Option<&PreparedSession>,
    codex_managed_session: Option<CodexManagedSession>,
) -> Result<SessionSideResources, SessionExecutionError> {
    if start_plan.surfaces().is_empty() {
        return Ok(SessionSideResources::default());
    }

    let launch_plan = SessionSurfaceLaunchPlan::from_start_plan(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &start_plan,
    )
    .context(RuntimeSnafu)?;
    let mut launcher = SessionSurfaceLauncher::new(launch_plan.control_listen());
    let mut environment = Vec::new();
    let mut terminal_surface_present = false;
    let mut terminal_process_surface = TerminalProcessSurface::absent();
    let mut filesystem_handler = None;
    let mut filesystem_overlay_wrapper = None;
    let mut codex_projection_wrapper = None;
    let mut codex_guard_lifecycle_handler = None;
    let mut codex_hook_broker = None;
    let mut codex_invocation_lease_owner = None;
    let mut codex_prompt_reconciliation = None;
    let mut process_exec_interception = None;
    let process_exec_supported = start_plan
        .interception()
        .operation_supported(SessionInterceptionOperation::ProcessExec);
    let mut lazy_browser_cdp = None;
    let uses_lazy_browser_cdp = start_plan
        .terminal()
        .is_some_and(TerminalProcessSurface::uses_managed_browser_cdp_mediation);

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                let policy_set = read_policy_set(config.policies())?;
                if uses_lazy_browser_cdp {
                    lazy_browser_cdp = Some(LazyBrowserCdpProcessMediation::new(
                        config.clone(),
                        policy_set,
                        CdpSessionContexts::from_plan(plan),
                        prepared_session
                            .map(|session| session.storage().audit_path().to_path_buf()),
                        plan.audit().clone(),
                    ));
                } else {
                    let mut surface = BrowserCdpSurface::new(
                        config.clone(),
                        policy_set,
                        CdpSessionContexts::from_plan(plan),
                    )
                    .with_audit_config(plan.audit().clone());
                    if let Some(audit_jsonl) =
                        prepared_session.map(|session| session.storage().audit_path())
                    {
                        surface = surface.with_audit_jsonl(audit_jsonl.to_path_buf());
                    }
                    launcher.add_surface(surface);
                }
            }
            SessionSurfaceDefinition::Terminal(config) => {
                terminal_surface_present = true;
                environment.push((
                    String::from("EREBOR_TERMINAL_SURFACE"),
                    String::from("terminal"),
                ));
                environment.push((
                    String::from("EREBOR_TERMINAL_TTY"),
                    config.tty().to_string(),
                ));

                if process_exec_supported {
                    terminal_process_surface = TerminalProcessSurface::present(config);
                    process_exec_interception = terminal_process_surface.backend_input(plan)?;
                }
            }
            SessionSurfaceDefinition::Filesystem(config) => {
                let policy_set = read_policy_set(config.policies())?;
                let mut handler = FilesystemFileOperationHandler::new(
                    policy_set,
                    FilesystemSessionContext::from_plan(plan),
                );
                if let Some(audit_jsonl) =
                    prepared_session.map(|session| session.storage().audit_path())
                {
                    handler =
                        handler.with_audit_jsonl(audit_jsonl.to_path_buf(), plan.audit().clone());
                }
                filesystem_handler = Some(handler);
                environment.push((
                    String::from("EREBOR_FILESYSTEM_SURFACE"),
                    String::from("filesystem"),
                ));
                if let Some(storage) = prepared_session
                    .map(PreparedSession::storage)
                    .and_then(|storage| storage.filesystem())
                {
                    environment.push((
                        String::from("EREBOR_FILESYSTEM_SESSION_DIR"),
                        storage.root().display().to_string(),
                    ));
                    environment.push((
                        String::from("EREBOR_FILESYSTEM_REPO"),
                        storage.repo_path().display().to_string(),
                    ));
                    if plan.runner_kind() == SessionRunnerKind::LinuxHost {
                        let overlay_view = LinuxOverlaySessionView::prepare(storage)
                            .context(FilesystemSurfaceSnafu)?;
                        let wrapper_path = overlay_view.wrapper_path().to_path_buf();
                        environment.push((
                            String::from("EREBOR_FILESYSTEM_OVERLAY_WRAPPER"),
                            wrapper_path.display().to_string(),
                        ));
                        filesystem_overlay_wrapper = Some(wrapper_path);
                        if let Some(codex_managed_session) = codex_managed_session.as_ref() {
                            let reconciliation = Arc::new(CodexPromptReconciliation::default());
                            let context_dag = prepared_session.map(|session| {
                                Arc::new(CodexContextDag::new(
                                    session.context_repository_handle(),
                                    plan.session_id().as_str(),
                                ))
                            });
                            let runtime_state_roots =
                                codex_runtime_state_roots(storage.repo_path())?;
                            let command_dispatch = codex_managed_session
                                .profile()
                                .app_server_transport
                                .command_dispatch
                                .as_ref()
                                .map(|dispatch| {
                                    CodexCommandDispatch::new(
                                        dispatch.program.clone(),
                                        dispatch.shell.display().to_string(),
                                    )
                                });
                            let lease_trust = CodexInvocationLeaseTrust::new(
                                runtime_state_roots,
                                command_dispatch,
                            );
                            let lease_owner = Arc::new(CodexInvocationLeaseOwner::new(
                                plan.session_id().as_str(),
                                erebor_runtime_events::ActorIdentity {
                                    id: plan.actor().id.clone(),
                                    kind: plan.actor().kind.clone(),
                                },
                                CodexInvocationLeaseProfile::new(
                                    codex_managed_session.profile().id.clone(),
                                    codex_managed_session
                                        .profile()
                                        .executable
                                        .display()
                                        .to_string(),
                                    codex_managed_session
                                        .profile()
                                        .hook_exec_history
                                        .iter()
                                        .map(|path| path.display().to_string())
                                        .collect(),
                                ),
                                lease_trust,
                                prepared_session
                                    .map(PreparedSession::storage)
                                    .map(|storage| storage.audit_path().to_path_buf()),
                            ));
                            if let Some(context_dag) = context_dag {
                                lease_owner
                                    .set_context_dag(context_dag)
                                    .context(CodexSessionSnafu)?;
                            }
                            let broker = CodexHookBroker::start(
                                codex_managed_session.clone(),
                                Arc::clone(&reconciliation),
                                Arc::clone(&lease_owner),
                            )
                            .context(CodexSessionSnafu)?;
                            let mut projections = CodexArtifactProjection::projections(
                                codex_managed_session.profile(),
                            )
                            .context(CodexSessionSnafu)?;
                            projections
                                .push(broker.session_projection().context(CodexSessionSnafu)?);
                            let projection =
                                LinuxReadOnlySessionView::prepare(storage, &projections)
                                    .map_err(|source| {
                                        crate::CodexSessionError::FilesystemProjection {
                                            source: Box::new(source),
                                            location: snafu::Location::default(),
                                        }
                                    })
                                    .context(CodexSessionSnafu)?;
                            let wrapper_path = projection.wrapper_path().to_path_buf();
                            environment.push((
                                String::from("EREBOR_CODEX_PROFILE_ID"),
                                codex_managed_session.profile().id.clone(),
                            ));
                            add_codex_hook_shell_environment(
                                &mut environment,
                                codex_managed_session.profile(),
                            )?;
                            environment.push((
                                String::from("EREBOR_CODEX_HOOK_BROKER"),
                                CodexHookBroker::session_endpoint().to_owned(),
                            ));
                            let lifecycle_handler = CodexGuardLifecycleHandler::new(
                                codex_managed_session.clone(),
                                Arc::clone(&lease_owner),
                            );
                            codex_projection_wrapper = Some(wrapper_path);
                            codex_guard_lifecycle_handler = Some(lifecycle_handler);
                            codex_hook_broker = Some(broker);
                            codex_invocation_lease_owner = Some(lease_owner);
                            codex_prompt_reconciliation = Some(reconciliation);
                        }
                    }
                }
            }
        }
    }

    let interception_setup =
        SessionInterceptionSetup::new(SessionInterceptionBackendBundle::prepare(
            start_plan.interception(),
            process_exec_interception,
            file_operation_interception_input(start_plan.interception(), &filesystem_handler),
            plan,
            prepared_session.map(PreparedSession::storage),
        )?);
    if codex_guard_lifecycle_handler.is_some() && interception_setup.backend_kind().is_none() {
        return GuardConfigSnafu {
            reason: String::from(
                "managed Codex hook tickets require the Linux process guard to be enabled",
            ),
        }
        .fail();
    }
    if terminal_surface_present {
        environment.push((
            String::from("EREBOR_TERMINAL_PROCESS_GUARD"),
            interception_setup
                .backend_kind()
                .unwrap_or("disabled")
                .to_owned(),
        ));
    }

    if launcher.is_empty() {
        let uses_lazy_browser_cdp = lazy_browser_cdp.is_some();
        let interception_router = session_interception_router(
            terminal_process_surface,
            None,
            lazy_browser_cdp,
            filesystem_handler,
            codex_invocation_lease_owner.clone(),
            codex_guard_lifecycle_handler,
        )?;
        let interception_registration =
            interception_setup.register(interception_router, plan, uses_lazy_browser_cdp)?;
        let mut resources = interception_setup.into_side_resources(
            environment,
            None,
            interception_registration,
            None,
            codex_hook_broker,
        )?;
        if let Some(wrapper) = filesystem_overlay_wrapper {
            resources.add_linux_host_outer_wrapper(wrapper);
        }
        resources.set_codex_prompt_reconciliation(codex_prompt_reconciliation);
        resources.set_codex_invocation_lease_owner(codex_invocation_lease_owner);
        apply_codex_launch_sanitization(&mut resources, codex_projection_wrapper);
        return Ok(resources);
    }

    let supervisor = launcher.start().context(RuntimeSnafu)?;
    let mut browser_cdp_endpoint = None;
    for runtime in supervisor.running() {
        match runtime.surface() {
            SessionSurfaceKind::BrowserCdp => {
                browser_cdp_endpoint = Some(runtime.endpoint().to_owned());
                environment.push((
                    String::from("EREBOR_BROWSER_CDP_URL"),
                    runtime.endpoint().to_owned(),
                ));
                environment.push((
                    String::from("EREBOR_OPENCLAW_BROWSER_PROFILE"),
                    String::from("erebor"),
                ));
            }
            SessionSurfaceKind::Terminal => {}
            SessionSurfaceKind::Filesystem => {}
            SessionSurfaceKind::Mcp
            | SessionSurfaceKind::Network
            | SessionSurfaceKind::Saas
            | SessionSurfaceKind::Desktop
            | SessionSurfaceKind::InternalSystem => {}
        }
    }

    let interception_router = session_interception_router(
        terminal_process_surface,
        browser_cdp_endpoint.as_deref(),
        lazy_browser_cdp,
        filesystem_handler,
        codex_invocation_lease_owner.clone(),
        codex_guard_lifecycle_handler,
    )?;
    let interception_registration =
        interception_setup.register(interception_router, plan, uses_lazy_browser_cdp)?;

    let mut resources = interception_setup.into_side_resources(
        environment,
        browser_cdp_endpoint,
        interception_registration,
        Some(supervisor),
        codex_hook_broker,
    )?;
    if let Some(wrapper) = filesystem_overlay_wrapper {
        resources.add_linux_host_outer_wrapper(wrapper);
    }
    resources.set_codex_prompt_reconciliation(codex_prompt_reconciliation);
    resources.set_codex_invocation_lease_owner(codex_invocation_lease_owner);
    apply_codex_launch_sanitization(&mut resources, codex_projection_wrapper);
    Ok(resources)
}

fn apply_codex_launch_sanitization(
    resources: &mut SessionSideResources,
    codex_projection_wrapper: Option<std::path::PathBuf>,
) {
    let Some(wrapper) = codex_projection_wrapper else {
        return;
    };
    resources.add_linux_host_outer_wrapper(wrapper);
    for key in ["BASH_ENV", "ENV", "KSH_ENV", "ZDOTDIR", "SHELL"] {
        resources.remove_linux_host_environment(key);
    }
}

fn add_codex_hook_shell_environment(
    environment: &mut Vec<(String, String)>,
    profile: &erebor_runtime_core::CodexProfileLayerConfig,
) -> Result<(), SessionExecutionError> {
    let startup_path = profile.shell_startup_path.display().to_string();
    match profile.hook_shell {
        CodexHookShellKind::Direct => {}
        CodexHookShellKind::Sh => environment.push((String::from("ENV"), startup_path)),
        CodexHookShellKind::Bash => environment.push((String::from("BASH_ENV"), startup_path)),
        CodexHookShellKind::Zsh => {
            let startup_directory = profile
                .shell_startup_path
                .parent()
                .ok_or_else(|| crate::CodexSessionError::IncompatibleProfile {
                    reason: String::from("Codex zsh startup path has no parent directory"),
                    location: snafu::Location::default(),
                })
                .context(CodexSessionSnafu)?;
            environment.push((
                String::from("ZDOTDIR"),
                startup_directory.display().to_string(),
            ));
        }
    }
    Ok(())
}

fn file_operation_interception_input(
    interception: &erebor_runtime_core::SessionInterceptionConfig,
    filesystem_handler: &Option<FilesystemFileOperationHandler>,
) -> FileOperationInterceptionInput {
    let filesystem_registered = filesystem_handler.is_some();
    FileOperationInterceptionInput::new(
        filesystem_registered
            && interception.operation_supported(SessionInterceptionOperation::FileOpen),
        filesystem_registered
            && interception.operation_supported(SessionInterceptionOperation::FileRead),
        filesystem_registered
            && interception.operation_supported(SessionInterceptionOperation::FileMutation),
    )
}

fn codex_runtime_state_roots(repo_path: &Path) -> Result<Vec<PathBuf>, SessionExecutionError> {
    let Some(root) = std::env::var_os("CODEX_HOME") else {
        return Ok(Vec::new());
    };
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return GuardConfigSnafu {
            reason: String::from("CODEX_HOME must be an absolute path for managed Codex sessions"),
        }
        .fail();
    }
    let root = match std::fs::canonicalize(&root) {
        Ok(root) => root,
        Err(error) => {
            return GuardConfigSnafu {
                reason: format!(
                    "managed Codex CODEX_HOME {} could not be resolved: {error}",
                    root.display()
                ),
            }
            .fail();
        }
    };
    let repo = match std::fs::canonicalize(repo_path) {
        Ok(repo) => repo,
        Err(error) => {
            return GuardConfigSnafu {
                reason: format!(
                    "governed repository {} could not be resolved: {error}",
                    repo_path.display()
                ),
            }
            .fail();
        }
    };
    if root.starts_with(&repo) || repo.starts_with(&root) {
        return GuardConfigSnafu {
            reason: format!(
                "CODEX_HOME runtime-state root {} must not overlap the governed repository {}",
                root.display(),
                repo.display()
            ),
        }
        .fail();
    }
    Ok(vec![root])
}

fn session_interception_router(
    terminal_process_surface: TerminalProcessSurface<'_>,
    browser_cdp_endpoint: Option<&str>,
    lazy_browser_cdp: Option<LazyBrowserCdpProcessMediation>,
    filesystem_handler: Option<FilesystemFileOperationHandler>,
    codex_invocation_lease_owner: Option<Arc<CodexInvocationLeaseOwner>>,
    codex_guard_lifecycle_handler: Option<CodexGuardLifecycleHandler>,
) -> Result<crate::runtime_interception_broker::SessionInterceptionRouter, SessionExecutionError> {
    let router = terminal_process_surface.router(browser_cdp_endpoint, lazy_browser_cdp)?;
    let router = match filesystem_handler {
        Some(handler) => router.with_file_operation_handler(handler),
        None => router,
    };
    let router = match codex_invocation_lease_owner {
        Some(owner) => router.with_codex_invocation_lease_owner(owner),
        None => router,
    };
    Ok(match codex_guard_lifecycle_handler {
        Some(handler) => router.with_guard_lifecycle_handler(handler),
        None => router,
    })
}

#[cfg(test)]
mod tests {
    use erebor_runtime_core::{
        CodexDeploymentMode, CodexHookEvent, CodexHookEventSchemaLayerConfig,
        CodexProfileLayerConfig, SessionRunnerKind,
    };

    use super::{add_codex_hook_shell_environment, CodexHookShellKind};

    #[test]
    fn certified_hook_shells_receive_only_their_root_controlled_startup_input(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (shell, expected) in [
            (CodexHookShellKind::Direct, None),
            (
                CodexHookShellKind::Sh,
                Some(("ENV", "/usr/lib/erebor/codex-hooks/shell-startup")),
            ),
            (
                CodexHookShellKind::Bash,
                Some(("BASH_ENV", "/usr/lib/erebor/codex-hooks/shell-startup")),
            ),
            (
                CodexHookShellKind::Zsh,
                Some(("ZDOTDIR", "/usr/lib/erebor/codex-hooks")),
            ),
        ] {
            let mut environment = Vec::new();
            add_codex_hook_shell_environment(&mut environment, &profile(shell))?;
            assert_eq!(
                environment,
                expected.map_or_else(Vec::new, |(key, value)| {
                    vec![(String::from(key), String::from(value))]
                })
            );
        }
        Ok(())
    }

    fn profile(hook_shell: CodexHookShellKind) -> CodexProfileLayerConfig {
        CodexProfileLayerConfig {
            id: String::from("test-profile"),
            runner: SessionRunnerKind::LinuxHost,
            executable: "/opt/codex/codex".into(),
            executable_sha256: "a".repeat(64),
            deployment: CodexDeploymentMode::FleetManaged,
            trust_root: "/var/lib/erebor/codex".into(),
            requirements_source: "/var/lib/erebor/codex/requirements.toml".into(),
            requirements_sha256: "b".repeat(64),
            managed_hook_source: "/var/lib/erebor/codex/hooks/erebor-codex-hook".into(),
            managed_hook_sha256: "c".repeat(64),
            managed_hook_path: "/usr/lib/erebor/codex-hooks/erebor-codex-hook".into(),
            shell_startup_source: "/var/lib/erebor/codex/hooks/shell-startup".into(),
            shell_startup_sha256: "d".repeat(64),
            shell_startup_path: "/usr/lib/erebor/codex-hooks/shell-startup".into(),
            hook_shell,
            hook_exec_history: vec![
                "/opt/codex/codex".into(),
                "/usr/lib/erebor/codex-hooks/erebor-codex-hook".into(),
            ],
            event_schemas: vec![CodexHookEventSchemaLayerConfig {
                event: CodexHookEvent::SessionStart,
                sha256: "e".repeat(64),
            }],
            app_server_transport: Default::default(),
        }
    }
}
