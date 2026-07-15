use std::path::Path;

use erebor_runtime_core::{
    DockerSessionCommandOptions, DockerSessionMount, LinuxHostSessionCommandOptions,
    SessionSurfaceSupervisor,
};
use snafu::ResultExt;

use crate::{
    agents::codex::{CodexGuardTicketIssuer, CodexHookBroker},
    error::RuntimeInterceptionBrokerSnafu,
    interception_backend::SessionInterceptionBackendBundle,
    runtime_interception_broker::{
        RuntimeInterceptionBroker, SessionInterceptionRegistration, SessionInterceptionRouter,
    },
    session_context::SessionPlanContext,
    session_resources::{SessionResourceLifetime, SessionSideResources},
    SessionExecutionError,
};

const DOCKER_INTERCEPTION_DIR: &str = "/erebor/interception";
const LAZY_BROWSER_CDP_INTERCEPTION_TIMEOUT_MS: u64 = 15_000;

pub(crate) struct SessionInterceptionSetup {
    backend: Option<SessionInterceptionBackendBundle>,
}

impl SessionInterceptionSetup {
    pub(crate) fn new(backend: Option<SessionInterceptionBackendBundle>) -> Self {
        Self { backend }
    }

    pub(crate) fn backend_kind(&self) -> Option<&str> {
        self.backend.as_ref().map(|backend| backend.backend_kind())
    }

    pub(crate) fn register(
        &self,
        router: SessionInterceptionRouter,
        plan: &impl SessionPlanContext,
        uses_lazy_browser_cdp: bool,
    ) -> Result<Option<SessionInterceptionRegistration>, SessionExecutionError> {
        self.backend
            .as_ref()
            .map(|_backend| {
                let registration = RuntimeInterceptionBroker::register_session(
                    plan.session_id().as_str(),
                    &plan.actor().id,
                    router,
                )
                .context(RuntimeInterceptionBrokerSnafu)?;
                let registration = if uses_lazy_browser_cdp {
                    registration.with_timeout_ms(LAZY_BROWSER_CDP_INTERCEPTION_TIMEOUT_MS)
                } else {
                    registration
                };
                Ok(registration)
            })
            .transpose()
    }

    pub(crate) fn into_side_resources(
        self,
        environment: Vec<(String, String)>,
        browser_cdp_endpoint: Option<String>,
        interception_registration: Option<SessionInterceptionRegistration>,
        supervisor: Option<SessionSurfaceSupervisor>,
        codex_guard_ticket_issuer: Option<CodexGuardTicketIssuer>,
        codex_hook_broker: Option<CodexHookBroker>,
    ) -> Result<SessionSideResources, SessionExecutionError> {
        let (docker_options, linux_host_options) = self.command_options(
            browser_cdp_endpoint.as_deref(),
            interception_registration.as_ref(),
        )?;

        Ok(SessionSideResources::new(
            environment,
            docker_options,
            linux_host_options,
            browser_cdp_endpoint,
            SessionResourceLifetime::new(
                interception_registration,
                self.backend,
                codex_guard_ticket_issuer,
                codex_hook_broker,
                supervisor,
            ),
        ))
    }

    fn command_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
        interception_registration: Option<&SessionInterceptionRegistration>,
    ) -> Result<(DockerSessionCommandOptions, LinuxHostSessionCommandOptions), SessionExecutionError>
    {
        let Some(backend) = self.backend.as_ref() else {
            return Ok((
                DockerSessionCommandOptions::default(),
                LinuxHostSessionCommandOptions::default(),
            ));
        };

        let mut docker_options = backend.docker_options();
        let mut linux_host_options = backend.linux_host_options(browser_cdp_endpoint)?;
        if let Some(interception_registration) = interception_registration {
            docker_options.add_mount(DockerSessionMount::new(
                interception_registration.endpoint().directory(),
                DOCKER_INTERCEPTION_DIR,
                true,
            ));
            for (key, value) in interception_registration
                .docker_endpoint(Path::new(DOCKER_INTERCEPTION_DIR))
                .environment()
            {
                docker_options.add_environment(key, value);
            }
            for (key, value) in interception_registration.endpoint().environment() {
                linux_host_options.add_environment(key, value);
            }
        }

        Ok((docker_options, linux_host_options))
    }
}
